package accounts

import (
	"context"
	"errors"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// AccountPasswordChangePermission reads the DACL's Change-Password ACE pattern
// using the shared account identity/class rules and a critical DACL-only control.
//
// Related cmdlet: Get-ADUser.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2025-ps
func (c *Service) AccountPasswordChangePermission(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (AccountPasswordPermissionResult, error) {
	var result admodel.AccountPasswordPermissionResult
	if options.Target > admodel.IdentityTargetAccount {
		return result, admodel.ErrInvalidIdentity
	}
	options = admodel.InternalAccountControlIdentity(
		identity,
		options.Partition,
		options.Properties,
	)
	if err := admodel.InternalValidateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		result.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalAccountControlClass(
			*result.Observation.Object,
			root.Capabilities().Type,
		); err != nil {
			return err
		}
		value, err := result.Observation.Object.Values("objectGUID").Single()
		if err != nil {
			return err
		}
		guid, err := value.GUID()
		if err != nil {
			return err
		}
		session, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalDirectoryDACLSession)
		if !ok {
			return admodel.ErrUnsupported
		}
		if !slices.Contains(root.SupportedControls, admodel.InternalDirectorySDFlagsControl) {
			return admodel.ErrObjectControlUnsupported
		}
		observed, _, _, err := admodel.InternalReadAccountPasswordPermission(
			ctx,
			session,
			root,
			result.Observation.Partition,
			guid,
			options.Properties,
		)
		result.Permission = &observed
		return err
	})
	return result, err
}

// SetAccountCannotChangePassword edits only explicit SELF/Everyone object ACEs
// for the Change-Password extended right. False installs allow rules rather
// than merely clearing a UAC bit or removing all matching rights. It preserves
// unrelated/inherited/opaque ACE bytes and never modifies a parent DACL.
// Ordinary updates follow Set-ADAccountControl semantics and do not guarantee
// isolation from concurrent permission changes. An explicit ExpectedVersion
// requires a supported critical server assertion and is never silently ignored.
//
// Related cmdlet: Set-ADAccountControl.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountcontrol?view=windowsserver2025-ps
func (c *Service) SetAccountCannotChangePassword(
	ctx context.Context,
	identity adshared.Identity,
	cannot bool,
	options adshared.ObjectMutationOptions,
) (AccountPasswordPermissionMutationResult, error) {
	var result admodel.AccountPasswordPermissionMutationResult
	resolve := admodel.InternalAccountControlIdentity(
		identity,
		options.Partition,
		options.Properties,
	)
	if err := admodel.InternalValidateIdentityOperation(identity, resolve); err != nil {
		return result, err
	}
	for _, property := range options.Properties {
		if property == "1.1" {
			return result, admodel.ErrInvalidProperty
		}
	}
	properties := admodel.InternalObjectWriteProperties(options, nil)
	var err error
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		resolve,
		func(ctx context.Context, writer admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalAccountControlClass(
				*observed.Object,
				root.Capabilities().Type,
			); err != nil {
				return err
			}
			session, ok := writer.(admodel.InternalDirectoryDACLSession)
			if !ok {
				return admodel.ErrUnsupported
			}
			if !slices.Contains(root.SupportedControls, admodel.InternalDirectorySDFlagsControl) {
				return admodel.ErrObjectControlUnsupported
			}
			before, raw, acl, err := admodel.InternalReadAccountPasswordPermission(
				ctx,
				session,
				root,
				mutation.Partition,
				*mutation.TargetGUID,
				properties,
			)
			result.Before = &before
			mutation.Before = &before.Raw
			if err != nil {
				return err
			}
			if !cannot && (before.Self.InheritedDeny || before.Everyone.InheritedDeny) {
				return admodel.ErrAccountPasswordPermission
			}
			aces, changed, err := admodel.InternalChangePasswordPermissionACEs(acl, cannot)
			if err != nil {
				return err
			}
			result.Changed = changed
			_, _, planned, unknown := admodel.InternalObservePasswordChangeACL(
				admodel.InternalDirectoryDACL{InternalAces: aces},
			)
			if unknown || planned == nil || *planned != cannot {
				// Do not dispatch a descriptor that is already known to leave the
				// requested reference pattern ambiguous (for example mixed rights).
				return admodel.ErrAccountPasswordPermission
			}
			if !changed {
				if options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				result.After = result.Before
				mutation.After = mutation.Before
				mutation.ReadbackComplete = true
				mutation.Verified = before.CannotChangePassword != nil &&
					*before.CannotChangePassword == cannot
				if !mutation.Verified {
					return admodel.ErrAccountPasswordPermission
				}
				return nil
			}
			controls, err := admodel.InternalDirectoryDACLWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*mutation.TargetGUID,
				before.Raw,
			)
			if err != nil {
				return err
			}
			updated, err := session.InternalEncodeDACL(raw, aces)
			if err != nil {
				return err
			}
			write := admodel.InternalLdapWriteRequest{
				InternalOperation: admodel.InternalLdapWriteModify,
				InternalDn:        admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
				InternalModifications: []admodel.InternalLdapAttributeModification{
					{
						InternalOperation: 2,
						InternalAttribute: "nTSecurityDescriptor",
						InternalValues:    [][]byte{updated},
					},
				},
				InternalControls: controls,
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				writer,
				write,
				false,
				mutation,
			); err != nil {
				return err
			}
			after, _, actual, err := admodel.InternalReadAccountPasswordPermission(
				ctx,
				session,
				root,
				mutation.Partition,
				*mutation.TargetGUID,
				properties,
			)
			result.After = &after
			mutation.After = &after.Raw
			mutation.ReadbackCandidates = []admodel.Object{after.Raw}
			if err != nil {
				return errors.Join(admodel.ErrObjectReadback, err)
			}
			mutation.ReadbackComplete = true
			if after.CannotChangePassword == nil || *after.CannotChangePassword != cannot ||
				!admodel.InternalDirectoryACEsRetained(aces, actual.InternalAces) {
				return errors.Join(
					admodel.ErrAccountPasswordPermission,
					admodel.ErrObjectVerification,
				)
			}
			mutation.Verified = true
			return nil
		},
	)
	return result, err
}
