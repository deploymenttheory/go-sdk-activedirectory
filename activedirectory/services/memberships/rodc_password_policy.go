package memberships

import (
	"context"
	"errors"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// AccountResultantPasswordReplicationPolicy asks the directory for an account's effective
// password-cache policy at the selected RODC. It uses the server's constructed policy result rather
// than inferring permission from the allow and deny lists.
//
// Related cmdlet: Get-ADAccountResultantPasswordReplicationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adaccountresultantpasswordreplicationpolicy?view=windowsserver2025-ps
func (c *Service) AccountResultantPasswordReplicationPolicy(
	ctx context.Context,
	controller, account adshared.Identity,
	options RODCPasswordReplicationOptions,
) (result RODCResultantPasswordReplicationResult, err error) {
	if options.Limits != (admodel.MembershipLimits{}) {
		return result, admodel.ErrInvalidRODCPasswordPolicy
	}
	if err = admodel.InternalValidateIdentityOperation(
		controller,
		admodel.InternalMembershipResolveOptions(controller, options.Partition, nil),
	); err != nil {
		return result, err
	}
	if err = admodel.InternalValidateIdentityOperation(
		account,
		admodel.InternalMembershipResolveOptions(account, options.Partition, options.Properties),
	); err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, readErr := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if readErr != nil {
			return readErr
		}
		result.Controller, readErr = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			controller,
			admodel.InternalMembershipResolveOptions(
				controller,
				options.Partition,
				admodel.InternalRodcPasswordProperties(nil),
			),
		)
		if readErr != nil {
			return readErr
		}
		if err := adengine.InternalRodcPasswordServer(
			ctx,
			c.engine(),
			adengine.InternalClientSession(c.engine()),
			root,
			result.Controller.Partition,
			false,
		); err != nil {
			return err
		}
		if err := admodel.InternalValidateRODCPasswordTarget(
			*result.Controller.Object,
		); err != nil {
			return err
		}
		result.Account, readErr = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			account,
			admodel.InternalMembershipResolveOptions(
				account,
				result.Controller.Partition,
				options.Properties,
			),
		)
		if readErr != nil {
			return readErr
		}
		if !admodel.InternalMembershipHasClass(*result.Account.Object, "user") {
			return admodel.ErrUnsupportedIdentity
		}
		principal, readErr := admodel.InternalDecodeMembershipPrincipal(
			*result.Account.Object,
			adengine.InternalClientConfig(c.engine()).Endpoint,
		)
		if readErr != nil {
			return readErr
		}
		rodc, readErr := admodel.InternalDecodeMembershipPrincipal(
			*result.Controller.Object,
			adengine.InternalClientConfig(c.engine()).Endpoint,
		)
		if readErr != nil {
			return readErr
		}
		reader, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalObjectSyncPolicySession)
		if !ok || !slices.Contains(root.SupportedControls, admodel.InternalObjectSyncDNInputOID) {
			return admodel.ErrRODCPasswordPolicyCapability
		}
		attrs, readErr := reader.InternalObjectSyncPasswordPolicy(
			ctx,
			admodel.InternalObjectGUIDTarget(rodc.GUID),
			admodel.InternalObjectGUIDTarget(principal.GUID),
		)
		result.Raw = admodel.Object{
			DistinguishedName:   result.Controller.Object.DistinguishedName,
			Attributes:          attrs,
			RequestedProperties: []string{"msDS-IsUserCachableAtRodc"},
		}
		value, valueErr := result.Raw.Values("msDS-IsUserCachableAtRodc").Single()
		if valueErr != nil {
			return errors.Join(readErr, admodel.ErrRODCPasswordPolicyCapability, valueErr)
		}
		number, valueErr := value.Int64()
		if valueErr != nil {
			return errors.Join(readErr, valueErr)
		}
		policy := admodel.RODCResultantPasswordReplicationPolicy(number)
		result.Policy = &policy
		result.Complete = readErr == nil
		return readErr
	})
	return result, admodel.InternalRodcPasswordError(err)
}
