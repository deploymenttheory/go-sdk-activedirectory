package authentication_policies

import (
	"context"
	"errors"
	"slices"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// InternalServiceAuthenticationPolicyOptions validates authentication-policy capabilities and selects
// configuration-partition mutation properties.
func InternalServiceAuthenticationPolicyOptions(c *Service,
	ctx context.Context,
	options admodel.ObjectMutationOptions,
) (admodel.ObjectMutationOptions, admodel.RootDSE, error) {
	root, err := c.engine().RootDSE(ctx, admodel.RootDSEOptions{})
	if err != nil {
		return options, root, err
	}
	if _, err := admodel.InternalAuthenticationPolicyContainer(root); err != nil {
		return options, root, err
	}
	if options.Partition != "" &&
		!admodel.InternalSameAuthenticationDN(options.Partition, *root.ConfigurationNamingContext) {
		return options, root, admodel.ErrIdentityScope
	}
	options.Partition = *root.ConfigurationNamingContext
	options.Properties = admodel.InternalAuthenticationPolicyProperties(options.Properties)
	return options, root, nil
}

// CreateAuthenticationPolicy creates an authentication policy in the configuration partition. Request
// supplies its name, typed properties, optional raw attributes, and deletion protection; enforcement
// defaults to false when omitted.
//
// Related cmdlet: New-ADAuthenticationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adauthenticationpolicy?view=windowsserver2025-ps
func (c *Service) CreateAuthenticationPolicy(
	ctx context.Context,
	request CreateAuthenticationPolicyRequest,
) (AuthenticationPolicyMutationResult, error) {
	var result admodel.AuthenticationPolicyMutationResult
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) {
		return result, admodel.ErrInvalidAuthenticationPolicy
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	var raw []admodel.AttributeChange
	for name, values := range request.Attributes {
		raw = append(
			raw,
			admodel.AttributeChange{Attribute: name, Kind: admodel.AttributeSet, Values: values},
		)
	}
	properties := request.Properties
	if properties.Enforced == nil &&
		!slices.ContainsFunc(raw, func(change admodel.AttributeChange) bool {
			return strings.EqualFold(change.Attribute, "msDS-AuthNPolicyEnforced")
		}) {
		value := false
		properties.Enforced = &value
	}
	mods, err := admodel.InternalAuthenticationPolicyChanges(properties, raw)
	if err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	options, root, err := InternalServiceAuthenticationPolicyOptions(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	container, _ := admodel.InternalAuthenticationPolicyContainer(root)
	parent, err := admodel.IdentityByDN(container)
	if err != nil {
		return result, err
	}
	if err := admodel.InternalValidateObjectOptions(parent, options); err != nil {
		return result, err
	}
	result.Mutation, err = adengine.InternalClientObjectMutation(
		c.engine(),
		ctx,
		parent,
		options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalAuthenticationPolicyWritePrerequisites(
				ctx,
				session,
				root,
				mods,
			); err != nil {
				return err
			}
			if err := admodel.InternalAuthenticationProtectionAvailable(
				session,
				root,
				request.ProtectedFromAccidentalDeletion,
				request.Options.Properties,
			); err != nil {
				return err
			}
			currentContainer, _ := admodel.InternalAuthenticationPolicyContainer(root)
			if !admodel.InternalSameAuthenticationDN(
				observed.Object.DistinguishedName,
				currentContainer,
			) {
				return admodel.ErrIdentityScope
			}
			classes, _ := observed.Object.Attribute("objectClass")
			if !slices.ContainsFunc(
				classes,
				func(value []byte) bool { return strings.EqualFold(string(value), "msDS-AuthNPolicies") },
			) {
				return admodel.ErrNotAuthenticationPolicy
			}
			naming, err := admodel.InternalObjectClassNamingAttribute(
				ctx,
				session,
				root,
				"msDS-AuthNPolicy",
			)
			if err != nil {
				return err
			}
			if !strings.EqualFold(naming, "cn") {
				return admodel.ErrInvalidResult
			}
			for _, mod := range mods {
				if strings.EqualFold(mod.InternalAttribute, naming) {
					return admodel.ErrInvalidAuthenticationPolicy
				}
			}
			mutation.Before, mutation.TargetGUID = nil, nil
			mutation.TargetDN = naming + "=" + admodel.InternalEscapeObjectName(
				request.Name,
			) + "," + observed.Object.DistinguishedName
			writes := append(
				slices.Clone(mods),
				admodel.InternalLdapAttributeModification{
					InternalAttribute: "objectClass",
					InternalValues:    [][]byte{[]byte("msDS-AuthNPolicy")},
				},
				admodel.InternalLdapAttributeModification{
					InternalAttribute: naming,
					InternalValues:    [][]byte{[]byte(request.Name)},
				},
			)
			for i := range writes {
				writes[i].InternalOperation = 0
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation:     admodel.InternalLdapWriteAdd,
					InternalDn:            mutation.TargetDN,
					InternalModifications: writes,
				},
				false,
				mutation,
			); err != nil {
				return err
			}
			identity, err := admodel.IdentityByDN(mutation.TargetDN)
			if err != nil {
				return errors.Join(admodel.ErrObjectReadback, err)
			}
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				identity,
				mutation,
				admodel.InternalObjectWriteProperties(options, writes),
				false,
			); err != nil {
				return err
			}
			if err := admodel.InternalVerifyObjectWrite(
				mutation,
				writes,
				request.Name,
			); err != nil {
				return err
			}
			if err := admodel.InternalAuthenticationPolicyScope(root, *mutation.After); err != nil {
				return err
			}
			return admodel.InternalAuthenticationPolicyProtection(
				ctx,
				session,
				root,
				adengine.InternalClientConfig(c.engine()),
				mutation,
				options,
				request.ProtectedFromAccidentalDeletion,
				request.Options.Properties,
				&result.Protection,
			)
		},
	)
	return admodel.InternalFinishAuthenticationPolicyMutation(result, err)
}

// UpdateAuthenticationPolicy changes an authentication policy's typed properties, raw attributes, and
// optional deletion protection. The result preserves the attribute mutation and protection outcomes
// separately.
//
// Related cmdlet: Set-ADAuthenticationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adauthenticationpolicy?view=windowsserver2025-ps
func (c *Service) UpdateAuthenticationPolicy(
	ctx context.Context,
	request UpdateAuthenticationPolicyRequest,
) (AuthenticationPolicyMutationResult, error) {
	var result admodel.AuthenticationPolicyMutationResult
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	mods, err := admodel.InternalAuthenticationPolicyChanges(request.Properties, request.Changes)
	if err != nil {
		return result, err
	}
	if len(mods) == 0 && request.ProtectedFromAccidentalDeletion == nil {
		return result, admodel.ErrInvalidAuthenticationPolicy
	}
	if len(mods) != 0 && request.ProtectedFromAccidentalDeletion != nil &&
		request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	options, _, err := InternalServiceAuthenticationPolicyOptions(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		options,
		admodel.ResolveIdentityOptions{Properties: options.Properties},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalAuthenticationPolicyScope(
				root,
				*observed.Object,
			); err != nil {
				return err
			}
			if err := admodel.InternalAuthenticationPolicyWritePrerequisites(
				ctx,
				session,
				root,
				mods,
			); err != nil {
				return err
			}
			if err := admodel.InternalAuthenticationProtectionAvailable(
				session,
				root,
				request.ProtectedFromAccidentalDeletion,
				request.Options.Properties,
			); err != nil {
				return err
			}
			if len(mods) != 0 {
				controls, err := admodel.InternalObjectWriteControls(
					root,
					adengine.InternalClientConfig(c.engine()).Endpoint,
					options,
					*mutation.TargetGUID,
					false,
				)
				if err != nil {
					return err
				}
				if err := admodel.InternalSubmitObjectWrite(
					ctx,
					session,
					admodel.InternalLdapWriteRequest{
						InternalOperation: admodel.InternalLdapWriteModify,
						InternalDn: admodel.InternalObjectGUIDTarget(
							*mutation.TargetGUID,
						),
						InternalModifications: mods,
						InternalControls:      controls,
					},
					false,
					mutation,
				); err != nil {
					return err
				}
				if err := admodel.InternalObserveObjectWrite(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
					mutation,
					admodel.InternalObjectWriteProperties(options, mods),
					false,
				); err != nil {
					return err
				}
				if err := admodel.InternalVerifyObjectWrite(mutation, mods, ""); err != nil {
					return err
				}
			}
			return admodel.InternalAuthenticationPolicyProtection(
				ctx,
				session,
				root,
				adengine.InternalClientConfig(c.engine()),
				mutation,
				options,
				request.ProtectedFromAccidentalDeletion,
				request.Options.Properties,
				&result.Protection,
			)
		},
	)
	return admodel.InternalFinishAuthenticationPolicyMutation(result, err)
}

// DeleteAuthenticationPolicy is a leaf delete. It never disables protection,
// edits referencing accounts/silos, or retries a server reference constraint.
//
// Related cmdlet: Remove-ADAuthenticationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adauthenticationpolicy?view=windowsserver2025-ps
func (c *Service) DeleteAuthenticationPolicy(
	ctx context.Context,
	request DeleteAuthenticationPolicyRequest,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return admodel.ObjectMutationResult{}, admodel.ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	options, _, err := InternalServiceAuthenticationPolicyOptions(c, ctx, request.Options)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return adengine.InternalClientObjectMutation(
		c.engine(),
		ctx,
		request.Identity,
		options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalAuthenticationPolicyScope(
				root,
				*observed.Object,
			); err != nil {
				return err
			}
			if err := admodel.InternalAuthenticationPolicyWritePrerequisites(
				ctx,
				session,
				root,
				nil,
			); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*mutation.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteDelete,
					InternalDn:        admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
					InternalControls:  controls,
				},
				false,
				mutation,
			); err != nil {
				return err
			}
			return admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				[]string{"objectGUID"},
				true,
			)
		},
	)
}
