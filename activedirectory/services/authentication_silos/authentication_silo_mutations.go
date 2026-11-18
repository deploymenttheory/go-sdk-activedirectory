package authentication_silos

import (
	"context"
	"slices"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_authentication_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// internalServiceAuthenticationSiloOptions validates silo capabilities and selects
// configuration-partition mutation properties.
func internalServiceAuthenticationSiloOptions(c *Service,
	ctx context.Context,
	options admodel.ObjectMutationOptions,
) (admodel.ObjectMutationOptions, admodel.RootDSE, error) {
	resolved, root, err := adservice_authentication_policies.InternalServiceAuthenticationPolicyOptions(
		adservice_authentication_policies.New(c.engine()),
		ctx,
		options,
	)
	resolved.Properties = admodel.InternalAuthenticationSiloProperties(options.Properties)
	return resolved, root, err
}

// CreateAuthenticationPolicySilo creates an audit-mode silo by default. Nil
// protection leaves the schema ACL unchanged, matching the module's default.
//
// Related cmdlet: New-ADAuthenticationPolicySilo.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adauthenticationpolicysilo?view=windowsserver2025-ps
func (c *Service) CreateAuthenticationPolicySilo(
	ctx context.Context,
	request CreateAuthenticationPolicySiloRequest,
) (AuthenticationPolicySiloMutationResult, error) {
	var result admodel.AuthenticationPolicySiloMutationResult
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) {
		return result, admodel.ErrInvalidAuthenticationSilo
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
			return strings.EqualFold(change.Attribute, "msDS-AuthNPolicySiloEnforced")
		}) {
		value := false
		properties.Enforced = &value
	}
	mods, err := admodel.InternalAuthenticationSiloChanges(properties, raw)
	if err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	options, root, err := internalServiceAuthenticationSiloOptions(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	container, _ := admodel.InternalAuthenticationSiloContainer(root)
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
				nil,
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
			currentContainer, _ := admodel.InternalAuthenticationSiloContainer(root)
			classes, _ := observed.Object.Attribute("objectClass")
			if !admodel.InternalSameAuthenticationDN(
				observed.Object.DistinguishedName,
				currentContainer,
			) ||
				!slices.ContainsFunc(
					classes,
					func(value []byte) bool { return strings.EqualFold(string(value), "msDS-AuthNPolicySilos") },
				) {
				return admodel.ErrNotAuthenticationSilo
			}
			naming, err := admodel.InternalObjectClassNamingAttribute(
				ctx,
				session,
				root,
				"msDS-AuthNPolicySilo",
			)
			if err != nil {
				return err
			}
			if !strings.EqualFold(naming, "cn") {
				return admodel.ErrInvalidResult
			}
			for _, mod := range mods {
				if strings.EqualFold(mod.InternalAttribute, naming) {
					return admodel.ErrInvalidAuthenticationSilo
				}
			}
			if err := admodel.InternalResolveSiloPolicies(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				properties,
				mods,
				&result,
			); err != nil {
				return err
			}
			mutation.Before, mutation.TargetGUID = nil, nil
			mutation.TargetDN = naming + "=" + admodel.InternalEscapeObjectName(
				request.Name,
			) + "," + observed.Object.DistinguishedName
			writes := append(
				slices.Clone(mods),
				admodel.InternalLdapAttributeModification{
					InternalAttribute: "objectClass",
					InternalValues:    [][]byte{[]byte("msDS-AuthNPolicySilo")},
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
			identity, _ := admodel.IdentityByDN(mutation.TargetDN)
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
			if err := admodel.InternalVerifyAuthenticationSiloWrite(
				mutation,
				writes,
				request.Name,
			); err != nil {
				return err
			}
			if err := admodel.InternalAuthenticationSiloScope(root, *mutation.After); err != nil {
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
	return admodel.InternalFinishAuthenticationSiloMutation(result, err)
}

// UpdateAuthenticationPolicySilo changes a silo's typed properties, raw attributes, and optional
// deletion protection. Attribute and protection writes retain separate outcomes when a later stage
// fails.
//
// Related cmdlet: Set-ADAuthenticationPolicySilo.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adauthenticationpolicysilo?view=windowsserver2025-ps
func (c *Service) UpdateAuthenticationPolicySilo(
	ctx context.Context,
	request UpdateAuthenticationPolicySiloRequest,
) (AuthenticationPolicySiloMutationResult, error) {
	var result admodel.AuthenticationPolicySiloMutationResult
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	mods, err := admodel.InternalAuthenticationSiloChanges(request.Properties, request.Changes)
	if err != nil {
		return result, err
	}
	if len(mods) == 0 && request.ProtectedFromAccidentalDeletion == nil {
		return result, admodel.ErrInvalidAuthenticationSilo
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
	options, _, err := internalServiceAuthenticationSiloOptions(c, ctx, request.Options)
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
			if err := admodel.InternalAuthenticationSiloScope(root, *observed.Object); err != nil {
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
			if err := admodel.InternalAuthenticationProtectionAvailable(
				session,
				root,
				request.ProtectedFromAccidentalDeletion,
				request.Options.Properties,
			); err != nil {
				return err
			}
			if err := admodel.InternalResolveSiloPolicies(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				request.Properties,
				mods,
				&result,
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
				if err := admodel.InternalVerifyAuthenticationSiloWrite(
					mutation,
					mods,
					"",
				); err != nil {
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
	return admodel.InternalFinishAuthenticationSiloMutation(result, err)
}

// DeleteAuthenticationPolicySilo deletes the selected silo as a leaf object. Directory reference and
// deletion-protection constraints remain authoritative; the result retains the write outcome.
//
// Related cmdlet: Remove-ADAuthenticationPolicySilo.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adauthenticationpolicysilo?view=windowsserver2025-ps
func (c *Service) DeleteAuthenticationPolicySilo(
	ctx context.Context,
	request DeleteAuthenticationPolicySiloRequest,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return admodel.ObjectMutationResult{}, admodel.ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	options, _, err := internalServiceAuthenticationSiloOptions(c, ctx, request.Options)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return adengine.InternalClientObjectMutation(
		c.engine(),
		ctx,
		request.Identity,
		options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalAuthenticationSiloScope(root, *observed.Object); err != nil {
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
