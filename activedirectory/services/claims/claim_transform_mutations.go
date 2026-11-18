package claims

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_central_access "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// CreateClaimTransformPolicy creates one policy. The rules are rendered and
// validated before anything is submitted.
//
// Related cmdlet: New-ADClaimTransformPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adclaimtransformpolicy?view=windowsserver2025-ps
func (c *Service) CreateClaimTransformPolicy(
	ctx context.Context,
	request CreateClaimTransformPolicyRequest,
) (ClaimTransformPolicyMutationResult, error) {
	var result admodel.ClaimTransformPolicyMutationResult
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) {
		return result, admodel.ErrInvalidObjectMutation
	}
	if request.Description != nil && !admodel.InternalValidDirectoryText(*request.Description) {
		return result, admodel.ErrInvalidObjectMutation
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	if err := admodel.InternalClaimTransformRawAttributes(request.Attributes); err != nil {
		return result, err
	}
	stored, present, err := admodel.InternalClaimTransformRuleSetRender(request.Rules)
	if err != nil {
		return result, err
	}
	ctx, cancel, options, err := adservice_central_access.InternalServiceCentralAccessMutationContext(
		adservice_central_access.New(c.engine()),
		ctx,
		request.Options,
	)
	if err != nil {
		return result, err
	}
	defer cancel()
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		return admodel.InternalCentralAccessProtectionCapability(
			adengine.InternalClientSession(c.engine()),
			root,
			request.ProtectedFromAccidentalDeletion,
		)
	})
	if err != nil {
		return result, err
	}
	attributes := map[string][]admodel.RawValue{}
	for name, values := range request.Attributes {
		attributes[name] = values
	}
	if request.Description != nil {
		attributes["description"] = []admodel.RawValue{
			admodel.NewRawValue([]byte(*request.Description)),
		}
	}
	if present {
		attributes[admodel.InternalClaimTransformRules] = []admodel.RawValue{
			admodel.NewRawValue([]byte(stored)),
		}
	}
	parent, _ := admodel.IdentityByDN(admodel.InternalClaimTransformParent(options.Partition))
	options.Properties = admodel.InternalClaimTransformProperties(options.Properties)
	result.Mutation, err = c.engine().
		CreateObject(ctx, admodel.CreateObjectRequest{Parent: parent, Class: admodel.InternalClaimTransformClass, Name: request.Name, Attributes: attributes, Options: options})
	if err != nil {
		return admodel.InternalClaimTransformProject(result, err)
	}
	if request.ProtectedFromAccidentalDeletion != nil {
		protection, protectErr := adservice_central_access.InternalServiceSetCentralAccessProtection(
			adservice_central_access.New(c.engine()),
			ctx,
			admodel.InternalObjectGUIDIdentity(*result.Mutation.TargetGUID),
			*request.ProtectedFromAccidentalDeletion,
			admodel.ObjectMutationOptions{Partition: options.Partition},
			false,
		)
		result.Protection = protection
		err = protectErr
	}
	return admodel.InternalClaimTransformProject(result, err)
}

// UpdateClaimTransformPolicy changes one policy in a single modify.
//
// Related cmdlet: Set-ADClaimTransformPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adclaimtransformpolicy?view=windowsserver2025-ps
func (c *Service) UpdateClaimTransformPolicy(
	ctx context.Context,
	request UpdateClaimTransformPolicyRequest,
) (ClaimTransformPolicyMutationResult, error) {
	var result admodel.ClaimTransformPolicyMutationResult
	changes, err := admodel.InternalClaimTransformUpdateChanges(request)
	if err != nil {
		return result, err
	}
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	ctx, cancel, options, err := adservice_central_access.InternalServiceCentralAccessMutationContext(
		adservice_central_access.New(c.engine()),
		ctx,
		request.Options,
	)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalClaimTransformProperties(options.Properties),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalClaimTransformLocation(
				*observed.Object,
				options.Partition,
			); err != nil {
				return err
			}
			if err := admodel.InternalCentralAccessProtectionCapability(
				session,
				root,
				request.ProtectedFromAccidentalDeletion,
			); err != nil {
				return err
			}
			mods, err := admodel.InternalObjectChanges(changes)
			if err != nil {
				return err
			}
			if len(mods) == 0 {
				if options.ExpectedVersion != nil &&
					request.ProtectedFromAccidentalDeletion == nil {
					return admodel.ErrObjectControlUnsupported
				}
				mutation.After = mutation.Before
				mutation.ReadbackComplete = true
				mutation.Verified = true
			} else {
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
				readOptions := options
				readOptions.Properties = admodel.InternalClaimTransformProperties(
					options.Properties,
				)
				if err := admodel.InternalObserveObjectWrite(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
					mutation,
					admodel.InternalObjectWriteProperties(readOptions, mods),
					false,
				); err != nil {
					return err
				}
				if err := admodel.InternalVerifyObjectWrite(mutation, mods, ""); err != nil {
					return err
				}
			}
			if request.ProtectedFromAccidentalDeletion != nil {
				result.Protection.Object = *mutation
				return admodel.InternalChangeOUProtection(
					ctx,
					session,
					root,
					adengine.InternalClientConfig(c.engine()),
					mutation,
					*request.ProtectedFromAccidentalDeletion,
					options,
					&result.Protection,
				)
			}
			return nil
		},
	)
	return admodel.InternalClaimTransformProject(result, err)
}

// DeleteClaimTransformPolicy removes one policy with a single native leaf
// delete. It never unprotects the object or clears trust links for the caller;
// a policy still linked from a trust is the directory's own referential
// concern and its refusal is surfaced unchanged.
//
// Related cmdlet: Remove-ADClaimTransformPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adclaimtransformpolicy?view=windowsserver2025-ps
func (c *Service) DeleteClaimTransformPolicy(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(identity, options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	ctx, cancel, options, err := adservice_central_access.InternalServiceCentralAccessMutationContext(
		adservice_central_access.New(c.engine()),
		ctx,
		options,
	)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	defer cancel()
	return adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalClaimTransformProperties(options.Properties),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalClaimTransformLocation(
				*observed.Object,
				options.Partition,
			); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*result.TargetGUID,
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
					InternalDn:        admodel.InternalObjectGUIDTarget(*result.TargetGUID),
					InternalControls:  controls,
				},
				false,
				result,
			); err != nil {
				return err
			}
			return admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				[]string{"objectGUID"},
				true,
			)
		},
	)
}

// SetClaimTransformLink points one direction of a trust at a policy.
//
// Related cmdlet: Set-ADClaimTransformLink.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adclaimtransformlink?view=windowsserver2025-ps
func (c *Service) SetClaimTransformLink(
	ctx context.Context,
	request ClaimTransformLinkRequest,
) (ClaimTransformLinkResult, error) {
	return internalServiceChangeClaimTransformLink(c, ctx, request, false)
}

// ClearClaimTransformLink removes the policy link from one direction of a
// trust. It does not delete the policy.
//
// Related cmdlet: Clear-ADClaimTransformLink.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/clear-adclaimtransformlink?view=windowsserver2025-ps
func (c *Service) ClearClaimTransformLink(
	ctx context.Context,
	request ClaimTransformLinkRequest,
) (ClaimTransformLinkResult, error) {
	return internalServiceChangeClaimTransformLink(c, ctx, request, true)
}

// internalServiceChangeClaimTransformLink sets or clears the selected trust policy link after
// resolving the trust and policy.
func internalServiceChangeClaimTransformLink(c *Service,
	ctx context.Context,
	request admodel.ClaimTransformLinkRequest,
	clear bool,
) (admodel.ClaimTransformLinkResult, error) {
	var result admodel.ClaimTransformLinkResult
	attribute, err := admodel.InternalClaimTransformDirectionAttribute(request.Direction)
	if err != nil {
		return result, err
	}
	result.Attribute = attribute
	if err := admodel.InternalValidateObjectOptions(request.Trust, request.Options); err != nil {
		return result, err
	}
	if !clear && request.Policy.Form() == 0 {
		return result, errors.Join(admodel.ErrClaimTransformLink, admodel.ErrInvalidIdentity)
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	options := request.Options
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		bounded,
		request.Trust,
		options,
		admodel.ResolveIdentityOptions{
			Properties: []string{
				"objectGUID",
				"uSNChanged",
				"objectClass",
				"name",
				"trustPartner",
				attribute,
			},
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			// The target must be a trust. A claim policy written onto an arbitrary
			// object would be silently meaningless.
			if err := admodel.InternalCentralAccessClassCheck(
				*observed.Object,
				"trustedDomain",
			); err != nil {
				return errors.Join(admodel.ErrClaimTransformLink, err)
			}
			mods := []admodel.InternalLdapAttributeModification{
				{InternalOperation: 1, InternalAttribute: attribute},
			}
			if !clear {
				configuration, err := admodel.InternalCentralAccessConfiguration(
					root,
					adengine.InternalClientConfig(c.engine()),
					"",
				)
				if err != nil {
					return err
				}
				policy, err := admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					request.Policy,
					admodel.ResolveIdentityOptions{
						Partition:  configuration,
						Properties: admodel.InternalClaimTransformProperties(nil),
					},
				)
				result.PolicyObservation = policy
				if err != nil {
					return err
				}
				if err := admodel.InternalClaimTransformLocation(
					*policy.Object,
					configuration,
				); err != nil {
					return err
				}
				mods = []admodel.InternalLdapAttributeModification{
					{
						InternalOperation: 2,
						InternalAttribute: attribute,
						InternalValues:    [][]byte{[]byte(policy.Object.DistinguishedName)},
					},
				}
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
					InternalOperation:     admodel.InternalLdapWriteModify,
					InternalDn:            admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
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
				[]string{"objectGUID", "uSNChanged", attribute},
				false,
			); err != nil {
				return err
			}
			// A clear of an already-absent value is not a failure, so the removal
			// is only verified when a value was written.
			if !clear {
				return admodel.InternalVerifyObjectWrite(mutation, mods, "")
			}
			return nil
		},
	)
	return result, err
}
