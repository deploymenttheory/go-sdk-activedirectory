package central_access

import (
	"context"
	"slices"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func InternalServiceCentralAccessMutationContext(c *Service,
	ctx context.Context,
	options admodel.ObjectMutationOptions,
) (context.Context, context.CancelFunc, admodel.ObjectMutationOptions, error) {
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return ctx, func() {}, options, admodel.ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	root, err := c.engine().RootDSE(bounded, admodel.RootDSEOptions{})
	if err == nil {
		options.Partition, err = admodel.InternalCentralAccessConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			options.Partition,
		)
	}
	if err != nil {
		cancel()
	}
	return bounded, cancel, options, err
}

func internalServiceCreateCentralAccess(c *Service,
	ctx context.Context,
	name string,
	description *string,
	attrs map[string][]admodel.RawValue,
	protect *bool,
	options admodel.ObjectMutationOptions,
	policy bool,
	result admodel.CentralAccessMutationResult,
) (admodel.CentralAccessMutationResult, error) {
	ctx, cancel, options, err := InternalServiceCentralAccessMutationContext(c, ctx, options)
	if err != nil {
		return result, err
	}
	defer cancel()
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		if e := admodel.InternalCentralAccessProtectionCapability(
			adengine.InternalClientSession(c.engine()),
			root,
			protect,
		); e != nil {
			return e
		}
		return admodel.InternalCentralAccessValidateSyntax(
			adengine.InternalClientSession(c.engine()),
			attrs,
		)
	})
	if err != nil {
		return result, err
	}
	if description != nil {
		attrs["description"] = []admodel.RawValue{admodel.NewRawValue([]byte(*description))}
	}
	parent, _ := admodel.IdentityByDN(
		admodel.InternalCentralAccessParent(options.Partition, policy),
	)
	options.Properties = admodel.InternalCentralAccessProperties(options.Properties, policy)
	result.Mutation, err = c.engine().
		CreateObject(ctx, admodel.CreateObjectRequest{Parent: parent, Class: admodel.InternalCentralAccessClass(policy), Name: name, Attributes: attrs, Options: options})
	if err != nil {
		return admodel.InternalCentralAccessProject(result, policy, err)
	}
	if protect != nil {
		protection, e := InternalServiceSetCentralAccessProtection(c,
			ctx,
			admodel.InternalObjectGUIDIdentity(*result.Mutation.TargetGUID),
			*protect,
			admodel.ObjectMutationOptions{Partition: options.Partition},
			policy,
		)
		result.Protection = protection
		err = e
	}
	return admodel.InternalCentralAccessProject(result, policy, err)
}

func (c *Service) CreateCentralAccessRule(
	ctx context.Context,
	request CreateCentralAccessRuleRequest,
) (CentralAccessMutationResult, error) {
	var result admodel.CentralAccessMutationResult
	if err := admodel.InternalCentralAccessCreateInput(
		request.Name,
		request.Description,
		request.Options,
	); err != nil {
		return result, err
	}
	current := admodel.DefaultCentralAccessRuleACL
	if request.CurrentACL != nil {
		current = *request.CurrentACL
	}
	attrs := map[string][]admodel.RawValue{
		admodel.InternalCentralCurrent: {admodel.NewRawValue([]byte(current))},
	}
	if request.ProposedACL != nil {
		attrs[admodel.InternalCentralProposed] = []admodel.RawValue{
			admodel.NewRawValue([]byte(*request.ProposedACL)),
		}
	}
	if request.ResourceCondition != nil {
		text, err := request.ResourceCondition.Render()
		if err != nil {
			return result, err
		}
		attrs[admodel.InternalCentralCondition] = []admodel.RawValue{
			admodel.NewRawValue([]byte(text)),
		}
	}
	return internalServiceCreateCentralAccess(c,
		ctx,
		request.Name,
		request.Description,
		attrs,
		request.ProtectedFromAccidentalDeletion,
		request.Options,
		false,
		result,
	)
}

func (c *Service) CreateCentralAccessPolicy(
	ctx context.Context,
	request CreateCentralAccessPolicyRequest,
) (CentralAccessMutationResult, error) {
	var result admodel.CentralAccessMutationResult
	if err := admodel.InternalCentralAccessCreateInput(
		request.Name,
		request.Description,
		request.Options,
	); err != nil {
		return result, err
	}
	sid, err := admodel.InternalNewCentralAccessPolicyID()
	if err != nil {
		return result, err
	}
	result.GeneratedPolicyID = &sid
	return internalServiceCreateCentralAccess(c,
		ctx,
		request.Name,
		request.Description,
		map[string][]admodel.RawValue{
			admodel.InternalCentralPolicyID: {admodel.NewRawValue(sid.Bytes())},
		},
		request.ProtectedFromAccidentalDeletion,
		request.Options,
		true,
		result,
	)
}

func (c *Service) UpdateCentralAccessRule(
	ctx context.Context,
	request UpdateCentralAccessRuleRequest,
) (CentralAccessMutationResult, error) {
	changes, err := admodel.InternalCentralAccessRuleChanges(request)
	if err != nil {
		return admodel.CentralAccessMutationResult{}, err
	}
	return internalServiceUpdateCentralAccess(c,
		ctx,
		request.Identity,
		request.Options,
		changes,
		request.CurrentACL,
		request.ClearCurrentACL,
		request.ProtectedFromAccidentalDeletion,
		false,
	)
}

func (c *Service) UpdateCentralAccessPolicy(
	ctx context.Context,
	request UpdateCentralAccessPolicyRequest,
) (CentralAccessMutationResult, error) {
	if err := admodel.InternalCentralAccessRawChanges(request.Changes); err != nil {
		return admodel.CentralAccessMutationResult{}, err
	}
	return internalServiceUpdateCentralAccess(c,
		ctx,
		request.Identity,
		request.Options,
		append(
			admodel.InternalCentralAccessText("description", request.Description),
			request.Changes...),
		nil,
		false,
		request.ProtectedFromAccidentalDeletion,
		true,
	)
}

func internalServiceUpdateCentralAccess(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	changes []admodel.AttributeChange,
	current *string,
	clearCurrent bool,
	protect *bool,
	policy bool,
) (admodel.CentralAccessMutationResult, error) {
	var result admodel.CentralAccessMutationResult
	if err := admodel.InternalValidateObjectOptions(identity, options); err != nil {
		return result, err
	}
	var mods []admodel.InternalLdapAttributeModification
	var err error
	if len(changes) > 0 {
		mods, err = admodel.InternalObjectChanges(changes)
		if err != nil {
			return result, err
		}
	}
	if protect != nil && options.ExpectedVersion != nil &&
		(*protect || len(mods) > 0 || current != nil || clearCurrent) {
		return result, admodel.ErrObjectControlUnsupported
	}
	ctx, cancel, options, err := InternalServiceCentralAccessMutationContext(c, ctx, options)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalCentralAccessProperties(options.Properties, policy),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalCentralAccessLocation(
				*observed.Object,
				options.Partition,
				policy,
			); err != nil {
				return err
			}
			if err := admodel.InternalCentralAccessProtectionCapability(
				session,
				root,
				protect,
			); err != nil {
				return err
			}
			validation := map[string][]admodel.RawValue{}
			for _, mod := range mods {
				if len(mod.InternalValues) == 1 {
					validation[mod.InternalAttribute] = []admodel.RawValue{
						admodel.NewRawValue(mod.InternalValues[0]),
					}
				}
			}
			if current != nil {
				validation[admodel.InternalCentralCurrent] = []admodel.RawValue{
					admodel.NewRawValue([]byte(*current)),
				}
			}
			if err := admodel.InternalCentralAccessValidateSyntax(session, validation); err != nil {
				return err
			}
			if current != nil || clearCurrent {
				// Strictly replace the observed current value and record that same
				// value as PreviousACL atomically. Hidden current permissions cannot
				// be treated as empty; concurrent replacement must reject this write.
				old, err := observed.Object.Values(admodel.InternalCentralCurrent).Single()
				if err != nil {
					return err
				}
				mods = append(
					mods,
					admodel.InternalLdapAttributeModification{
						InternalOperation: 1,
						InternalAttribute: admodel.InternalCentralCurrent,
						InternalValues:    [][]byte{old.Bytes()},
					},
				)
				if current != nil {
					mods = append(
						mods,
						admodel.InternalLdapAttributeModification{
							InternalOperation: 0,
							InternalAttribute: admodel.InternalCentralCurrent,
							InternalValues:    [][]byte{[]byte(*current)},
						},
					)
				}
				mods = append(
					mods,
					admodel.InternalLdapAttributeModification{
						InternalOperation: 2,
						InternalAttribute: admodel.InternalCentralPrevious,
						InternalValues:    [][]byte{old.Bytes()},
					},
				)
			}
			if len(mods) == 0 {
				if options.ExpectedVersion != nil && protect == nil {
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
				readOptions.Properties = admodel.InternalCentralAccessProperties(
					options.Properties,
					policy,
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
				verification := slices.Clone(mods)
				// A strict remove/add of identical text is a legitimate write; its
				// final effect is replacement, not simultaneous absence/presence.
				if current != nil {
					verification = slices.DeleteFunc(
						verification,
						func(mod admodel.InternalLdapAttributeModification) bool {
							return strings.EqualFold(
								mod.InternalAttribute,
								admodel.InternalCentralCurrent,
							) &&
								mod.InternalOperation == 1
						},
					)
				}
				if err := admodel.InternalVerifyObjectWrite(
					mutation,
					verification,
					"",
				); err != nil {
					return err
				}
			}
			if protect != nil {
				result.Protection.Object = *mutation
				return admodel.InternalChangeOUProtection(
					ctx,
					session,
					root,
					adengine.InternalClientConfig(c.engine()),
					mutation,
					*protect,
					options,
					&result.Protection,
				)
			}
			return nil
		},
	)
	return admodel.InternalCentralAccessProject(result, policy, err)
}

func InternalServiceSetCentralAccessProtection(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	protect bool,
	options admodel.ObjectMutationOptions,
	policy bool,
) (admodel.OUProtectionResult, error) {
	var result admodel.OUProtectionResult
	var err error
	result.Object, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalCentralAccessProperties(options.Properties, policy),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalCentralAccessLocation(
				*observed.Object,
				options.Partition,
				policy,
			); err != nil {
				return err
			}
			return admodel.InternalChangeOUProtection(
				ctx,
				session,
				root,
				adengine.InternalClientConfig(c.engine()),
				mutation,
				protect,
				options,
				&result,
			)
		},
	)
	return result, err
}

func internalServiceDeleteCentralAccess(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	policy bool,
) (admodel.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(identity, options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	ctx, cancel, options, err := InternalServiceCentralAccessMutationContext(c, ctx, options)
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
			Properties: admodel.InternalCentralAccessProperties(options.Properties, policy),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalCentralAccessLocation(
				*observed.Object,
				options.Partition,
				policy,
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

// Deletes submit one native leaf delete. They never unprotect an object, remove
// rule memberships separately, or delete referenced rules/policies. Native
// referential-integrity and access-check outcomes remain authoritative.
func (c *Service) DeleteCentralAccessRule(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	return internalServiceDeleteCentralAccess(c, ctx, identity, options, false)
}

func (c *Service) DeleteCentralAccessPolicy(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	return internalServiceDeleteCentralAccess(c, ctx, identity, options, true)
}
