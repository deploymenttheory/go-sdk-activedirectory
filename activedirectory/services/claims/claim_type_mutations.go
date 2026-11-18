package claims

import (
	"context"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_central_access "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// CreateClaimType creates one claim type. The source is resolved against the
// schema before anything is submitted, so an unusable source fails without a
// partially built object.
//
// Related cmdlet: New-ADClaimType.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adclaimtype?view=windowsserver2025-ps
func (c *Service) CreateClaimType(
	ctx context.Context,
	request CreateClaimTypeRequest,
) (ClaimTypeMutationResult, error) {
	var result admodel.ClaimTypeMutationResult
	if request.DisplayName == "" || !admodel.InternalValidDirectoryText(request.DisplayName) {
		return result, admodel.ErrInvalidObjectMutation
	}
	if request.Description != nil && !admodel.InternalValidDirectoryText(*request.Description) {
		return result, admodel.ErrInvalidObjectMutation
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	if err := admodel.InternalClaimRawAttributes(request.Attributes); err != nil {
		return result, err
	}
	id := ""
	if request.ID != nil {
		if err := admodel.InternalValidateClaimID(*request.ID); err != nil {
			return result, err
		}
		id = *request.ID
	} else {
		generated, err := admodel.InternalGenerateClaimID(request.DisplayName)
		if err != nil {
			return result, err
		}
		id = generated
		result.GeneratedID = &generated
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

	var resolution admodel.InternalClaimSchemaResolution
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		if e := admodel.InternalCentralAccessProtectionCapability(
			adengine.InternalClientSession(c.engine()),
			root,
			request.ProtectedFromAccidentalDeletion,
		); e != nil {
			return e
		}
		reader := admodel.InternalNewClaimSchemaReader(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			&result.Schema,
		)
		resolution, e = admodel.InternalValidateClaimSchema(
			reader,
			request.Source,
			request.AppliesToClasses,
			nil,
		)
		return e
	})
	if err != nil {
		return result, err
	}

	attributes := admodel.InternalClaimSourceAttributes(request.Source, resolution)
	for name, values := range request.Attributes {
		attributes[name] = values
	}
	attributes["displayName"] = []admodel.RawValue{admodel.NewRawValue([]byte(request.DisplayName))}
	if request.Description != nil {
		attributes["description"] = []admodel.RawValue{
			admodel.NewRawValue([]byte(*request.Description)),
		}
	}
	if request.Enabled != nil {
		attributes["enabled"] = []admodel.RawValue{admodel.InternalClaimBoolValue(*request.Enabled)}
	}
	if request.IsSingleValued != nil {
		attributes[admodel.InternalClaimSingle] = []admodel.RawValue{
			admodel.InternalClaimBoolValue(*request.IsSingleValued),
		}
	}
	if request.RestrictValues != nil {
		attributes[admodel.InternalClaimRestricted] = []admodel.RawValue{
			admodel.InternalClaimBoolValue(*request.RestrictValues),
		}
	}
	suggested, err := admodel.InternalClaimSuggestedValueAttribute(
		request.SuggestedValues,
		resolution.ValueType,
	)
	if err != nil {
		return result, err
	}
	if suggested != nil {
		attributes[admodel.InternalClaimPossible] = suggested
	}
	if len(resolution.AppliesToClassDNs) != 0 {
		attributes[admodel.InternalClaimApplies] = admodel.InternalClaimClassValues(
			resolution.AppliesToClassDNs,
		)
	}

	parent, _ := admodel.IdentityByDN(admodel.InternalClaimParent(options.Partition))
	options.Properties = admodel.InternalClaimProperties(options.Properties)
	result.Mutation, err = c.engine().
		CreateObject(ctx, admodel.CreateObjectRequest{Parent: parent, Class: admodel.InternalClaimClass, Name: id, Attributes: attributes, Options: options})
	if err != nil {
		return admodel.InternalClaimProject(result, err)
	}
	if request.ProtectedFromAccidentalDeletion != nil {
		protection, e := adservice_central_access.InternalServiceSetCentralAccessProtection(
			adservice_central_access.New(c.engine()),
			ctx,
			admodel.InternalObjectGUIDIdentity(*result.Mutation.TargetGUID),
			*request.ProtectedFromAccidentalDeletion,
			admodel.ObjectMutationOptions{Partition: options.Partition},
			false,
		)
		result.Protection = protection
		err = e
	}
	return admodel.InternalClaimProject(result, err)
}

// UpdateClaimType changes one claim type in a single modify. A source change
// is resolved against the schema and must agree with the stored value type.
//
// Related cmdlet: Set-ADClaimType.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adclaimtype?view=windowsserver2025-ps
func (c *Service) UpdateClaimType(
	ctx context.Context,
	request UpdateClaimTypeRequest,
) (ClaimTypeMutationResult, error) {
	var result admodel.ClaimTypeMutationResult
	changes, err := admodel.InternalClaimUpdateChanges(request)
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
			Properties: admodel.InternalClaimProperties(options.Properties),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalClaimLocation(
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
			current, decodeErr := admodel.InternalDecodeClaimType(*observed.Object)
			if decodeErr != nil {
				return decodeErr
			}
			applied := changes
			if request.Source != nil || len(request.AppliesToClasses) != 0 ||
				len(request.SuggestedValues) != 0 {
				reader := admodel.InternalNewClaimSchemaReader(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					&result.Schema,
				)
				var source admodel.ClaimTypeSource
				if request.Source != nil {
					source = *request.Source
				} else {
					// Without a stated source the claim keeps its own, so the
					// applies-to classes and values are still settled against it.
					observedSource, err := admodel.InternalClaimSourceFromObject(current)
					if err != nil {
						return err
					}
					source = observedSource
				}
				resolution, err := admodel.InternalValidateClaimSchema(
					reader,
					source,
					request.AppliesToClasses,
					current.ValueType,
				)
				if err != nil {
					return err
				}
				if request.Source != nil {
					for name, values := range admodel.InternalClaimSourceAttributes(source, resolution) {
						applied = append(
							applied,
							admodel.AttributeChange{
								Attribute: name,
								Kind:      admodel.AttributeSet,
								Values:    values,
							},
						)
					}
					// Re-pointing a source retires the attributes the previous
					// form owned, so a stale DN or OID never outlives it.
					for _, stale := range admodel.InternalClaimStaleSourceAttributes(source.Type) {
						applied = append(
							applied,
							admodel.AttributeChange{Attribute: stale, Kind: admodel.AttributeClear},
						)
					}
				}
				if len(resolution.AppliesToClassDNs) != 0 {
					kind := admodel.AttributeAddValues
					if request.ReplaceAppliesToClasses {
						kind = admodel.AttributeSet
					}
					applied = append(
						applied,
						admodel.AttributeChange{
							Attribute: admodel.InternalClaimApplies,
							Kind:      kind,
							Values: admodel.InternalClaimClassValues(
								resolution.AppliesToClassDNs,
							),
						},
					)
				}
				if len(request.SuggestedValues) != 0 {
					suggested, err := admodel.InternalClaimSuggestedValueAttribute(
						request.SuggestedValues,
						resolution.ValueType,
					)
					if err != nil {
						return err
					}
					applied = append(
						applied,
						admodel.AttributeChange{
							Attribute: admodel.InternalClaimPossible,
							Kind:      admodel.AttributeSet,
							Values:    suggested,
						},
					)
				}
			}
			return internalServiceSubmitClaimTypeUpdate(c,
				ctx,
				session,
				root,
				options,
				applied,
				request.ProtectedFromAccidentalDeletion,
				mutation,
				&result,
			)
		},
	)
	return admodel.InternalClaimProject(result, err)
}

// internalServiceSubmitClaimTypeUpdate submits claim-type attribute and protection changes while
// retaining separate write outcomes.
func internalServiceSubmitClaimTypeUpdate(c *Service,
	ctx context.Context,
	session admodel.InternalLdapWriteSession,
	root admodel.RootDSE,
	options admodel.ObjectMutationOptions,
	changes []admodel.AttributeChange,
	protect *bool,
	mutation *admodel.ObjectMutationResult,
	result *admodel.ClaimTypeMutationResult,
) error {
	mods, err := admodel.InternalObjectChanges(changes)
	if err != nil {
		return err
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
		readOptions := options
		readOptions.Properties = admodel.InternalClaimProperties(options.Properties)
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
}

// DeleteClaimType removes one claim type. It submits a single native leaf
// delete and never unprotects the object or removes references for the caller.
//
// Related cmdlet: Remove-ADClaimType.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adclaimtype?view=windowsserver2025-ps
func (c *Service) DeleteClaimType(
	ctx context.Context,
	request DeleteClaimTypeRequest,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	limits, err := admodel.InternalNormalizeCentralAccessLimits(request.References)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	ctx, cancel, options, err := adservice_central_access.InternalServiceCentralAccessMutationContext(
		adservice_central_access.New(c.engine()),
		ctx,
		request.Options,
	)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	defer cancel()
	return adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalClaimProperties(options.Properties),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalClaimLocation(
				*observed.Object,
				options.Partition,
			); err != nil {
				return err
			}
			if !request.Force {
				// An observed reference is reported without deleting. A failed or
				// incomplete reference read is never read as "no references".
				references, err := admodel.InternalReadCentralAccessReferences(
					ctx,
					session,
					*observed.Object,
					admodel.InternalClaimBacklinks,
					limits,
				)
				if err != nil {
					return err
				}
				if !references.Complete {
					return admodel.ErrIncompleteResult
				}
				if len(references.References) != 0 {
					return admodel.ErrClaimTypeReferenced
				}
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
