package resource_properties

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_central_access "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// internalServiceResolveResourceValueType selects the value-type object a property points at.
// Only an identity or an explicit name is accepted; the SDK never guesses a
// value type from the property's own name.
func internalServiceResolveResourceValueType(c *Service,
	ctx context.Context,
	root admodel.RootDSE,
	configuration string,
	reference admodel.SchemaReference,
) (*admodel.ResourceValueTypeResult, error) {
	if admodel.InternalClaimSchemaReferenceEmpty(reference) {
		return nil, errors.Join(admodel.ErrResourceProperty, admodel.ErrInvalidIdentity)
	}
	if reference.LDAPDisplayName != "" && reference.Identity.Form() != 0 {
		return nil, errors.Join(admodel.ErrResourceProperty, admodel.ErrInvalidIdentity)
	}
	if reference.Identity.Form() != 0 {
		return internalServiceReadResourceValueTypeSession(c,
			ctx,
			root,
			configuration,
			reference.Identity.String(),
		)
	}
	if !admodel.InternalValidDirectoryText(reference.LDAPDisplayName) {
		return nil, errors.Join(admodel.ErrResourceProperty, admodel.ErrInvalidIdentity)
	}
	observed, err := admodel.InternalSearchIdentitySession(
		ctx,
		adengine.InternalClientSession(c.engine()),
		admodel.SearchOptions{
			Base:  admodel.InternalResourceValueTypeParent(configuration),
			Scope: admodel.ScopeOneLevel,
			Filter: "(&(objectClass=" + admodel.InternalResourceValueTypeClass + ")(name=" + admodel.InternalLdapLiteral(
				reference.LDAPDisplayName,
			) + "))",
			Properties:  admodel.InternalResourceValueTypeProperties(nil),
			PageSize:    2,
			ResultLimit: 2,
		},
	)
	result := &admodel.ResourceValueTypeResult{
		Observation: admodel.IdentityResult{
			Candidates: observed.Objects,
			Complete:   observed.Complete,
		},
	}
	switch {
	case err != nil:
		return result, err
	case len(observed.Objects) > 1:
		return result, admodel.ErrAmbiguousIdentity
	case !observed.Complete:
		return result, admodel.ErrIncompleteResult
	case len(observed.Objects) == 0:
		return result, admodel.ErrDirectoryObjectNotFound
	}
	object := observed.Objects[0]
	result.Observation.Object = &object
	value, decodeErr := admodel.InternalDecodeResourceValueType(object)
	result.ValueType = &value
	return result, decodeErr
}

// CreateResourceProperty creates one resource property. The value type is
// resolved first, so an unusable reference fails before anything is written.
//
// Related cmdlet: New-ADResourceProperty.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adresourceproperty?view=windowsserver2025-ps
func (c *Service) CreateResourceProperty(
	ctx context.Context,
	request CreateResourcePropertyRequest,
) (ResourcePropertyMutationResult, error) {
	var result admodel.ResourcePropertyMutationResult
	if err := internalServiceValidateResourceCreate(request); err != nil {
		return result, err
	}
	name := request.DisplayName
	if request.ID != nil {
		if *request.ID == "" || !admodel.InternalValidDirectoryText(*request.ID) {
			return result, admodel.ErrInvalidObjectMutation
		}
		name = *request.ID
	} else {
		generated := name
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

	var settled admodel.ClaimValueType
	var sharedDN string
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
		observation, e := internalServiceResolveResourceValueType(c,
			ctx,
			root,
			options.Partition,
			request.ValueType,
		)
		result.ValueTypeObservation = observation
		if e != nil {
			return e
		}
		if observation.ValueType == nil || observation.ValueType.ValueType == nil {
			return errors.Join(admodel.ErrResourceProperty, admodel.ErrAttributeUnavailable)
		}
		settled = *observation.ValueType.ValueType
		if request.SharesValuesWith != nil {
			// The shared reference must be a claim type in its own container,
			// so a property can never share values with an arbitrary object.
			shared, e := admodel.InternalResolveIdentitySession(
				ctx,
				adengine.InternalClientSession(c.engine()),
				adengine.InternalClientConfig(c.engine()),
				root,
				*request.SharesValuesWith,
				admodel.ResolveIdentityOptions{
					Partition:  options.Partition,
					Properties: admodel.InternalClaimProperties(nil),
				},
			)
			if e != nil {
				return e
			}
			if e := admodel.InternalClaimLocation(*shared.Object, options.Partition); e != nil {
				return e
			}
			sharedDN = shared.Object.DistinguishedName
		}
		return nil
	})
	if err != nil {
		return result, err
	}

	attributes := map[string][]admodel.RawValue{}
	for attribute, values := range request.Attributes {
		attributes[attribute] = values
	}
	attributes["displayName"] = []admodel.RawValue{admodel.NewRawValue([]byte(request.DisplayName))}
	attributes[admodel.InternalResourceValueTypeReference] = []admodel.RawValue{
		admodel.NewRawValue(
			[]byte(result.ValueTypeObservation.Observation.Object.DistinguishedName),
		),
	}
	if request.Description != nil {
		attributes["description"] = []admodel.RawValue{
			admodel.NewRawValue([]byte(*request.Description)),
		}
	}
	if sharedDN != "" {
		attributes[admodel.InternalResourceSharesValuesWith] = []admodel.RawValue{
			admodel.NewRawValue([]byte(sharedDN)),
		}
	}
	for _, flag := range []struct {
		InternalAttribute string
		InternalValue     *bool
	}{
		{"enabled", request.Enabled},
		{admodel.InternalResourceIsSecured, request.IsSecured},
		{admodel.InternalClaimRestricted, request.RestrictValues},
	} {
		if flag.InternalValue != nil {
			attributes[flag.InternalAttribute] = []admodel.RawValue{
				admodel.InternalClaimBoolValue(*flag.InternalValue),
			}
		}
	}
	suggested, err := admodel.InternalClaimSuggestedValueAttribute(request.SuggestedValues, settled)
	if err != nil {
		return result, err
	}
	if suggested != nil {
		attributes[admodel.InternalClaimPossible] = suggested
	}
	if len(request.AppliesToResourceTypes) != 0 {
		values := make([]admodel.RawValue, 0, len(request.AppliesToResourceTypes))
		for _, kind := range request.AppliesToResourceTypes {
			values = append(values, admodel.NewRawValue([]byte(kind)))
		}
		attributes[admodel.InternalResourceAppliesTo] = values
	}

	parent, _ := admodel.IdentityByDN(admodel.InternalResourcePropertyParent(options.Partition))
	options.Properties = admodel.InternalResourcePropertyProperties(options.Properties)
	result.Mutation, err = c.engine().
		CreateObject(ctx, admodel.CreateObjectRequest{Parent: parent, Class: admodel.InternalResourcePropertyClass, Name: name, Attributes: attributes, Options: options})
	if err != nil {
		return admodel.InternalResourceProject(result, err)
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
	return admodel.InternalResourceProject(result, err)
}

// UpdateResourceProperty changes one resource property in a single modify. The
// value type is never changed: the reference exposes no parameter for it, so a
// property keeps the value type it was created with.
//
// Related cmdlet: Set-ADResourceProperty.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adresourceproperty?view=windowsserver2025-ps
func (c *Service) UpdateResourceProperty(
	ctx context.Context,
	request UpdateResourcePropertyRequest,
) (ResourcePropertyMutationResult, error) {
	var result admodel.ResourcePropertyMutationResult
	changes, err := admodel.InternalResourcePropertyUpdateChanges(request)
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
			Properties: admodel.InternalResourcePropertyProperties(options.Properties),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalResourceLocation(
				*observed.Object,
				options.Partition,
				admodel.InternalResourcePropertyClass,
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
			applied := changes
			current, decodeErr := admodel.InternalDecodeResourceProperty(*observed.Object)
			if decodeErr != nil {
				return decodeErr
			}
			if request.SharesValuesWith != nil {
				shared, err := admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					*request.SharesValuesWith,
					admodel.ResolveIdentityOptions{
						Partition:  options.Partition,
						Properties: admodel.InternalClaimProperties(nil),
					},
				)
				if err != nil {
					return err
				}
				if err := admodel.InternalClaimLocation(
					*shared.Object,
					options.Partition,
				); err != nil {
					return err
				}
				applied = append(
					applied,
					admodel.AttributeChange{
						Attribute: admodel.InternalResourceSharesValuesWith,
						Kind:      admodel.AttributeSet,
						Values: []admodel.RawValue{
							admodel.NewRawValue([]byte(shared.Object.DistinguishedName)),
						},
					},
				)
			}
			if len(request.SuggestedValues) != 0 {
				// Suggested values are encoded for the value type the property
				// already stores; it is not re-derived or changed here.
				if current.ValueType == nil {
					return errors.Join(admodel.ErrResourceProperty, admodel.ErrAttributeUnavailable)
				}
				suggested, err := admodel.InternalClaimSuggestedValueAttribute(
					request.SuggestedValues,
					*current.ValueType,
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
			return internalServiceSubmitResourceWrite(c,
				ctx,
				session,
				root,
				options,
				applied,
				request.ProtectedFromAccidentalDeletion,
				mutation,
				&result.Protection,
				admodel.InternalResourcePropertyProperties,
			)
		},
	)
	return admodel.InternalResourceProject(result, err)
}

// internalServiceSubmitResourceWrite submits resource attribute and protection changes, preserving
// readback and verification results.
func internalServiceSubmitResourceWrite(c *Service,
	ctx context.Context,
	session admodel.InternalLdapWriteSession,
	root admodel.RootDSE,
	options admodel.ObjectMutationOptions,
	changes []admodel.AttributeChange,
	protect *bool,
	mutation *admodel.ObjectMutationResult,
	protection *admodel.OUProtectionResult,
	properties func([]string) []string,
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
		readOptions.Properties = properties(options.Properties)
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
		if err := admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, mutation, mods, ""); err != nil {
			return err
		}
	}
	if protect != nil {
		protection.Object = *mutation
		return admodel.InternalChangeOUProtection(
			ctx,
			session,
			root,
			adengine.InternalClientConfig(c.engine()),
			mutation,
			*protect,
			options,
			protection,
		)
	}
	return nil
}

// DeleteResourceProperty removes one resource property with a single native
// leaf delete. It never removes the property from the lists that reference it;
// the directory's own referential outcome is surfaced unchanged.
//
// Related cmdlet: Remove-ADResourceProperty.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adresourceproperty?view=windowsserver2025-ps
func (c *Service) DeleteResourceProperty(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	return internalServiceDeleteResourceObject(c,
		ctx,
		identity,
		options,
		admodel.InternalResourcePropertyClass,
		admodel.InternalResourcePropertyProperties,
	)
}

// DeleteResourcePropertyList removes one property list. It never deletes the
// properties the list referenced.
//
// Related cmdlet: Remove-ADResourcePropertyList.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adresourcepropertylist?view=windowsserver2025-ps
func (c *Service) DeleteResourcePropertyList(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	return internalServiceDeleteResourceObject(c,
		ctx,
		identity,
		options,
		admodel.InternalResourcePropertyListClass,
		admodel.InternalResourceListProperties,
	)
}

// internalServiceDeleteResourceObject validates a resource property or list before issuing a leaf
// deletion.
func internalServiceDeleteResourceObject(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	class string,
	properties func([]string) []string,
) (admodel.ObjectMutationResult, error) {
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
		admodel.ResolveIdentityOptions{Properties: properties(options.Properties)},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalResourceLocation(
				*observed.Object,
				options.Partition,
				class,
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

// CreateResourcePropertyList creates one property list.
//
// Related cmdlet: New-ADResourcePropertyList.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adresourcepropertylist?view=windowsserver2025-ps
func (c *Service) CreateResourcePropertyList(
	ctx context.Context,
	request CreateResourcePropertyListRequest,
) (ResourcePropertyListMutationResult, error) {
	var result admodel.ResourcePropertyListMutationResult
	if err := admodel.InternalCentralAccessCreateInput(
		request.Name,
		request.Description,
		request.Options,
	); err != nil {
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
	if request.Description != nil {
		attributes["description"] = []admodel.RawValue{
			admodel.NewRawValue([]byte(*request.Description)),
		}
	}
	parent, _ := admodel.IdentityByDN(admodel.InternalResourcePropertyListParent(options.Partition))
	options.Properties = admodel.InternalResourceListProperties(options.Properties)
	result.Mutation, err = c.engine().
		CreateObject(ctx, admodel.CreateObjectRequest{
			Parent:     parent,
			Class:      admodel.InternalResourcePropertyListClass,
			Name:       request.Name,
			Attributes: attributes,
			Options:    options,
		})
	if err != nil {
		return admodel.InternalResourceListProject(result, err)
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
	return admodel.InternalResourceListProject(result, err)
}

// UpdateResourcePropertyList changes one property list. Membership is edited
// with AddResourcePropertyListMembers and RemoveResourcePropertyListMembers,
// not through this call.
//
// Related cmdlet: Set-ADResourcePropertyList.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adresourcepropertylist?view=windowsserver2025-ps
func (c *Service) UpdateResourcePropertyList(
	ctx context.Context,
	request UpdateResourcePropertyListRequest,
) (ResourcePropertyListMutationResult, error) {
	var result admodel.ResourcePropertyListMutationResult
	if request.Description != nil && request.ClearDescription {
		return result, admodel.ErrResourceProperty
	}
	if err := admodel.InternalResourceRawChanges(request.Changes); err != nil {
		return result, err
	}
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	var changes []admodel.AttributeChange
	if request.Description != nil {
		if !admodel.InternalValidDirectoryText(*request.Description) {
			return result, admodel.ErrInvalidObjectMutation
		}
		changes = append(
			changes,
			admodel.AttributeChange{
				Attribute: "description",
				Kind:      admodel.AttributeSet,
				Values:    []admodel.RawValue{admodel.NewRawValue([]byte(*request.Description))},
			},
		)
	}
	if request.ClearDescription {
		changes = append(
			changes,
			admodel.AttributeChange{Attribute: "description", Kind: admodel.AttributeClear},
		)
	}
	changes = append(changes, request.Changes...)
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
			Properties: admodel.InternalResourceListProperties(options.Properties),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalResourceLocation(
				*observed.Object,
				options.Partition,
				admodel.InternalResourcePropertyListClass,
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
			return internalServiceSubmitResourceWrite(c,
				ctx,
				session,
				root,
				options,
				changes,
				request.ProtectedFromAccidentalDeletion,
				mutation,
				&result.Protection,
				admodel.InternalResourceListProperties,
			)
		},
	)
	return admodel.InternalResourceListProject(result, err)
}

// AddResourcePropertyListMembers adds resource properties to one list.
func (c *Service) AddResourcePropertyListMembers(
	ctx context.Context,
	request ResourcePropertyListMembersRequest,
) (ResourcePropertyListMembersResult, error) {
	return internalServiceChangeResourceListMembers(c, ctx, request, false)
}

// RemoveResourcePropertyListMembers removes resource properties from one list.
// It never deletes the properties themselves.
func (c *Service) RemoveResourcePropertyListMembers(
	ctx context.Context,
	request ResourcePropertyListMembersRequest,
) (ResourcePropertyListMembersResult, error) {
	return internalServiceChangeResourceListMembers(c, ctx, request, true)
}

// internalServiceChangeResourceListMembers resolves resource properties before adding or removing list
// membership links.
func internalServiceChangeResourceListMembers(c *Service,
	ctx context.Context,
	request admodel.ResourcePropertyListMembersRequest,
	remove bool,
) (admodel.ResourcePropertyListMembersResult, error) {
	var result admodel.ResourcePropertyListMembersResult
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if len(request.Members) == 0 || len(request.Members) > admodel.ResourcePropertyListMemberLimit {
		return result, admodel.ErrResourcePropertyMember
	}
	limits, err := admodel.InternalNormalizeCentralAccessLimits(request.References)
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
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalResourceListProperties(options.Properties),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalResourceLocation(
				*observed.Object,
				options.Partition,
				admodel.InternalResourcePropertyListClass,
			); err != nil {
				return err
			}
			before, err := admodel.InternalReadCentralAccessReferences(
				ctx,
				session,
				*observed.Object,
				admodel.InternalResourceListMembers,
				limits,
			)
			result.Before = before
			if err != nil {
				return err
			}
			if !remove &&
				len(
					before.References,
				)+len(
					request.Members,
				) > admodel.ResourcePropertyListMemberLimit {
				return admodel.ErrResourcePropertyMember
			}
			values := make([][]byte, 0, len(request.Members))
			seen := map[string]struct{}{}
			for _, identity := range request.Members {
				// Every member must be a resource property in its own container,
				// so a list can never reference an arbitrary object.
				input, err := admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					identity,
					admodel.ResolveIdentityOptions{
						Partition:  options.Partition,
						Properties: admodel.InternalResourcePropertyProperties(nil),
					},
				)
				result.Inputs = append(
					result.Inputs,
					admodel.CentralAccessMemberInput{Identity: identity, Observation: input},
				)
				if err != nil {
					return err
				}
				if err := admodel.InternalResourceLocation(
					*input.Object,
					options.Partition,
					admodel.InternalResourcePropertyClass,
				); err != nil {
					return err
				}
				parsed, err := admodel.InternalParseIdentityDN(input.Object.DistinguishedName)
				if err != nil {
					return err
				}
				key := admodel.InternalIdentityDNKey(parsed)
				if _, duplicate := seen[key]; duplicate {
					return admodel.ErrResourcePropertyMember
				}
				seen[key] = struct{}{}
				values = append(values, []byte(input.Object.DistinguishedName))
			}
			operation := uint32(0)
			if remove {
				operation = 1
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
					InternalOperation: admodel.InternalLdapWriteModify,
					InternalDn:        admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
					InternalModifications: []admodel.InternalLdapAttributeModification{
						{
							InternalOperation: operation,
							InternalAttribute: admodel.InternalResourceListMembers,
							InternalValues:    values,
						},
					},
					InternalControls: controls,
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
				admodel.InternalResourceListProperties(options.Properties),
				false,
			); err != nil {
				return err
			}
			after, err := admodel.InternalReadCentralAccessReferences(
				ctx,
				session,
				*mutation.After,
				admodel.InternalResourceListMembers,
				limits,
			)
			result.After = after
			if err != nil {
				return errors.Join(admodel.ErrObjectReadback, err)
			}
			return nil
		},
	)
	return result, err
}

// internalServiceValidateResourceCreate checks text, raw attributes and resource
// applicability before resolving any value-type or shared-claim references.
func internalServiceValidateResourceCreate(request admodel.CreateResourcePropertyRequest) error {
	if request.DisplayName == "" || !admodel.InternalValidDirectoryText(request.DisplayName) {
		return admodel.ErrInvalidObjectMutation
	}
	if request.Description != nil && !admodel.InternalValidDirectoryText(*request.Description) {
		return admodel.ErrInvalidObjectMutation
	}
	if request.Options.ExpectedVersion != nil {
		return admodel.ErrObjectControlUnsupported
	}
	if err := admodel.InternalResourceRawAttributes(request.Attributes); err != nil {
		return err
	}
	if err := admodel.InternalResourceAppliesToValid(request.AppliesToResourceTypes); err != nil {
		return err
	}
	return nil
}
