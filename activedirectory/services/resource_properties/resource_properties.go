package resource_properties

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// internalServiceResourceRead resolves one object of the requested class inside the Claims
// Configuration container and hands it to the caller's projection.
func internalServiceResourceRead(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ResolveIdentityOptions,
	class string,
	properties func([]string) []string,
	project func(context.Context, admodel.RootDSE, string, admodel.IdentityResult) error,
) (admodel.IdentityResult, error) {
	var observed admodel.IdentityResult
	if err := admodel.InternalCentralAccessIdentity(identity, options); err != nil {
		return observed, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		configuration, e := admodel.InternalCentralAccessConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			options.Partition,
		)
		if e != nil {
			return e
		}
		resolve := options
		resolve.Partition = configuration
		resolve.Properties = properties(options.Properties)
		observed, e = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			resolve,
		)
		if e != nil {
			return e
		}
		if e := admodel.InternalResourceLocation(*observed.Object, configuration, class); e != nil {
			return e
		}
		return project(ctx, root, configuration, observed)
	})
	return observed, err
}

// ResourceProperty reads one resource property by identity.
//
// Related cmdlet: Get-ADResourceProperty.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adresourceproperty?view=windowsserver2025-ps
func (c *Service) ResourceProperty(
	ctx context.Context,
	identity adshared.Identity,
	options ResourcePropertyReadOptions,
) (ResourcePropertyResult, error) {
	var result admodel.ResourcePropertyResult
	limits, err := admodel.InternalNormalizeCentralAccessLimits(options.References)
	if err != nil {
		return result, err
	}
	result.Observation, err = internalServiceResourceRead(
		c,
		ctx,
		identity,
		options.ResolveIdentityOptions,
		admodel.InternalResourcePropertyClass,
		admodel.InternalResourcePropertyProperties,
		func(ctx context.Context, root admodel.RootDSE, configuration string, observed admodel.IdentityResult) error {
			value, decodeErr := admodel.InternalDecodeResourceProperty(*observed.Object)
			result.Property = &value
			var err error
			if options.IncludeValueType && value.ValueTypeDN != nil {
				observation, e := internalServiceReadResourceValueTypeSession(c,
					ctx,
					root,
					configuration,
					*value.ValueTypeDN,
				)
				result.ValueTypeObservation = observation
				err = e
				// The property's own stored value type must agree with the object
				// it references; a disagreement is reported, never reconciled.
				if e == nil && observation != nil && observation.ValueType != nil &&
					value.ValueType != nil &&
					observation.ValueType.ValueType != nil &&
					*observation.ValueType.ValueType != *value.ValueType {
					err = admodel.ErrResourceProperty
				}
			}
			if options.IncludeProtection && value.GUID != nil {
				protection, e := admodel.InternalReadOUProtection(
					ctx,
					adengine.InternalClientSession(c.engine()),
					root,
					adengine.InternalClientConfig(c.engine()),
					admodel.OrganizationalUnit{
						DistinguishedName: observed.Object.DistinguishedName,
						GUID:              value.GUID,
					},
					configuration,
				)
				result.Protection = protection
				value.ProtectedFromAccidentalDeletion = protection.ProtectedFromAccidentalDeletion
				result.Property = &value
				err = errors.Join(err, e)
			}
			_ = limits
			return errors.Join(decodeErr, err)
		},
	)
	return result, err
}

// internalServiceReadResourceValueTypeSession reads and decodes one resource-property value type in
// the selected configuration partition.
func internalServiceReadResourceValueTypeSession(c *Service,
	ctx context.Context,
	root admodel.RootDSE,
	configuration, dn string,
) (*admodel.ResourceValueTypeResult, error) {
	identity, err := admodel.IdentityByDN(dn)
	if err != nil {
		return nil, err
	}
	observed, err := admodel.InternalResolveIdentitySession(
		ctx,
		adengine.InternalClientSession(c.engine()),
		adengine.InternalClientConfig(c.engine()),
		root,
		identity,
		admodel.ResolveIdentityOptions{
			Partition:  configuration,
			Properties: admodel.InternalResourceValueTypeProperties(nil),
		},
	)
	result := &admodel.ResourceValueTypeResult{Observation: observed}
	if err != nil {
		return result, err
	}
	if err := admodel.InternalResourceLocation(
		*observed.Object,
		configuration,
		admodel.InternalResourceValueTypeClass,
	); err != nil {
		return result, err
	}
	value, decodeErr := admodel.InternalDecodeResourceValueType(*observed.Object)
	result.ValueType = &value
	return result, decodeErr
}

// ResourceValueType reads one read-only value type by identity.
//
// Related cmdlet: Get-ADResourcePropertyValueType.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adresourcepropertyvaluetype?view=windowsserver2025-ps
func (c *Service) ResourceValueType(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (ResourceValueTypeResult, error) {
	var result admodel.ResourceValueTypeResult
	var err error
	result.Observation, err = internalServiceResourceRead(
		c,
		ctx,
		identity,
		options,
		admodel.InternalResourceValueTypeClass,
		admodel.InternalResourceValueTypeProperties,
		func(_ context.Context, _ admodel.RootDSE, _ string, observed admodel.IdentityResult) error {
			value, decodeErr := admodel.InternalDecodeResourceValueType(*observed.Object)
			result.ValueType = &value
			return decodeErr
		},
	)
	return result, err
}

// internalServiceResourceSearch restricts a caller's query to one container and class.
func internalServiceResourceSearch(c *Service,
	ctx context.Context,
	options admodel.SearchOptions,
	class string,
	properties func([]string) []string,
	row func(context.Context, admodel.RootDSE, string, admodel.Object) error,
) (admodel.SearchResult, error) {
	var observation admodel.SearchResult
	query, err := admodel.InternalSearchOptionsNormalized(options)
	if err != nil {
		return observation, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		configuration, e := admodel.InternalCentralAccessConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			"",
		)
		if e != nil {
			return e
		}
		container := admodel.InternalResourceContainerFor(class, configuration)
		if query.Base != "" && !admodel.InternalCentralSameDN(query.Base, container) {
			return admodel.ErrIdentityScope
		}
		query.Base = container
		query.Scope = admodel.ScopeOneLevel
		query.Filter = "(&(objectClass=" + class + ")" + query.Filter + ")"
		query.Properties = properties(options.Properties)
		observation, e = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			query,
		)
		for _, object := range observation.Objects {
			e = errors.Join(e, row(ctx, root, configuration, object))
		}
		return e
	})
	if err != nil {
		observation.Complete = false
	}
	return observation, err
}

// ResourceProperties lists resource properties in the Claims Configuration
// container. The value type reference is not resolved per row; read one
// property with IncludeValueType for that.
//
// Related cmdlet: Get-ADResourceProperty.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adresourceproperty?view=windowsserver2025-ps
func (c *Service) ResourceProperties(
	ctx context.Context,
	options adshared.SearchOptions,
) (ResourcePropertiesResult, error) {
	var result admodel.ResourcePropertiesResult
	var err error
	result.Observation, err = internalServiceResourceSearch(c,
		ctx,
		options,
		admodel.InternalResourcePropertyClass,
		admodel.InternalResourcePropertyProperties,
		func(_ context.Context, _ admodel.RootDSE, _ string, object admodel.Object) error {
			value, decodeErr := admodel.InternalDecodeResourceProperty(object)
			result.Properties = append(
				result.Properties,
				admodel.ResourcePropertyResult{
					Property:    &value,
					Observation: admodel.IdentityResult{Object: &object, Complete: true},
				},
			)
			return decodeErr
		},
	)
	return result, err
}

// ResourceValueTypes lists the read-only value types.
//
// Related cmdlet: Get-ADResourcePropertyValueType.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adresourcepropertyvaluetype?view=windowsserver2025-ps
func (c *Service) ResourceValueTypes(
	ctx context.Context,
	options adshared.SearchOptions,
) (ResourceValueTypesResult, error) {
	var result admodel.ResourceValueTypesResult
	var err error
	result.Observation, err = internalServiceResourceSearch(c,
		ctx,
		options,
		admodel.InternalResourceValueTypeClass,
		admodel.InternalResourceValueTypeProperties,
		func(_ context.Context, _ admodel.RootDSE, _ string, object admodel.Object) error {
			value, decodeErr := admodel.InternalDecodeResourceValueType(object)
			result.ValueTypes = append(
				result.ValueTypes,
				admodel.ResourceValueTypeResult{
					ValueType:   &value,
					Observation: admodel.IdentityResult{Object: &object, Complete: true},
				},
			)
			return decodeErr
		},
	)
	return result, err
}

// ResourcePropertyList reads one property list. Members are retrieved through
// the shared bounded reference reader, so a large list is either complete or
// reported as incomplete rather than silently truncated.
//
// Related cmdlet: Get-ADResourcePropertyList.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adresourcepropertylist?view=windowsserver2025-ps
func (c *Service) ResourcePropertyList(
	ctx context.Context,
	identity adshared.Identity,
	options ResourcePropertyReadOptions,
) (ResourcePropertyListResult, error) {
	var result admodel.ResourcePropertyListResult
	limits, err := admodel.InternalNormalizeCentralAccessLimits(options.References)
	if err != nil {
		return result, err
	}
	result.Observation, err = internalServiceResourceRead(
		c,
		ctx,
		identity,
		options.ResolveIdentityOptions,
		admodel.InternalResourcePropertyListClass,
		admodel.InternalResourceListProperties,
		func(ctx context.Context, root admodel.RootDSE, configuration string, observed admodel.IdentityResult) error {
			value, decodeErr := admodel.InternalDecodeResourcePropertyList(*observed.Object)
			result.List = &value
			members, membersErr := admodel.InternalReadCentralAccessReferences(
				ctx,
				adengine.InternalClientSession(c.engine()),
				*observed.Object,
				admodel.InternalResourceListMembers,
				limits,
			)
			result.Members = members
			err := errors.Join(decodeErr, membersErr)
			if options.IncludeProtection && value.GUID != nil {
				protection, protectErr := admodel.InternalReadOUProtection(
					ctx,
					adengine.InternalClientSession(c.engine()),
					root,
					adengine.InternalClientConfig(c.engine()),
					admodel.OrganizationalUnit{
						DistinguishedName: observed.Object.DistinguishedName,
						GUID:              value.GUID,
					},
					configuration,
				)
				result.Protection = protection
				value.ProtectedFromAccidentalDeletion = protection.ProtectedFromAccidentalDeletion
				result.List = &value
				err = errors.Join(err, protectErr)
			}
			return err
		},
	)
	return result, err
}

// ResourcePropertyLists lists property lists. Members are not retrieved per
// row; read one list for its membership.
//
// Related cmdlet: Get-ADResourcePropertyList.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adresourcepropertylist?view=windowsserver2025-ps
func (c *Service) ResourcePropertyLists(
	ctx context.Context,
	options adshared.SearchOptions,
) (ResourcePropertyListsResult, error) {
	var result admodel.ResourcePropertyListsResult
	var err error
	result.Observation, err = internalServiceResourceSearch(c,
		ctx,
		options,
		admodel.InternalResourcePropertyListClass,
		admodel.InternalResourceListProperties,
		func(_ context.Context, _ admodel.RootDSE, _ string, object admodel.Object) error {
			value, decodeErr := admodel.InternalDecodeResourcePropertyList(object)
			result.Lists = append(
				result.Lists,
				admodel.ResourcePropertyListResult{
					List:        &value,
					Observation: admodel.IdentityResult{Object: &object, Complete: true},
				},
			)
			return decodeErr
		},
	)
	return result, err
}
