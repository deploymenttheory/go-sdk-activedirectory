package claims

import (
	"context"
	"errors"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// ClaimType reads one claim type with its schema and resource-property references. Options select the
// configuration partition, extra properties, and reference limits; partial observations may accompany
// an error.
//
// Related cmdlet: Get-ADClaimType.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adclaimtype?view=windowsserver2025-ps
func (c *Service) ClaimType(
	ctx context.Context,
	identity adshared.Identity,
	options ClaimTypeReadOptions,
) (result ClaimTypeResult, err error) {
	if err := admodel.InternalCentralAccessIdentity(
		identity,
		options.ResolveIdentityOptions,
	); err != nil {
		return result, err
	}
	limits, err := admodel.InternalNormalizeCentralAccessLimits(options.References)
	if err != nil {
		return result, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
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
		resolve := options.ResolveIdentityOptions
		resolve.Partition = configuration
		resolve.Properties = admodel.InternalClaimProperties(resolve.Properties)
		result.Observation, e = admodel.InternalResolveIdentitySession(
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
		return internalServiceProjectClaimType(
			c,
			ctx,
			root,
			configuration,
			options,
			limits,
			&result,
		)
	})
	return result, err
}

// internalServiceProjectClaimType decodes a claim and reads its bounded schema and resource-property
// references.
func internalServiceProjectClaimType(c *Service,
	ctx context.Context,
	root admodel.RootDSE,
	configuration string,
	options admodel.ClaimTypeReadOptions,
	limits admodel.CentralAccessReferenceLimits,
	result *admodel.ClaimTypeResult,
) error {
	object := *result.Observation.Object
	value, decodeErr := admodel.InternalDecodeClaimType(object)
	result.Claim = &value
	if err := admodel.InternalClaimLocation(object, configuration); err != nil {
		return errors.Join(decodeErr, err)
	}
	var err, errorRefs error
	result.AppliesToClasses, err = admodel.InternalReadCentralAccessReferences(
		ctx,
		adengine.InternalClientSession(c.engine()),
		object,
		admodel.InternalClaimApplies,
		limits,
	)
	result.ResourceReferences, errorRefs = admodel.InternalReadCentralAccessReferences(
		ctx,
		adengine.InternalClientSession(c.engine()),
		object,
		admodel.InternalClaimBacklinks,
		limits,
	)
	err = errors.Join(decodeErr, err, errorRefs)
	if options.IncludeSchema && err == nil {
		schema := admodel.InternalNewClaimSchemaReader(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			&result.Schema,
		)
		source, e := admodel.InternalClaimSourceFromObject(value)
		if e == nil {
			_, e = admodel.InternalValidateClaimSchema(
				schema,
				source,
				admodel.InternalClaimReferences(result.AppliesToClasses),
				value.ValueType,
			)
		}
		err = errors.Join(err, e)
	}
	if options.IncludeCompatibleResourceTypes {
		if value.ValueType == nil || value.RestrictValues == nil {
			err = errors.Join(err, admodel.ErrAttributeUnavailable)
		} else {
			filter := admodel.FilterAnd(
				admodel.FilterEqual("objectClass", admodel.FilterText("msDS-ValueType")),
				admodel.FilterEqual(
					admodel.InternalClaimValueType,
					admodel.FilterInteger(int64(*value.ValueType)),
				),
				admodel.FilterEqual(
					"msDS-IsPossibleValuesPresent",
					admodel.FilterText(
						strings.ToUpper(
							admodel.InternalStrconvClaimBool(value.SuggestedValues != nil),
						),
					),
				),
			)
			result.CompatibleResourceTypes, errorRefs = admodel.InternalSearchIdentitySession(
				ctx,
				adengine.InternalClientSession(c.engine()),
				admodel.SearchOptions{
					Base:        "CN=Value Types,CN=Claims Configuration,CN=Services," + configuration,
					Scope:       admodel.ScopeOneLevel,
					TypedFilter: filter,
					Properties: []string{
						"objectGUID",
						"name",
						"displayName",
						admodel.InternalClaimValueType,
						admodel.InternalClaimSingle,
						admodel.InternalClaimRestricted,
						"msDS-IsPossibleValuesPresent",
					},
				},
			)
			err = errors.Join(err, errorRefs)
		}
	}
	if options.IncludeProtection && value.GUID != nil {
		result.Protection, errorRefs = admodel.InternalReadOUProtection(
			ctx,
			adengine.InternalClientSession(c.engine()),
			root,
			adengine.InternalClientConfig(c.engine()),
			admodel.OrganizationalUnit{
				DistinguishedName: object.DistinguishedName,
				GUID:              value.GUID,
			},
			configuration,
		)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Claim = &value
		err = errors.Join(err, errorRefs)
	}
	return err
}

// ClaimTypes searches claim types and projects their schema and resource-property references. Options
// bound the search and reference expansion; raw search observations and projection errors are
// retained.
//
// Related cmdlet: Get-ADClaimType.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adclaimtype?view=windowsserver2025-ps
func (c *Service) ClaimTypes(
	ctx context.Context,
	options adshared.SearchOptions,
) (result ClaimTypesResult, err error) {
	query, err := admodel.InternalSearchOptionsNormalized(options)
	if err != nil {
		return result, err
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
		if query.Base != "" &&
			!admodel.InternalCentralSameDN(query.Base, admodel.InternalClaimParent(configuration)) {
			return admodel.ErrIdentityScope
		}
		query.Base = admodel.InternalClaimParent(configuration)
		query.Scope = admodel.ScopeOneLevel
		query.Filter = "(&(objectClass=" + admodel.InternalClaimClass + ")" + query.Filter + ")"
		query.Properties = admodel.InternalClaimProperties(options.Properties)
		result.Observation, e = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			query,
		)
		limits, _ := admodel.InternalNormalizeCentralAccessLimits(
			admodel.CentralAccessReferenceLimits{},
		)
		for _, object := range result.Observation.Objects {
			row := admodel.ClaimTypeResult{
				Observation: admodel.IdentityResult{Object: &object, Complete: true},
			}
			rowErr := internalServiceProjectClaimType(c,
				ctx,
				root,
				configuration,
				admodel.ClaimTypeReadOptions{},
				limits,
				&row,
			)
			result.Claims = append(result.Claims, row)
			e = errors.Join(e, rowErr)
		}
		return e
	})
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
