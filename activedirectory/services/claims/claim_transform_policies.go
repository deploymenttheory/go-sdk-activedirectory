package claims

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// ClaimTransformPolicy reads one policy by identity.
func (c *Service) ClaimTransformPolicy(
	ctx context.Context,
	identity adshared.Identity,
	options ClaimTransformPolicyReadOptions,
) (ClaimTransformPolicyResult, error) {
	var result admodel.ClaimTransformPolicyResult
	if err := admodel.InternalCentralAccessIdentity(
		identity,
		options.ResolveIdentityOptions,
	); err != nil {
		return result, err
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
		resolve := options.ResolveIdentityOptions
		resolve.Partition = configuration
		resolve.Properties = admodel.InternalClaimTransformProperties(resolve.Properties)
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
		if e := admodel.InternalClaimTransformLocation(
			*result.Observation.Object,
			configuration,
		); e != nil {
			return e
		}
		value, decodeErr := admodel.InternalDecodeClaimTransformPolicy(*result.Observation.Object)
		result.Policy = &value
		if options.IncludeProtection && value.GUID != nil {
			protection, protectErr := admodel.InternalReadOUProtection(
				ctx,
				adengine.InternalClientSession(c.engine()),
				root,
				adengine.InternalClientConfig(c.engine()),
				admodel.OrganizationalUnit{
					DistinguishedName: result.Observation.Object.DistinguishedName,
					GUID:              value.GUID,
				},
				configuration,
			)
			result.Protection = protection
			value.ProtectedFromAccidentalDeletion = protection.ProtectedFromAccidentalDeletion
			result.Policy = &value
			decodeErr = errors.Join(decodeErr, protectErr)
		}
		return decodeErr
	})
	return result, err
}

// ClaimTransformPolicies lists policies in the Claims Transformation Policies
// container, restricting any caller filter to that container and class.
func (c *Service) ClaimTransformPolicies(
	ctx context.Context,
	options adshared.SearchOptions,
) (ClaimTransformPoliciesResult, error) {
	var result admodel.ClaimTransformPoliciesResult
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
		container := admodel.InternalClaimTransformParent(configuration)
		if query.Base != "" && !admodel.InternalCentralSameDN(query.Base, container) {
			return admodel.ErrIdentityScope
		}
		query.Base = container
		query.Scope = admodel.ScopeOneLevel
		query.Filter = "(&(objectClass=" + admodel.InternalClaimTransformClass + ")" + query.Filter + ")"
		query.Properties = admodel.InternalClaimTransformProperties(options.Properties)
		result.Observation, e = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			query,
		)
		for _, object := range result.Observation.Objects {
			value, decodeErr := admodel.InternalDecodeClaimTransformPolicy(object)
			result.Policies = append(
				result.Policies,
				admodel.ClaimTransformPolicyResult{
					Policy:      &value,
					Observation: admodel.IdentityResult{Object: &object, Complete: true},
				},
			)
			e = errors.Join(e, decodeErr)
		}
		return e
	})
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
