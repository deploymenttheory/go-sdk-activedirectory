package central_access

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func internalServiceReadCentralAccess(
	c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.CentralAccessReadOptions,
	policy bool,
) (admodel.IdentityResult, admodel.CentralAccessReferencesResult, admodel.OUProtectionResult, error) {
	var observed admodel.IdentityResult
	var references admodel.CentralAccessReferencesResult
	var protection admodel.OUProtectionResult
	if err := admodel.InternalCentralAccessIdentity(
		identity,
		options.ResolveIdentityOptions,
	); err != nil {
		return observed, references, protection, err
	}
	limits, err := admodel.InternalNormalizeCentralAccessLimits(options.References)
	if err != nil {
		return observed, references, protection, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err := admodel.InternalCentralAccessConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			options.Partition,
		)
		if err != nil {
			return err
		}
		resolve := options.ResolveIdentityOptions
		resolve.Partition = configuration
		resolve.Properties = admodel.InternalCentralAccessProperties(resolve.Properties, policy)
		observed, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			resolve,
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalCentralAccessLocation(
			*observed.Object,
			configuration,
			policy,
		); err != nil {
			return err
		}
		attribute := admodel.InternalCentralMemberOf
		if policy {
			attribute = admodel.InternalCentralMembers
		}
		references, err = admodel.InternalReadCentralAccessReferences(
			ctx,
			adengine.InternalClientSession(c.engine()),
			*observed.Object,
			attribute,
			limits,
		)
		if options.IncludeProtection {
			guid, e := admodel.InternalCentralAccessGUID(*observed.Object)
			if e == nil {
				protection, e = admodel.InternalReadOUProtection(
					ctx,
					adengine.InternalClientSession(c.engine()),
					root,
					adengine.InternalClientConfig(c.engine()),
					admodel.OrganizationalUnit{
						DistinguishedName: observed.Object.DistinguishedName,
						GUID:              &guid,
					},
					configuration,
				)
			}
			err = errors.Join(err, e)
		}
		return err
	})
	return observed, references, protection, err
}

func (c *Service) CentralAccessRule(
	ctx context.Context,
	identity adshared.Identity,
	options CentralAccessReadOptions,
) (CentralAccessRuleResult, error) {
	var result admodel.CentralAccessRuleResult
	var err error
	result.Observation, result.Policies, result.Protection, err = internalServiceReadCentralAccess(
		c,
		ctx,
		identity,
		options,
		false,
	)
	if result.Observation.Object != nil {
		value, e := admodel.InternalDecodeCentralAccessRule(*result.Observation.Object)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Rule = &value
		err = errors.Join(err, e)
	}
	return result, err
}

func (c *Service) CentralAccessPolicy(
	ctx context.Context,
	identity adshared.Identity,
	options CentralAccessReadOptions,
) (CentralAccessPolicyResult, error) {
	var result admodel.CentralAccessPolicyResult
	var err error
	result.Observation, result.Members, result.Protection, err = internalServiceReadCentralAccess(c,
		ctx,
		identity,
		options,
		true,
	)
	if result.Observation.Object != nil {
		value, e := admodel.InternalDecodeCentralAccessPolicy(*result.Observation.Object)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Policy = &value
		err = errors.Join(err, e)
	}
	return result, err
}

func internalServiceSearchCentralAccess(c *Service,
	ctx context.Context,
	options admodel.SearchOptions,
	limits admodel.CentralAccessReferenceLimits,
	policy bool,
) (admodel.SearchResult, []admodel.CentralAccessReferencesResult, error) {
	var result admodel.SearchResult
	var references []admodel.CentralAccessReferencesResult
	query, err := admodel.InternalSearchOptionsNormalized(options)
	if err != nil {
		return result, references, err
	}
	limits, err = admodel.InternalNormalizeCentralAccessLimits(limits)
	if err != nil {
		return result, references, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err := admodel.InternalCentralAccessConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			"",
		)
		if err != nil {
			return err
		}
		parent := admodel.InternalCentralAccessParent(configuration, policy)
		if query.Base != "" && !admodel.InternalCentralSameDN(query.Base, parent) {
			return admodel.ErrIdentityScope
		}
		query.Base = parent
		query.Scope = admodel.ScopeOneLevel
		query.Filter = "(&(objectClass=" + admodel.InternalCentralAccessClass(
			policy,
		) + ")" + query.Filter + ")"
		query.Properties = admodel.InternalCentralAccessProperties(options.Properties, policy)
		result, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			query,
		)
		attribute := admodel.InternalCentralMemberOf
		if policy {
			attribute = admodel.InternalCentralMembers
		}
		for _, object := range result.Objects {
			var refs admodel.CentralAccessReferencesResult
			e := admodel.InternalCentralAccessLocation(object, configuration, policy)
			if e == nil {
				refs, e = admodel.InternalReadCentralAccessReferences(
					ctx,
					adengine.InternalClientSession(c.engine()),
					object,
					attribute,
					limits,
				)
			}
			references = append(references, refs)
			err = errors.Join(err, e)
		}
		return err
	})
	if err != nil {
		result.Complete = false
	}
	return result, references, err
}

func (c *Service) CentralAccessRules(
	ctx context.Context,
	options adshared.SearchOptions,
	limits CentralAccessReferenceLimits,
) (CentralAccessRulesResult, error) {
	var result admodel.CentralAccessRulesResult
	observed, references, err := internalServiceSearchCentralAccess(c, ctx, options, limits, false)
	result.Observation = observed
	for i, object := range observed.Objects {
		rule, e := admodel.InternalDecodeCentralAccessRule(object)
		result.Rules = append(
			result.Rules,
			admodel.CentralAccessRuleResult{
				Rule:        &rule,
				Observation: admodel.IdentityResult{Object: &object, Complete: true},
				Policies:    references[i],
			},
		)
		err = errors.Join(err, e)
	}
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}

func (c *Service) CentralAccessPolicies(
	ctx context.Context,
	options adshared.SearchOptions,
	limits CentralAccessReferenceLimits,
) (CentralAccessPoliciesResult, error) {
	var result admodel.CentralAccessPoliciesResult
	observed, references, err := internalServiceSearchCentralAccess(c, ctx, options, limits, true)
	result.Observation = observed
	for i, object := range observed.Objects {
		policy, e := admodel.InternalDecodeCentralAccessPolicy(object)
		result.Policies = append(
			result.Policies,
			admodel.CentralAccessPolicyResult{
				Policy:      &policy,
				Observation: admodel.IdentityResult{Object: &object, Complete: true},
				Members:     references[i],
			},
		)
		err = errors.Join(err, e)
	}
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
