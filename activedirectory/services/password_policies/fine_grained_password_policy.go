package password_policies

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// FineGrainedPasswordPolicy resolves a PSO by explicit DN/GUID. Policy names
// are not guessed as SAM identities; search supports a typed name filter.
//
// Related cmdlet: Get-ADFineGrainedPasswordPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adfinegrainedpasswordpolicy?view=windowsserver2025-ps
func (c *Service) FineGrainedPasswordPolicy(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (FineGrainedPasswordPolicyResult, error) {
	var result admodel.FineGrainedPasswordPolicyResult
	if options.Target != admodel.IdentityTargetObject ||
		(identity.Form() != admodel.IdentityFormDN && identity.Form() != admodel.IdentityFormGUID) {
		return result, admodel.ErrUnsupportedIdentity
	}
	options.Properties = admodel.InternalFineGrainedPolicyProperties(options.Properties)
	if err := admodel.InternalValidateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		domain, err := admodel.InternalFineGrainedPolicyDomain(
			root,
			adengine.InternalClientConfig(c.engine()),
			options.Partition,
		)
		if err != nil {
			return err
		}
		options.Partition = domain
		result.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalFineGrainedPolicyLocation(
			*result.Observation.Object,
			domain,
		); err != nil {
			return err
		}
		policy, err := admodel.InternalDecodeFineGrainedPolicy(*result.Observation.Object)
		result.Policy = &policy
		return err
	})
	return result, err
}

// FineGrainedPasswordPolicies searches only the domain's Password Settings
// Container. Scope is fixed to its direct children; paging/limits and raw or
// typed filters use the existing SearchOptions contract.
//
// Related cmdlet: Get-ADFineGrainedPasswordPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adfinegrainedpasswordpolicy?view=windowsserver2025-ps
func (c *Service) FineGrainedPasswordPolicies(
	ctx context.Context,
	options adshared.SearchOptions,
) (FineGrainedPasswordPoliciesResult, error) {
	var result admodel.FineGrainedPasswordPoliciesResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	options.Properties = admodel.InternalFineGrainedPolicyProperties(options.Properties)
	if !admodel.InternalFilterUnset(options.TypedFilter) {
		options.TypedFilter = admodel.FilterAnd(
			admodel.FilterEqual("objectClass", admodel.FilterText("msDS-PasswordSettings")),
			options.TypedFilter,
		)
	} else if options.Filter == "" {
		options.Filter = "(objectClass=msDS-PasswordSettings)"
	} else {
		options.Filter = "(&(objectClass=msDS-PasswordSettings)" + options.Filter + ")"
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		domain, err := admodel.InternalFineGrainedPolicyDomain(
			root,
			adengine.InternalClientConfig(c.engine()),
			"",
		)
		if err != nil {
			return err
		}
		container := admodel.InternalFineGrainedPolicyContainer(domain)
		if options.Base != "" {
			actual, e := admodel.InternalParseIdentityDN(options.Base)
			want, _ := admodel.InternalParseIdentityDN(container)
			if e != nil || !admodel.InternalSameIdentityDN(actual, want) {
				return admodel.ErrFineGrainedPolicyTarget
			}
		}
		options.Base, options.Scope = container, admodel.ScopeOneLevel
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			options,
		)
		for _, object := range result.Observation.Objects {
			policy, decodeErr := admodel.InternalDecodeFineGrainedPolicy(object)
			result.Policies = append(result.Policies, policy)
			err = errors.Join(
				err,
				decodeErr,
				admodel.InternalFineGrainedPolicyLocation(object, domain),
			)
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}
