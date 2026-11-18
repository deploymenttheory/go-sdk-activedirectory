package password_policies

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// UserResultantPasswordPolicy reads a user's server-computed resultant fine-grained password policy.
// Options.Properties select policy attributes; NotReturned records an omitted resultant-policy value
// without inventing a default policy.
//
// Related cmdlet: Get-ADUserResultantPasswordPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduserresultantpasswordpolicy?view=windowsserver2025-ps
func (c *Service) UserResultantPasswordPolicy(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (UserResultantPasswordPolicyResult, error) {
	var result admodel.UserResultantPasswordPolicyResult
	if options.Target > admodel.IdentityTargetAccount {
		return result, admodel.ErrUnsupportedIdentity
	}
	resolve := admodel.InternalAccountControlIdentity(
		identity,
		options.Partition,
		[]string{"msDS-ResultantPSO"},
	)
	if err := admodel.InternalValidateIdentityOperation(identity, resolve); err != nil {
		return result, err
	}
	// Properties select the resultant PSO, not a second uncontrolled user read.
	if err := (admodel.SearchOptions{Properties: options.Properties}).Validate(); err != nil {
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
		resolve.Partition = domain
		result.User, err = admodel.InternalResolveIdentitySession(
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
		if admodel.InternalGroupClass(*result.User.Object) == nil {
			return admodel.ErrFineGrainedPolicySubject
		}
		if err := admodel.InternalFineGrainedSubjectClass(*result.User.Object); err != nil {
			return err
		}
		values := result.User.Object.Values("msDS-ResultantPSO")
		result.AttributeState = values.State
		if values.State == admodel.AttributePartial {
			return admodel.ErrIncompleteResult
		}
		if len(values.Values) == 0 {
			result.NotReturned, result.Complete = true, true
			return nil
		}
		value, err := values.Single()
		if err != nil {
			return err
		}
		dn, err := value.Text()
		if err != nil {
			return err
		}
		result.PolicyDN = &dn
		policyIdentity, err := admodel.IdentityByDN(dn)
		if err != nil {
			return errors.Join(admodel.ErrInvalidResult, err)
		}
		result.Policy.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			policyIdentity,
			admodel.ResolveIdentityOptions{
				Partition:  domain,
				Properties: admodel.InternalFineGrainedPolicyProperties(options.Properties),
			},
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalFineGrainedPolicyLocation(
			*result.Policy.Observation.Object,
			domain,
		); err != nil {
			return err
		}
		policy, err := admodel.InternalDecodeFineGrainedPolicy(*result.Policy.Observation.Object)
		result.Policy.Policy = &policy
		result.Complete = err == nil
		return err
	})
	return result, err
}
