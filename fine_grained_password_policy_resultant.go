package activedirectory

import (
	"context"
	"errors"
)

// UserResultantPasswordPolicyResult reports the server's constructed
// msDS-ResultantPSO value. NotReturned is an observation: it does not prove the
// default domain policy applies when ACLs hide an attribute. No local policy
// precedence or group expansion substitutes for the constructed value.
type UserResultantPasswordPolicyResult struct {
	User                  IdentityResult
	Policy                FineGrainedPasswordPolicyResult
	PolicyDN              *string
	AttributeState        AttributeState
	NotReturned, Complete bool
}

func (c *Client) UserResultantPasswordPolicy(ctx context.Context, identity Identity, options ResolveIdentityOptions) (UserResultantPasswordPolicyResult, error) {
	var result UserResultantPasswordPolicyResult
	if options.Target > IdentityTargetAccount {
		return result, ErrUnsupportedIdentity
	}
	resolve := accountControlIdentity(identity, options.Partition, []string{"msDS-ResultantPSO"})
	if err := validateIdentityOperation(identity, resolve); err != nil {
		return result, err
	}
	// Properties select the resultant PSO, not a second uncontrolled user read.
	if err := (SearchOptions{Properties: options.Properties}).Validate(); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		domain, err := fineGrainedPolicyDomain(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		resolve.Partition = domain
		result.User, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if err != nil {
			return err
		}
		if groupClass(*result.User.Object) == nil {
			return ErrFineGrainedPolicySubject
		}
		if err := fineGrainedSubjectClass(*result.User.Object); err != nil {
			return err
		}
		values := result.User.Object.Values("msDS-ResultantPSO")
		result.AttributeState = values.State
		if values.State == AttributePartial {
			return ErrIncompleteResult
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
		policyIdentity, err := IdentityByDN(dn)
		if err != nil {
			return errors.Join(ErrInvalidResult, err)
		}
		result.Policy.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, policyIdentity, ResolveIdentityOptions{Partition: domain, Properties: fineGrainedPolicyProperties(options.Properties)})
		if err != nil {
			return err
		}
		if err := fineGrainedPolicyLocation(*result.Policy.Observation.Object, domain); err != nil {
			return err
		}
		policy, err := decodeFineGrainedPolicy(*result.Policy.Observation.Object)
		result.Policy.Policy = &policy
		result.Complete = err == nil
		return err
	})
	return result, err
}
