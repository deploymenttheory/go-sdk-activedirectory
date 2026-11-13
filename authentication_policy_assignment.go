package activedirectory

import (
	"context"
	"errors"
)

// SetAccountAuthenticationPolicyRequest assigns Policy or explicitly clears
// the direct policy link. Exactly one of Policy/Clear must be supplied. Account
// identities use the existing DN/GUID/SID/SAM rules; Policy accepts DN/GUID.
// Silo membership/assignment is not changed and may override this direct link
// during authentication. This result never claims an effective resultant policy.
type SetAccountAuthenticationPolicyRequest struct {
	Identity Identity
	Policy   *Identity
	Clear    bool
	Options  ObjectMutationOptions
}

type AccountAuthenticationPolicyResult struct {
	Mutation          ObjectMutationResult
	Policy            *AuthenticationPolicy
	PolicyObservation IdentityResult
}

func (c *Client) SetAccountAuthenticationPolicy(ctx context.Context, request SetAccountAuthenticationPolicyRequest) (AccountAuthenticationPolicyResult, error) {
	var result AccountAuthenticationPolicyResult
	if (request.Policy == nil) == !request.Clear {
		return result, ErrInvalidAuthenticationPolicy
	}
	if request.Policy != nil {
		if err := validateIdentityOperation(*request.Policy, ResolveIdentityOptions{}); err != nil {
			return result, err
		}
	}
	resolve := accountControlIdentity(request.Identity, request.Options.Partition, append([]string{"msDS-AssignedAuthNPolicy", "msDS-AssignedAuthNPolicySilo"}, request.Options.Properties...))
	if err := validateIdentityOperation(request.Identity, resolve); err != nil {
		return result, err
	}
	for _, name := range request.Options.Properties {
		if name == "1.1" {
			return result, ErrInvalidProperty
		}
	}
	var err error
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, request.Options, resolve, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := authenticationPolicyWritePrerequisites(ctx, session, root, nil); err != nil {
			return err
		}
		if root.DefaultNamingContext == nil || !sameAuthenticationDN(mutation.Partition, *root.DefaultNamingContext) {
			return ErrIdentityScope
		}
		if err := accountControlClass(*observed.Object, DirectoryADDS); err != nil {
			return err
		}
		mod := ldapAttributeModification{operation: 1, attribute: "msDS-AssignedAuthNPolicy"}
		if request.Policy != nil {
			result.PolicyObservation, err = resolveIdentitySession(ctx, session, c.config, root, *request.Policy, ResolveIdentityOptions{Partition: *root.ConfigurationNamingContext, Properties: authenticationPolicyProperties(nil)})
			if err != nil {
				return err
			}
			if err := authenticationPolicyScope(root, *result.PolicyObservation.Object); err != nil {
				return err
			}
			policy, decodeErr := decodeAuthenticationPolicy(*result.PolicyObservation.Object)
			result.Policy = &policy
			if decodeErr != nil {
				return decodeErr
			}
			mod.operation, mod.values = 2, [][]byte{[]byte(policy.DistinguishedName)}
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		mods := []ldapAttributeModification{mod}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); err != nil {
			return err
		}
		properties := objectWriteProperties(request.Options, mods)
		properties = append(properties, "msDS-AssignedAuthNPolicySilo")
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, properties, false); err != nil {
			return err
		}
		if !request.Clear {
			value, err := mutation.After.Values(mod.attribute).Single()
			if err != nil {
				return errors.Join(ErrObjectVerification, err)
			}
			dn, err := value.Text()
			if err != nil || !sameAuthenticationDN(dn, string(mod.values[0])) {
				return errors.Join(ErrObjectVerification, err)
			}
			mutation.Verified = true
			return nil
		}
		// An omitted link can be hidden by ACLs, so accepted Clear remains
		// explicitly unverified under the same conservative generic semantics.
		return verifyObjectWrite(mutation, mods, "")
	})
	return result, err
}
