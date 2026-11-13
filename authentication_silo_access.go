package activedirectory

import (
	"context"
	"errors"
)

type AuthenticationPolicySiloAccessRequest struct {
	Identity, Account Identity
	Options           ObjectMutationOptions
	MaxMembers        int
}

type AuthenticationPolicySiloAccessResult struct {
	Mutation           ObjectMutationResult
	AccountObservation IdentityResult
	Members            AuthenticationSiloLinks
}

// GrantAuthenticationPolicySiloAccess adds one exact account DN to the silo's
// grant link. It does not assign the account or edit a security descriptor.
func (c *Client) GrantAuthenticationPolicySiloAccess(ctx context.Context, request AuthenticationPolicySiloAccessRequest) (AuthenticationPolicySiloAccessResult, error) {
	return c.changeAuthenticationSiloAccess(ctx, request, true)
}

// RevokeAuthenticationPolicySiloAccess removes one grant. The account's stored
// silo assignment remains unchanged. Neither method silently retries duplicates.
func (c *Client) RevokeAuthenticationPolicySiloAccess(ctx context.Context, request AuthenticationPolicySiloAccessRequest) (AuthenticationPolicySiloAccessResult, error) {
	return c.changeAuthenticationSiloAccess(ctx, request, false)
}

func (c *Client) changeAuthenticationSiloAccess(ctx context.Context, request AuthenticationPolicySiloAccessRequest, grant bool) (AuthenticationPolicySiloAccessResult, error) {
	var result AuthenticationPolicySiloAccessResult
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if err := validateIdentityOperation(request.Account, accountControlIdentity(request.Account, "", nil)); err != nil {
		return result, err
	}
	limit, err := authenticationSiloLimit(request.MaxMembers)
	if err != nil {
		return result, err
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	options, _, err := c.authenticationSiloOptions(ctx, request.Options)
	if err != nil {
		return result, err
	}
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: options.Properties}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := authenticationSiloScope(root, *observed.Object); err != nil {
			return err
		}
		if err := authenticationPolicyWritePrerequisites(ctx, session, root, nil); err != nil {
			return err
		}
		if root.DefaultNamingContext == nil {
			return ErrIdentityScope
		}
		result.AccountObservation, err = resolveIdentitySession(ctx, session, c.config, root, request.Account, accountControlIdentity(request.Account, *root.DefaultNamingContext, nil))
		if err != nil {
			return err
		}
		if err := accountControlClass(*result.AccountObservation.Object, DirectoryADDS); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		operation := uint32(1)
		if grant {
			operation = 0
		}
		accountDN := result.AccountObservation.Object.DistinguishedName
		mod := ldapAttributeModification{operation: operation, attribute: siloMembersAttribute, values: [][]byte{[]byte(accountDN)}}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: []ldapAttributeModification{mod}, controls: controls}, false, mutation); err != nil {
			return err
		}
		// Do not request a possibly ranged link through the public identity reader.
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, options.Properties, false); err != nil {
			return err
		}
		result.Members, err = readAuthenticationSiloLinks(ctx, session, *mutation.After, siloMembersAttribute, limit)
		if err != nil {
			return errors.Join(ErrObjectVerification, err)
		}
		present, err := authenticationSiloContains(ctx, result.Members, accountDN)
		if err != nil {
			return errors.Join(ErrObjectVerification, err)
		}
		if present != grant || (!grant && !result.Members.AttributeReturned) {
			return ErrObjectVerification
		}
		mutation.Verified = true
		return nil
	})
	return result, err
}

// The two account links are independently omitted, assigned, or explicitly
// cleared. A combined change is one atomic LDAP Modify on that account.
type SetAccountAuthenticationPolicySiloRequest struct {
	Identity               Identity
	Silo, Policy           *Identity
	ClearSilo, ClearPolicy bool
	// RequireGranted is an optional positive-observation precondition. The
	// default permits staging assignment before grant, as the module does.
	// This cross-object read is not an atomic server assertion on the silo.
	RequireGranted bool
	MaxMembers     int
	Options        ObjectMutationOptions
}

type AccountAuthenticationPolicySiloResult struct {
	Mutation                           ObjectMutationResult
	SiloObservation, PolicyObservation IdentityResult
	GrantObservation                   AuthenticationSiloLinks
}

func (c *Client) SetAccountAuthenticationPolicySilo(ctx context.Context, request SetAccountAuthenticationPolicySiloRequest) (AccountAuthenticationPolicySiloResult, error) {
	var result AccountAuthenticationPolicySiloResult
	if (request.Silo == nil && !request.ClearSilo && request.Policy == nil && !request.ClearPolicy) || (request.Silo != nil && request.ClearSilo) || (request.Policy != nil && request.ClearPolicy) || (request.RequireGranted && request.Silo == nil) {
		return result, ErrInvalidAuthenticationSilo
	}
	for _, identity := range []*Identity{request.Silo, request.Policy} {
		if identity != nil {
			if err := validateIdentityOperation(*identity, ResolveIdentityOptions{}); err != nil {
				return result, err
			}
		}
	}
	limit, err := authenticationSiloLimit(request.MaxMembers)
	if err != nil {
		return result, err
	}
	resolve := accountControlIdentity(request.Identity, request.Options.Partition, append([]string{"msDS-AssignedAuthNPolicySilo", "msDS-AssignedAuthNPolicy"}, request.Options.Properties...))
	if err := validateIdentityOperation(request.Identity, resolve); err != nil {
		return result, err
	}
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
		var mods []ldapAttributeModification
		for _, link := range []struct {
			attribute   string
			identity    *Identity
			clear       bool
			silo        bool
			observation *IdentityResult
		}{
			{"msDS-AssignedAuthNPolicySilo", request.Silo, request.ClearSilo, true, &result.SiloObservation},
			{"msDS-AssignedAuthNPolicy", request.Policy, request.ClearPolicy, false, &result.PolicyObservation},
		} {
			if link.identity == nil {
				if link.clear {
					mods = append(mods, ldapAttributeModification{operation: 1, attribute: link.attribute})
				}
				continue
			}
			properties := authenticationPolicyProperties(nil)
			if link.silo {
				properties = authenticationSiloProperties(nil)
			}
			*link.observation, err = resolveIdentitySession(ctx, session, c.config, root, *link.identity, ResolveIdentityOptions{Partition: *root.ConfigurationNamingContext, Properties: properties})
			if err != nil {
				return err
			}
			if link.silo {
				if err := authenticationSiloScope(root, *link.observation.Object); err != nil {
					return err
				}
				if request.RequireGranted {
					result.GrantObservation, err = readAuthenticationSiloLinks(ctx, session, *link.observation.Object, siloMembersAttribute, limit)
					if err != nil {
						return err
					}
					granted, err := authenticationSiloContains(ctx, result.GrantObservation, mutation.TargetDN)
					if err != nil {
						return err
					}
					if !granted {
						return ErrAuthenticationSiloGrant
					}
				}
			} else if err := authenticationPolicyScope(root, *link.observation.Object); err != nil {
				return err
			}
			mods = append(mods, ldapAttributeModification{operation: 2, attribute: link.attribute, values: [][]byte{[]byte(link.observation.Object.DistinguishedName)}})
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); err != nil {
			return err
		}
		properties := append(objectWriteProperties(request.Options, mods), "msDS-AssignedAuthNPolicySilo", "msDS-AssignedAuthNPolicy")
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, properties, false); err != nil {
			return err
		}
		for _, mod := range mods {
			if len(mod.values) == 0 {
				return ErrObjectVerification
			} // omission is not proof of a cleared link
			value, err := mutation.After.Values(mod.attribute).Single()
			if err != nil || !sameAuthenticationDN(string(value.Bytes()), string(mod.values[0])) {
				return errors.Join(ErrObjectVerification, err)
			}
		}
		mutation.Verified = true
		return nil
	})
	return result, err
}
