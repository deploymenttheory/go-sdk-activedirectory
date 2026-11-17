package authentication_silos

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// GrantAuthenticationPolicySiloAccess adds one exact account DN to the silo's
// grant link. It does not assign the account or edit a security descriptor.
func (c *Service) GrantAuthenticationPolicySiloAccess(
	ctx context.Context,
	request AuthenticationPolicySiloAccessRequest,
) (AuthenticationPolicySiloAccessResult, error) {
	return InternalServiceChangeAuthenticationSiloAccess(c, ctx, request, true)
}

// RevokeAuthenticationPolicySiloAccess removes one grant. The account's stored
// silo assignment remains unchanged. Neither method silently retries duplicates.
func (c *Service) RevokeAuthenticationPolicySiloAccess(
	ctx context.Context,
	request AuthenticationPolicySiloAccessRequest,
) (AuthenticationPolicySiloAccessResult, error) {
	return InternalServiceChangeAuthenticationSiloAccess(c, ctx, request, false)
}

func InternalServiceChangeAuthenticationSiloAccess(c *Service,
	ctx context.Context,
	request admodel.AuthenticationPolicySiloAccessRequest,
	grant bool,
) (admodel.AuthenticationPolicySiloAccessResult, error) {
	var result admodel.AuthenticationPolicySiloAccessResult
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if err := admodel.InternalValidateIdentityOperation(
		request.Account,
		admodel.InternalAccountControlIdentity(request.Account, "", nil),
	); err != nil {
		return result, err
	}
	limit, err := admodel.InternalAuthenticationSiloLimit(request.MaxMembers)
	if err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	options, _, err := internalServiceAuthenticationSiloOptions(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		options,
		admodel.ResolveIdentityOptions{Properties: options.Properties},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalAuthenticationSiloScope(root, *observed.Object); err != nil {
				return err
			}
			if err := admodel.InternalAuthenticationPolicyWritePrerequisites(
				ctx,
				session,
				root,
				nil,
			); err != nil {
				return err
			}
			if root.DefaultNamingContext == nil {
				return admodel.ErrIdentityScope
			}
			result.AccountObservation, err = admodel.InternalResolveIdentitySession(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				request.Account,
				admodel.InternalAccountControlIdentity(
					request.Account,
					*root.DefaultNamingContext,
					nil,
				),
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalAccountControlClass(
				*result.AccountObservation.Object,
				admodel.DirectoryADDS,
			); err != nil {
				return err
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
			operation := uint32(1)
			if grant {
				operation = 0
			}
			accountDN := result.AccountObservation.Object.DistinguishedName
			mod := admodel.InternalLdapAttributeModification{
				InternalOperation: operation,
				InternalAttribute: admodel.InternalSiloMembersAttribute,
				InternalValues:    [][]byte{[]byte(accountDN)},
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation:     admodel.InternalLdapWriteModify,
					InternalDn:            admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
					InternalModifications: []admodel.InternalLdapAttributeModification{mod},
					InternalControls:      controls,
				},
				false,
				mutation,
			); err != nil {
				return err
			}
			// Do not request a possibly ranged link through the public identity reader.
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				options.Properties,
				false,
			); err != nil {
				return err
			}
			result.Members, err = admodel.InternalReadAuthenticationSiloLinks(
				ctx,
				session,
				*mutation.After,
				admodel.InternalSiloMembersAttribute,
				limit,
			)
			if err != nil {
				return errors.Join(admodel.ErrObjectVerification, err)
			}
			present, err := admodel.InternalAuthenticationSiloContains(
				ctx,
				result.Members,
				accountDN,
			)
			if err != nil {
				return errors.Join(admodel.ErrObjectVerification, err)
			}
			if present != grant || (!grant && !result.Members.AttributeReturned) {
				return admodel.ErrObjectVerification
			}
			mutation.Verified = true
			return nil
		},
	)
	return result, err
}

func (c *Service) SetAccountAuthenticationPolicySilo(
	ctx context.Context,
	request SetAccountAuthenticationPolicySiloRequest,
) (AccountAuthenticationPolicySiloResult, error) {
	var result admodel.AccountAuthenticationPolicySiloResult
	if (request.Silo == nil && !request.ClearSilo && request.Policy == nil && !request.ClearPolicy) ||
		(request.Silo != nil && request.ClearSilo) ||
		(request.Policy != nil && request.ClearPolicy) ||
		(request.RequireGranted && request.Silo == nil) {
		return result, admodel.ErrInvalidAuthenticationSilo
	}
	for _, identity := range []*admodel.Identity{request.Silo, request.Policy} {
		if identity != nil {
			if err := admodel.InternalValidateIdentityOperation(
				*identity,
				admodel.ResolveIdentityOptions{},
			); err != nil {
				return result, err
			}
		}
	}
	limit, err := admodel.InternalAuthenticationSiloLimit(request.MaxMembers)
	if err != nil {
		return result, err
	}
	resolve := admodel.InternalAccountControlIdentity(
		request.Identity,
		request.Options.Partition,
		append(
			[]string{"msDS-AssignedAuthNPolicySilo", "msDS-AssignedAuthNPolicy"},
			request.Options.Properties...),
	)
	if err := admodel.InternalValidateIdentityOperation(request.Identity, resolve); err != nil {
		return result, err
	}
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		resolve,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalAuthenticationPolicyWritePrerequisites(
				ctx,
				session,
				root,
				nil,
			); err != nil {
				return err
			}
			if root.DefaultNamingContext == nil ||
				!admodel.InternalSameAuthenticationDN(
					mutation.Partition,
					*root.DefaultNamingContext,
				) {
				return admodel.ErrIdentityScope
			}
			if err := admodel.InternalAccountControlClass(
				*observed.Object,
				admodel.DirectoryADDS,
			); err != nil {
				return err
			}
			var mods []admodel.InternalLdapAttributeModification
			for _, link := range []struct {
				InternalAttribute   string
				InternalIdentity    *admodel.Identity
				InternalClear       bool
				InternalSilo        bool
				InternalObservation *admodel.IdentityResult
			}{
				{"msDS-AssignedAuthNPolicySilo", request.Silo, request.ClearSilo, true, &result.SiloObservation},
				{"msDS-AssignedAuthNPolicy", request.Policy, request.ClearPolicy, false, &result.PolicyObservation},
			} {
				if link.InternalIdentity == nil {
					if link.InternalClear {
						mods = append(
							mods,
							admodel.InternalLdapAttributeModification{
								InternalOperation: 1,
								InternalAttribute: link.InternalAttribute,
							},
						)
					}
					continue
				}
				properties := admodel.InternalAuthenticationPolicyProperties(nil)
				if link.InternalSilo {
					properties = admodel.InternalAuthenticationSiloProperties(nil)
				}
				*link.InternalObservation, err = admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					*link.InternalIdentity,
					admodel.ResolveIdentityOptions{
						Partition:  *root.ConfigurationNamingContext,
						Properties: properties,
					},
				)
				if err != nil {
					return err
				}
				if link.InternalSilo {
					if err := admodel.InternalAuthenticationSiloScope(
						root,
						*link.InternalObservation.Object,
					); err != nil {
						return err
					}
					if request.RequireGranted {
						result.GrantObservation, err = admodel.InternalReadAuthenticationSiloLinks(
							ctx,
							session,
							*link.InternalObservation.Object,
							admodel.InternalSiloMembersAttribute,
							limit,
						)
						if err != nil {
							return err
						}
						granted, err := admodel.InternalAuthenticationSiloContains(
							ctx,
							result.GrantObservation,
							mutation.TargetDN,
						)
						if err != nil {
							return err
						}
						if !granted {
							return admodel.ErrAuthenticationSiloGrant
						}
					}
				} else if err := admodel.InternalAuthenticationPolicyScope(root, *link.InternalObservation.Object); err != nil {
					return err
				}
				mods = append(
					mods,
					admodel.InternalLdapAttributeModification{
						InternalOperation: 2,
						InternalAttribute: link.InternalAttribute,
						InternalValues: [][]byte{
							[]byte(link.InternalObservation.Object.DistinguishedName),
						},
					},
				)
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
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
			properties := append(
				admodel.InternalObjectWriteProperties(request.Options, mods),
				"msDS-AssignedAuthNPolicySilo",
				"msDS-AssignedAuthNPolicy",
			)
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				properties,
				false,
			); err != nil {
				return err
			}
			for _, mod := range mods {
				if len(mod.InternalValues) == 0 {
					return admodel.ErrObjectVerification
				} // omission is not proof of a cleared link
				value, err := mutation.After.Values(mod.InternalAttribute).Single()
				if err != nil ||
					!admodel.InternalSameAuthenticationDN(
						string(value.Bytes()),
						string(mod.InternalValues[0]),
					) {
					return errors.Join(admodel.ErrObjectVerification, err)
				}
			}
			mutation.Verified = true
			return nil
		},
	)
	return result, err
}
