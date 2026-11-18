package authentication_policies

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// SetAccountAuthenticationPolicy assigns or clears an account's authentication policy in AD DS.
// Request.Policy and request.Clear are mutually exclusive; this operation does not assign a silo.
//
// Related cmdlet: Set-ADAccountControl.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountcontrol?view=windowsserver2025-ps
func (c *Service) SetAccountAuthenticationPolicy(
	ctx context.Context,
	request SetAccountAuthenticationPolicyRequest,
) (AccountAuthenticationPolicyResult, error) {
	var result admodel.AccountAuthenticationPolicyResult
	if (request.Policy == nil) == !request.Clear {
		return result, admodel.ErrInvalidAuthenticationPolicy
	}
	if request.Policy != nil {
		if err := admodel.InternalValidateIdentityOperation(
			*request.Policy,
			admodel.ResolveIdentityOptions{},
		); err != nil {
			return result, err
		}
	}
	resolve := admodel.InternalAccountControlIdentity(
		request.Identity,
		request.Options.Partition,
		append(
			[]string{"msDS-AssignedAuthNPolicy", "msDS-AssignedAuthNPolicySilo"},
			request.Options.Properties...),
	)
	if err := admodel.InternalValidateIdentityOperation(request.Identity, resolve); err != nil {
		return result, err
	}
	for _, name := range request.Options.Properties {
		if name == "1.1" {
			return result, admodel.ErrInvalidProperty
		}
	}
	var err error
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
			mod := admodel.InternalLdapAttributeModification{
				InternalOperation: 1,
				InternalAttribute: "msDS-AssignedAuthNPolicy",
			}
			if request.Policy != nil {
				result.PolicyObservation, err = admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					*request.Policy,
					admodel.ResolveIdentityOptions{
						Partition:  *root.ConfigurationNamingContext,
						Properties: admodel.InternalAuthenticationPolicyProperties(nil),
					},
				)
				if err != nil {
					return err
				}
				if err := admodel.InternalAuthenticationPolicyScope(
					root,
					*result.PolicyObservation.Object,
				); err != nil {
					return err
				}
				policy, decodeErr := admodel.InternalDecodeAuthenticationPolicy(
					*result.PolicyObservation.Object,
				)
				result.Policy = &policy
				if decodeErr != nil {
					return decodeErr
				}
				mod.InternalOperation, mod.InternalValues = 2, [][]byte{
					[]byte(policy.DistinguishedName),
				}
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
			mods := []admodel.InternalLdapAttributeModification{mod}
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
			properties := admodel.InternalObjectWriteProperties(request.Options, mods)
			properties = append(properties, "msDS-AssignedAuthNPolicySilo")
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
			if !request.Clear {
				value, err := mutation.After.Values(mod.InternalAttribute).Single()
				if err != nil {
					return errors.Join(admodel.ErrObjectVerification, err)
				}
				dn, err := value.Text()
				if err != nil ||
					!admodel.InternalSameAuthenticationDN(dn, string(mod.InternalValues[0])) {
					return errors.Join(admodel.ErrObjectVerification, err)
				}
				mutation.Verified = true
				return nil
			}
			// An omitted link can be hidden by ACLs, so accepted Clear remains
			// explicitly unverified under the same conservative generic semantics.
			return admodel.InternalVerifyObjectWrite(mutation, mods, "")
		},
	)
	return result, err
}
