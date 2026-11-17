package central_access

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (c *Service) AddCentralAccessPolicyMembers(
	ctx context.Context,
	request CentralAccessPolicyMembersRequest,
) (CentralAccessPolicyMembersResult, error) {
	return internalServiceChangeCentralAccessMembers(c, ctx, request, false)
}

func (c *Service) RemoveCentralAccessPolicyMembers(
	ctx context.Context,
	request CentralAccessPolicyMembersRequest,
) (CentralAccessPolicyMembersResult, error) {
	return internalServiceChangeCentralAccessMembers(c, ctx, request, true)
}

func internalServiceChangeCentralAccessMembers(c *Service,
	ctx context.Context,
	request admodel.CentralAccessPolicyMembersRequest,
	remove bool,
) (admodel.CentralAccessPolicyMembersResult, error) {
	var result admodel.CentralAccessPolicyMembersResult
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if len(request.Members) == 0 || len(request.Members) > admodel.CentralAccessPolicyMemberLimit {
		return result, admodel.ErrCentralAccessMemberLimit
	}
	for _, identity := range request.Members {
		if err := admodel.InternalCentralAccessIdentity(
			identity,
			admodel.ResolveIdentityOptions{},
		); err != nil {
			return result, err
		}
	}
	ctx, cancel, options, err := InternalServiceCentralAccessMutationContext(
		c,
		ctx,
		request.Options,
	)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalCentralAccessProperties(options.Properties, true),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			configuration, e := admodel.InternalCentralAccessConfiguration(
				root,
				adengine.InternalClientConfig(c.engine()),
				options.Partition,
			)
			if e != nil {
				return e
			}
			if e := admodel.InternalCentralAccessLocation(
				*observed.Object,
				configuration,
				true,
			); e != nil {
				return e
			}
			limits, _ := admodel.InternalNormalizeCentralAccessLimits(
				admodel.CentralAccessReferenceLimits{},
			)
			result.Before, e = admodel.InternalReadCentralAccessReferences(
				ctx,
				session,
				*observed.Object,
				admodel.InternalCentralMembers,
				limits,
			)
			if e != nil {
				return e
			}
			if !remove &&
				len(
					result.Before.References,
				)+len(
					request.Members,
				) > admodel.CentralAccessPolicyMemberLimit {
				return admodel.ErrCentralAccessMemberLimit
			}
			values := make([][]byte, 0, len(request.Members))
			seen := map[string]struct{}{}
			for _, identity := range request.Members {
				input, e := admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					identity,
					admodel.ResolveIdentityOptions{
						Partition:  configuration,
						Properties: admodel.InternalCentralAccessProperties(nil, false),
					},
				)
				result.Inputs = append(
					result.Inputs,
					admodel.CentralAccessMemberInput{Identity: identity, Observation: input},
				)
				if e != nil {
					return e
				}
				if e := admodel.InternalCentralAccessLocation(
					*input.Object,
					configuration,
					false,
				); e != nil {
					return e
				}
				parsed, e := admodel.InternalParseIdentityDN(input.Object.DistinguishedName)
				if e != nil {
					return e
				}
				key := admodel.InternalIdentityDNKey(parsed)
				if _, exists := seen[key]; exists {
					return admodel.ErrCentralAccess
				}
				seen[key] = struct{}{}
				values = append(values, []byte(input.Object.DistinguishedName))
			}
			operation := uint32(0)
			if remove {
				operation = 1
			}
			controls, e := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*mutation.TargetGUID,
				false,
			)
			if e != nil {
				return e
			}
			if e := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteModify,
					InternalDn:        admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
					InternalModifications: []admodel.InternalLdapAttributeModification{
						{
							InternalOperation: operation,
							InternalAttribute: admodel.InternalCentralMembers,
							InternalValues:    values,
						},
					},
					InternalControls: controls,
				},
				false,
				mutation,
			); e != nil {
				return e
			}
			if e := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				admodel.InternalCentralAccessProperties(options.Properties, true),
				false,
			); e != nil {
				return e
			}
			result.After, e = admodel.InternalReadCentralAccessReferences(
				ctx,
				session,
				*mutation.After,
				admodel.InternalCentralMembers,
				limits,
			)
			if e != nil {
				return errors.Join(admodel.ErrObjectReadback, e)
			}
			if len(result.After.References) > admodel.CentralAccessPolicyMemberLimit {
				return admodel.ErrCentralAccessMemberLimit
			}
			if !result.After.AttributeReturned {
				return admodel.ErrObjectVerification
			}
			actual := map[string]struct{}{}
			for _, ref := range result.After.References {
				if err := context.Cause(ctx); err != nil {
					return err
				}
				parsed, e := admodel.InternalParseIdentityDN(ref.DistinguishedName)
				if e != nil {
					return e
				}
				actual[admodel.InternalIdentityDNKey(parsed)] = struct{}{}
			}
			for key := range seen {
				if err := context.Cause(ctx); err != nil {
					return err
				}
				_, present := actual[key]
				if present == remove {
					return admodel.ErrObjectVerification
				}
			}
			mutation.Verified = true
			return nil
		},
	)
	return result, err
}
