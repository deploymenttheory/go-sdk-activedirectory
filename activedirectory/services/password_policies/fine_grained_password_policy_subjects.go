package password_policies

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func (c *Service) FineGrainedPasswordPolicySubjects(
	ctx context.Context,
	identity adshared.Identity,
	options FineGrainedPolicySubjectsOptions,
) (FineGrainedPolicySubjectsResult, error) {
	var result admodel.FineGrainedPolicySubjectsResult
	options, err := admodel.InternalNormalizeFineGrainedSubjectOptions(options)
	if err != nil {
		return result, err
	}
	resolve := admodel.ResolveIdentityOptions{
		Partition:  options.Partition,
		Properties: []string{"objectClass", "objectGUID", "uSNChanged"},
	}
	if err := admodel.InternalFineGrainedMutationOptions(
		identity,
		admodel.ObjectMutationOptions{Partition: options.Partition, Properties: options.Properties},
	); err != nil {
		return result, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
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
		result.Policy, err = admodel.InternalResolveIdentitySession(
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
		if err := admodel.InternalFineGrainedPolicyLocation(
			*result.Policy.Object,
			domain,
		); err != nil {
			return err
		}
		return admodel.InternalCollectFineGrainedSubjects(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			options,
			&result,
		)
	})
	if err != nil {
		result.Complete = false
	}
	return result, err
}

func (c *Service) AddFineGrainedPasswordPolicySubjects(
	ctx context.Context,
	request FineGrainedPolicySubjectsRequest,
) (FineGrainedPolicySubjectsMutationResult, error) {
	return internalServiceChangeFineGrainedPolicySubjects(c, ctx, request, false)
}

func (c *Service) RemoveFineGrainedPasswordPolicySubjects(
	ctx context.Context,
	request FineGrainedPolicySubjectsRequest,
) (FineGrainedPolicySubjectsMutationResult, error) {
	return internalServiceChangeFineGrainedPolicySubjects(c, ctx, request, true)
}

// Resolve every supplied identity before a single strict linked-value Modify.
// GUID references retain identity across renames; duplicates are rejected.
func internalServiceChangeFineGrainedPolicySubjects(c *Service,
	ctx context.Context,
	request admodel.FineGrainedPolicySubjectsRequest,
	remove bool,
) (admodel.FineGrainedPolicySubjectsMutationResult, error) {
	var result admodel.FineGrainedPolicySubjectsMutationResult
	if err := admodel.InternalFineGrainedMutationOptions(
		request.Identity,
		request.Options,
	); err != nil {
		return result, err
	}
	if len(request.Subjects) == 0 || len(request.Subjects) > 1000 {
		return result, admodel.ErrFineGrainedPolicyLimit
	}
	for _, identity := range request.Subjects {
		if err := admodel.InternalValidateIdentityOperation(
			identity,
			admodel.InternalAccountControlIdentity(identity, request.Options.Partition, nil),
		); err != nil {
			return result, err
		}
		result.Subjects = append(
			result.Subjects,
			admodel.FineGrainedPolicySubjectInput{Identity: identity},
		)
	}
	var err error
	result.Mutation, err = internalServiceMutateFineGrainedPolicy(
		c,
		ctx,
		request.Identity,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, _ admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
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
			seen := make(map[admodel.GUID]bool)
			values := make([][]byte, 0, len(request.Subjects))
			for i, identity := range request.Subjects {
				resolved, err := admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					identity,
					admodel.InternalAccountControlIdentity(
						identity,
						mutation.Partition,
						[]string{"groupType"},
					),
				)
				result.Subjects[i].Observation = resolved
				if err != nil {
					return err
				}
				if err := admodel.InternalFineGrainedSubjectClass(*resolved.Object); err != nil {
					return err
				}
				value, err := resolved.Object.Values("objectGUID").Single()
				if err != nil {
					return err
				}
				guid, err := value.GUID()
				if err != nil {
					return err
				}
				if seen[guid] {
					return admodel.ErrInvalidFineGrainedPolicy
				}
				seen[guid] = true
				reference := admodel.InternalObjectGUIDTarget(guid)
				result.Subjects[i].Reference = reference
				values = append(values, []byte(reference))
			}
			operation := uint32(0)
			if remove {
				operation = 1
			}
			write := admodel.InternalLdapWriteRequest{
				InternalOperation: admodel.InternalLdapWriteModify,
				InternalDn:        admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
				InternalModifications: []admodel.InternalLdapAttributeModification{
					{
						InternalOperation: operation,
						InternalAttribute: "msDS-PSOAppliesTo",
						InternalValues:    values,
					},
				},
				InternalControls: controls,
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				write,
				false,
				mutation,
			); err != nil {
				return err
			}
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				admodel.InternalFineGrainedPolicyProperties(
					append(append([]string{}, request.Options.Properties...), "uSNChanged"),
				),
				false,
			); err != nil {
				return err
			}
			result.After.Policy = admodel.IdentityResult{
				Object:    mutation.After,
				Partition: mutation.Partition,
				Complete:  true,
			}
			limits, _ := admodel.InternalNormalizeFineGrainedSubjectOptions(
				admodel.FineGrainedPolicySubjectsOptions{Partition: mutation.Partition},
			)
			if err := admodel.InternalCollectFineGrainedSubjects(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				limits,
				&result.After,
			); err != nil {
				return errors.Join(admodel.ErrObjectReadback, err)
			}
			if !result.After.AttributeReturned {
				return admodel.ErrObjectVerification
			}
			found := make(map[admodel.GUID]bool)
			for _, subject := range result.After.Subjects {
				value, e := subject.Observation.Object.Values("objectGUID").Single()
				if e != nil {
					return e
				}
				guid, e := value.GUID()
				if e != nil {
					return e
				}
				found[guid] = true
			}
			for guid := range seen {
				if found[guid] == remove {
					return admodel.ErrObjectVerification
				}
			}
			mutation.Verified = true
			return nil
		},
	)
	return result, err
}
