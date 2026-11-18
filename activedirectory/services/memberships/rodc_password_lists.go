package memberships

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// RODCPasswordReplicationPolicy reads the selected read-only domain controller's allowed or denied
// password-replication list. Options bound linked-value reads and principal resolution; partial
// observations remain in the result.
//
// Related cmdlet: Get-ADDomainControllerPasswordReplicationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomaincontrollerpasswordreplicationpolicy?view=windowsserver2025-ps
func (c *Service) RODCPasswordReplicationPolicy(
	ctx context.Context,
	controller adshared.Identity,
	list RODCPasswordReplicationList,
	options RODCPasswordReplicationOptions,
) (RODCPasswordReplicationResult, error) {
	attribute, err := admodel.InternalRODCPasswordReplicationListAttribute(list)
	if err != nil {
		return admodel.RODCPasswordReplicationResult{}, err
	}
	return internalServiceRodcPasswordLinks(c, ctx, controller, attribute, false, options)
}

// RODCPasswordReplicationPolicyUsage reads accounts whose passwords were revealed to, or that
// authenticated through, the selected RODC. Kind selects the usage list; options bound linked-value
// reads and retain incomplete observations.
//
// Related cmdlet: Get-ADDomainControllerPasswordReplicationPolicyUsage.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomaincontrollerpasswordreplicationpolicyusage?view=windowsserver2025-ps
func (c *Service) RODCPasswordReplicationPolicyUsage(
	ctx context.Context,
	controller adshared.Identity,
	kind RODCPasswordReplicationUsageKind,
	options RODCPasswordReplicationOptions,
) (RODCPasswordReplicationResult, error) {
	switch kind {
	case admodel.RODCPasswordRevealed:
		return internalServiceRodcPasswordLinks(
			c,
			ctx,
			controller,
			"msDS-RevealedList",
			true,
			options,
		)
	case admodel.RODCPasswordAuthenticated:
		return internalServiceRodcPasswordLinks(c,
			ctx,
			controller,
			"msDS-AuthenticatedToAccountlist",
			false,
			options,
		)
	default:
		return admodel.RODCPasswordReplicationResult{}, admodel.ErrInvalidRODCPasswordPolicy
	}
}

// internalServiceRodcPasswordLinks reads a bounded RODC policy or usage attribute and resolves its
// principal references.
func internalServiceRodcPasswordLinks(c *Service,
	ctx context.Context,
	controller admodel.Identity,
	attribute string,
	revealed bool,
	options admodel.RODCPasswordReplicationOptions,
) (result admodel.RODCPasswordReplicationResult, err error) {
	if options.Limits.MaxGroups != 0 || options.Limits.MaxDepth != 0 {
		return result, admodel.ErrInvalidRODCPasswordPolicy
	}
	limits, err := admodel.InternalNormalizeMembershipLimits(options.Limits)
	if err != nil {
		return result, err
	}
	if err = admodel.InternalValidateIdentityOperation(
		controller,
		admodel.InternalMembershipResolveOptions(controller, options.Partition, options.Properties),
	); err != nil {
		return result, err
	}
	result.Attribute = attribute
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, readErr := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if readErr != nil {
			return readErr
		}
		result.Controller, readErr = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			controller,
			admodel.InternalMembershipResolveOptions(
				controller,
				options.Partition,
				admodel.InternalRodcPasswordProperties(nil),
			),
		)
		if readErr != nil {
			return readErr
		}
		if err := adengine.InternalRodcPasswordServer(
			ctx,
			c.engine(),
			adengine.InternalClientSession(c.engine()),
			root,
			result.Controller.Partition,
			false,
		); err != nil {
			return err
		}
		if err := admodel.InternalValidateRODCPasswordTarget(
			*result.Controller.Object,
		); err != nil {
			return err
		}
		budget := admodel.InternalMembershipBudget{InternalLimits: limits}
		if err := budget.InternalObject(*result.Controller.Object); err != nil {
			return err
		}
		rangeErr := admodel.InternalCollectRODCPasswordLinks(
			ctx,
			adengine.InternalClientSession(c.engine()),
			attribute,
			revealed,
			*result.Controller.Object,
			&budget,
			&result,
		)
		if rangeErr != nil {
			return rangeErr
		}
		seen := map[admodel.GUID]bool{}
		var failures []error
		for i := range result.Entries {
			entry := &result.Entries[i]
			if budget.InternalObjects >= limits.MaxObjects ||
				budget.InternalBytes >= limits.MaxBytes {
				return errors.Join(append(failures, admodel.ErrMembershipLimit)...)
			}
			identity, parseErr := admodel.IdentityByDN(entry.DistinguishedName)
			if parseErr != nil {
				return parseErr
			}
			observed, resolveErr := admodel.InternalResolveIdentitySession(
				ctx,
				adengine.InternalClientSession(c.engine()),
				adengine.InternalClientConfig(c.engine()),
				root,
				identity,
				admodel.InternalMembershipResolveOptions(
					identity,
					result.Controller.Partition,
					append([]string{"groupType"}, options.Properties...),
				),
			)
			entry.Observation = observed
			for _, object := range observed.Candidates {
				resolveErr = errors.Join(resolveErr, budget.InternalObject(object))
			}
			if resolveErr == nil {
				object := *observed.Object
				if principalErr := admodel.InternalValidateRODCPasswordPrincipal(
					object,
					attribute != "msDS-AuthenticatedToAccountlist" && !revealed,
				); principalErr != nil {
					resolveErr = principalErr
				} else {
					principal, decodeErr := admodel.InternalDecodeMembershipPrincipal(
						object,
						adengine.InternalClientConfig(c.engine()).Endpoint,
					)
					resolveErr = decodeErr
					if decodeErr == nil && !seen[principal.GUID] {
						seen[principal.GUID] = true
						result.Principals = append(result.Principals, principal)
					}
				}
			}
			entry.Error = resolveErr
			if resolveErr != nil {
				failures = append(failures, resolveErr)
				if errors.Is(resolveErr, admodel.ErrMembershipLimit) {
					break
				}
			}
		}
		return errors.Join(failures...)
	})
	result.Complete = err == nil
	result.LimitReached = errors.Is(err, admodel.ErrMembershipLimit)
	return result, admodel.InternalRodcPasswordError(err)
}
