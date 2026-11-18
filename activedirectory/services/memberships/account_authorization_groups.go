package memberships

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// AccountAuthorizationGroups computes a bounded set of security groups for the selected account using
// the supplied directory contexts and optional global catalog. Inspect completeness and limit
// information before treating the result as exhaustive.
//
// Related cmdlet: Get-ADAccountAuthorizationGroup.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adaccountauthorizationgroup?view=windowsserver2025-ps
func (c *Service) AccountAuthorizationGroups(
	ctx context.Context,
	identity adshared.Identity,
	options AccountAuthorizationGroupsOptions,
) (result AccountAuthorizationGroupsResult, err error) {
	defer func() { result.LimitReached = result.LimitReached || errors.Is(err, admodel.ErrMembershipLimit) }()
	limits, err := admodel.InternalNormalizeMembershipLimits(options.Limits)
	if err != nil {
		return result, err
	}
	if err := admodel.InternalValidateIdentityOperation(
		identity,
		admodel.InternalMembershipResolveOptions(identity, options.Partition, options.Properties),
	); err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	home, err := adengine.InternalNewMembershipEndpoint(
		bounded,
		c.engine(),
		identity,
		options.Partition,
		true,
	)
	if err != nil {
		return result, err
	}
	result.Account, err = home.InternalResolve(bounded, identity, nil)
	if err != nil {
		return result, err
	}
	account := *result.Account.Object
	if admodel.InternalMembershipHasClass(account, "group") ||
		(!admodel.InternalMembershipHasClass(account, "user") &&
			!admodel.InternalMembershipHasClass(account, "inetOrgPerson") &&
			!admodel.InternalMembershipHasClass(account, "msDS-BindableObject")) {
		return result, admodel.ErrUnsupportedIdentity
	}
	if _, err := admodel.InternalDecodeMembershipPrincipal(
		account,
		adengine.InternalClientConfig(c.engine()).Endpoint,
	); err != nil {
		return result, err
	}
	endpoints, err := adengine.InternalMembershipContexts(bounded, home, options.Contexts)
	if err != nil {
		return result, err
	}
	if options.GlobalCatalog != nil {
		catalog, err := adengine.InternalMembershipCatalog(bounded, options.GlobalCatalog, home)
		if err != nil {
			return result, err
		}
		endpoints = append(endpoints, catalog)
	}
	budget := admodel.InternalMembershipBudget{InternalLimits: limits}
	if err := budget.InternalObject(account); err != nil {
		return result, err
	}
	err = adengine.InternalClientRead(
		home.InternalClient,
		bounded,
		func(ctx context.Context) error {
			return adengine.InternalCollectAuthorizationSIDs(ctx, home, account, &budget, &result)
		},
	)
	if err != nil {
		result.LimitReached = errors.Is(err, admodel.ErrMembershipLimit)
		return result, err
	}
	var failures []error
	for _, sid := range result.SIDs {
		if cause := context.Cause(bounded); cause != nil {
			return result, errors.Join(append(failures, cause)...)
		}
		resolution := admodel.AuthorizationGroupSIDResult{SID: sid}
		var found *admodel.Group
		var lookupFailures []error
		for _, endpoint := range endpoints {
			if budget.InternalObjects >= limits.MaxObjects ||
				budget.InternalBytes >= limits.MaxBytes {
				resolution.Error = admodel.ErrMembershipLimit
				break
			}
			query := admodel.SearchOptions{
				Base:  endpoint.InternalPartition,
				Scope: admodel.ScopeSubtree,
				TypedFilter: admodel.FilterAnd(
					admodel.FilterEqual("objectClass", admodel.FilterText("group")),
					admodel.FilterEqual("objectSid", admodel.FilterBytes(sid.Bytes())),
				),
				Properties:  admodel.InternalGroupProperties(options.Properties),
				PageSize:    2,
				ResultLimit: 2,
			}
			observed, lookupErr := endpoint.InternalSearch(bounded, query)
			resolution.Lookups = append(
				resolution.Lookups,
				admodel.MembershipSearch{
					Source:      adengine.InternalClientConfig(endpoint.InternalClient).Endpoint,
					Query:       query,
					Observation: observed,
					Error:       lookupErr,
				},
			)
			for _, object := range observed.Objects {
				if err := budget.InternalObject(object); err != nil {
					lookupErr = errors.Join(lookupErr, err)
				}
			}
			if lookupErr != nil {
				lookupFailures = append(lookupFailures, lookupErr)
				if errors.Is(lookupErr, admodel.ErrMembershipLimit) {
					break
				}
				continue
			}
			if !observed.Complete || len(observed.Objects) > 1 {
				lookupFailures = append(lookupFailures, admodel.ErrAmbiguousIdentity)
				continue
			}
			if len(observed.Objects) == 0 {
				continue
			}
			group, decodeErr := admodel.InternalDecodeGroup(observed.Objects[0])
			if decodeErr != nil || group.SID == nil || group.SID.String() != sid.String() ||
				group.Type == nil ||
				!group.Type.Has(admodel.InternalGroupSecurityBit) ||
				group.GUID == nil {
				lookupFailures = append(
					lookupFailures,
					errors.Join(decodeErr, admodel.ErrInvalidResult),
				)
				continue
			}
			if found != nil && *found.GUID != *group.GUID {
				lookupFailures = append(lookupFailures, admodel.ErrAmbiguousIdentity)
				continue
			}
			found = &group
		}
		if resolution.Error == nil {
			resolution.Error = errors.Join(lookupFailures...)
			if found == nil {
				resolution.Error = errors.Join(resolution.Error, admodel.ErrDirectoryObjectNotFound)
			}
		}
		result.Resolutions = append(result.Resolutions, resolution)
		if resolution.Error != nil {
			failures = append(failures, resolution.Error)
		} else {
			if len(result.Groups) >= limits.MaxGroups {
				failures = append(failures, admodel.ErrMembershipLimit)
				result.LimitReached = true
				break
			}
			result.Groups = append(result.Groups, *found)
		}
		if errors.Is(resolution.Error, admodel.ErrMembershipLimit) {
			result.LimitReached = true
			break
		}
	}
	err = errors.Join(failures...)
	result.Complete = err == nil
	return result, err
}
