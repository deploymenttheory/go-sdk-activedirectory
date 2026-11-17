package engine

import (
	"context"
	"errors"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type GroupMembersOptions struct {
	Partition  string
	Recursive  bool
	Contexts   []MembershipContext
	Properties []string
	Limits     admodel.MembershipLimits
}

func InternalResolveMembershipLink(
	ctx context.Context,
	dn string,
	endpoints []InternalMembershipEndpoint,
	properties []string,
	budget *admodel.InternalMembershipBudget,
) (result admodel.MembershipResolution, index int) {
	result.Reference = dn
	index, err := InternalMembershipDNEndpoint(dn, endpoints)
	if err != nil {
		result.Error = err
		return result, index
	}
	identity, _ := admodel.IdentityByDN(dn)
	e := endpoints[index]
	result.Source = e.InternalClient.config.Endpoint
	result.Observation, result.Error = e.InternalResolve(ctx, identity, properties)
	for _, object := range result.Observation.Candidates {
		if err := budget.InternalObject(object); err != nil {
			result.Error = errors.Join(result.Error, err)
			return result, index
		}
	}
	if result.Error != nil ||
		!admodel.InternalMembershipHasClass(
			*result.Observation.Object,
			"foreignSecurityPrincipal",
		) {
		return result, index
	}
	fsp := result.Observation.Object
	result.ForeignReference = fsp
	value, err := fsp.Values("objectSid").Single()
	if err != nil {
		result.Error = err
		return result, index
	}
	sid, err := value.SID()
	if err != nil {
		result.Error = err
		return result, index
	}
	var match *admodel.IdentityResult
	matchedIndex := -1
	var failures []error
	for i, candidate := range endpoints {
		if i == index || candidate.InternalRoot.Capabilities().Type != admodel.DirectoryADDS {
			continue
		}
		if budget.InternalObjects >= budget.InternalLimits.MaxObjects ||
			budget.InternalBytes >= budget.InternalLimits.MaxBytes {
			result.Error = admodel.ErrMembershipLimit
			return result, index
		}
		identity, _ := admodel.IdentityBySID(sid.String())
		observed, lookupErr := candidate.InternalResolve(ctx, identity, properties)
		result.Lookups = append(
			result.Lookups,
			admodel.MembershipLookup{Observation: observed, Error: lookupErr},
		)
		for _, object := range observed.Candidates {
			if err := budget.InternalObject(object); err != nil {
				result.Error = errors.Join(lookupErr, err)
				return result, index
			}
		}
		if errors.Is(lookupErr, admodel.ErrDirectoryObjectNotFound) {
			continue
		}
		if lookupErr != nil {
			failures = append(failures, lookupErr)
			continue
		}
		if admodel.InternalMembershipHasClass(*observed.Object, "foreignSecurityPrincipal") {
			continue
		}
		if match != nil {
			result.Error = errors.Join(admodel.ErrMembershipForeign, admodel.ErrAmbiguousIdentity)
			return result, index
		}
		match, matchedIndex = &observed, i
	}
	if len(failures) > 0 || match == nil {
		result.Error = errors.Join(append(failures, admodel.ErrMembershipForeign)...)
		return result, index
	}
	result.Observation = *match
	result.Source = endpoints[matchedIndex].InternalClient.config.Endpoint
	return result, matchedIndex
}
