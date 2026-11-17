package memberships

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func (c *Service) PrincipalGroupMembership(
	ctx context.Context,
	identity adshared.Identity,
	options PrincipalGroupMembershipOptions,
) (result PrincipalGroupMembershipResult, err error) {
	defer func() { result.LimitReached = result.LimitReached || errors.Is(err, admodel.ErrMembershipLimit) }()
	limits, err := admodel.InternalNormalizeMembershipLimits(options.Limits)
	if err != nil {
		return result, err
	}
	if options.ResourceContext != nil && options.GlobalCatalog != nil {
		return result, admodel.ErrInvalidMembership
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
	result.Principal, err = home.InternalResolve(bounded, identity, nil)
	if err != nil {
		return result, err
	}
	principal, err := admodel.InternalDecodeMembershipPrincipal(
		*result.Principal.Object,
		adengine.InternalClientConfig(c.engine()).Endpoint,
	)
	if err != nil {
		return result, err
	}
	budget := admodel.InternalMembershipBudget{InternalLimits: limits}
	if err := budget.InternalObject(principal.Object); err != nil {
		return result, err
	}
	seen := map[admodel.GUID]bool{}
	appendGroups := func(objects []admodel.Object) error {
		for _, object := range objects {
			if err := budget.InternalObject(object); err != nil {
				return err
			}
			group, err := admodel.InternalDecodeGroup(object)
			if err != nil {
				return err
			}
			if group.GUID == nil {
				return admodel.ErrAttributeUnavailable
			}
			if !seen[*group.GUID] {
				if len(result.Groups) >= limits.MaxGroups {
					return admodel.ErrMembershipLimit
				}
				seen[*group.GUID] = true
				result.Groups = append(result.Groups, group)
			}
		}
		return nil
	}
	queryGroups := func(endpoint adengine.InternalMembershipEndpoint, base string, filter admodel.Filter) error {
		remaining := limits.MaxObjects - budget.InternalObjects
		if remaining <= 0 || budget.InternalBytes >= limits.MaxBytes {
			return admodel.ErrMembershipLimit
		}
		query := admodel.SearchOptions{
			Base:        base,
			Scope:       admodel.ScopeSubtree,
			TypedFilter: filter,
			Properties:  admodel.InternalGroupProperties(options.Properties),
			ResultLimit: remaining,
		}
		observed, readErr := endpoint.InternalSearch(bounded, query)
		result.Searches = append(
			result.Searches,
			admodel.MembershipSearch{
				Source:      adengine.InternalClientConfig(endpoint.InternalClient).Endpoint,
				Query:       query,
				Observation: observed,
				Error:       readErr,
			},
		)
		decodeErr := appendGroups(observed.Objects)
		if !observed.Complete {
			if observed.LimitReached {
				return errors.Join(readErr, decodeErr, admodel.ErrMembershipLimit)
			}
			return errors.Join(readErr, decodeErr, admodel.ErrIncompleteResult)
		}
		return errors.Join(readErr, decodeErr)
	}
	addPrimary := func() error {
		sid, present, err := admodel.InternalMembershipPrimarySID(principal.Object)
		if err != nil || !present {
			return err
		}
		if budget.InternalObjects >= limits.MaxObjects || budget.InternalBytes >= limits.MaxBytes {
			return admodel.ErrMembershipLimit
		}
		identity, _ := admodel.IdentityBySID(sid.String())
		observed, readErr := home.InternalResolve(
			bounded,
			identity,
			admodel.InternalGroupProperties(options.Properties),
		)
		result.PrimaryGroup = &admodel.MembershipLookup{Observation: observed, Error: readErr}
		if readErr != nil {
			return readErr
		}
		return appendGroups([]admodel.Object{*observed.Object})
	}
	direct := func(reference string) admodel.Filter {
		return admodel.FilterAnd(
			admodel.FilterEqual("objectClass", admodel.FilterText("group")),
			admodel.FilterEqual("member", admodel.FilterText(reference)),
		)
	}
	if options.ResourceContext != nil {
		resource := *options.ResourceContext
		resourceIdentity, parseErr := admodel.IdentityByDN(resource.Partition)
		if parseErr != nil {
			return result, errors.Join(admodel.ErrMembershipContext, parseErr)
		}
		endpoint, readErr := adengine.InternalNewMembershipEndpoint(
			bounded,
			resource.Client,
			resourceIdentity,
			resource.Partition,
			true,
		)
		if readErr != nil {
			return result, readErr
		}
		sameForest, readErr := adengine.InternalMembershipSameForest(bounded, home, endpoint)
		if readErr != nil {
			return result, readErr
		}
		reference := principal.Object.DistinguishedName
		if !sameForest {
			if endpoint.InternalRoot.Capabilities().Type != admodel.DirectoryADDS {
				return result, admodel.ErrMembershipForeign
			}
			if budget.InternalObjects >= limits.MaxObjects ||
				budget.InternalBytes >= limits.MaxBytes {
				return result, admodel.ErrMembershipLimit
			}
			sidIdentity, _ := admodel.IdentityBySID(principal.SID.String())
			observed, lookupErr := endpoint.InternalResolve(bounded, sidIdentity, nil)
			result.ResourcePrincipal = &admodel.MembershipLookup{
				Observation: observed,
				Error:       lookupErr,
			}
			for _, object := range observed.Candidates {
				if err := budget.InternalObject(object); err != nil {
					return result, errors.Join(lookupErr, err)
				}
			}
			if lookupErr != nil {
				return result, errors.Join(admodel.ErrMembershipForeign, lookupErr)
			}
			if !admodel.InternalMembershipHasClass(*observed.Object, "foreignSecurityPrincipal") {
				return result, admodel.ErrMembershipForeign
			}
			reference = observed.Object.DistinguishedName
		}
		err = queryGroups(endpoint, endpoint.InternalPartition, direct(reference))
		if err == nil && sameForest &&
			admodel.InternalMembershipSameDN(home.InternalPartition, endpoint.InternalPartition) &&
			home.InternalRoot.Capabilities().Type == admodel.DirectoryADDS {
			err = addPrimary()
		}
	} else {
		if home.InternalRoot.Capabilities().Type != admodel.DirectoryADDS {
			return result, admodel.ErrMembershipContext
		}
		catalog, readErr := adengine.InternalMembershipCatalog(bounded, options.GlobalCatalog, home)
		if readErr != nil {
			return result, readErr
		}
		err = queryGroups(
			home,
			home.InternalPartition,
			admodel.FilterAnd(
				direct(principal.Object.DistinguishedName),
				admodel.FilterBitOr("groupType", 7),
			),
		)
		if err == nil {
			err = addPrimary()
		}
		if err == nil {
			err = queryGroups(
				catalog,
				"",
				admodel.FilterAnd(
					direct(principal.Object.DistinguishedName),
					admodel.FilterBitAnd("groupType", 8),
				),
			)
		}
	}
	result.LimitReached = errors.Is(err, admodel.ErrMembershipLimit)
	result.Complete = err == nil
	return result, err
}
