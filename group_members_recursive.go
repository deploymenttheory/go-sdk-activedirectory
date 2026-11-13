package activedirectory

import (
	"context"
	"errors"
	"fmt"
)

type GroupMembersOptions struct {
	Partition  string
	Recursive  bool
	Contexts   []MembershipContext
	Properties []string
	Limits     MembershipLimits
}
type GroupMembershipTraversal struct {
	Source         Endpoint
	Depth          int
	Links          GroupMemberLinksResult
	Resolutions    []MembershipResolution
	PrimaryMembers SearchResult
}

// Complete means every requested traversal, range and resolution completed.
// It does not prove ACL visibility or a transactionally consistent graph. Each
// Links.AttributeReturned preserves omission without proving no hidden members.
type GroupMembersResult struct {
	Members                []MembershipPrincipal
	Groups                 []GroupMembershipTraversal
	Unresolved             []MembershipResolution
	Complete, LimitReached bool
}

func (c *Client) GroupMembers(ctx context.Context, identity Identity, options GroupMembersOptions) (result GroupMembersResult, err error) {
	defer func() {
		result.LimitReached = result.LimitReached || errors.Is(err, ErrMembershipLimit) || errors.Is(err, ErrGroupMembershipLimit)
	}()
	limits, err := normalizeMembershipLimits(options.Limits)
	if err != nil {
		return result, err
	}
	if err := validateIdentityOperation(identity, membershipResolveOptions(identity, options.Partition, options.Properties)); err != nil {
		return result, err
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	home, err := newMembershipEndpoint(bounded, c, identity, options.Partition, true)
	if err != nil {
		return result, err
	}
	endpoints, err := membershipContexts(bounded, home, options.Contexts)
	if err != nil {
		return result, err
	}
	budget := membershipBudget{limits: limits}
	type queuedGroup struct {
		identity        Identity
		endpoint, depth int
	}
	queue := []queuedGroup{{identity: identity}}
	groups, principals := map[string]bool{}, map[string]int{}
	var failures []error
	for len(queue) > 0 {
		if err := context.Cause(bounded); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		item := queue[0]
		queue = queue[1:]
		if budget.groups >= limits.MaxGroups || item.depth > limits.MaxDepth || budget.objects >= limits.MaxObjects || budget.ranges >= limits.MaxRanges || budget.bytes >= limits.MaxBytes {
			result.LimitReached = true
			return result, errors.Join(append(failures, ErrMembershipLimit)...)
		}
		e := endpoints[item.endpoint]
		links, readErr := e.client.GroupMemberLinks(bounded, item.identity, GroupMemberLinksOptions{Partition: e.partition, MaxValues: limits.MaxObjects - budget.objects, MaxRanges: limits.MaxRanges - budget.ranges, MaxBytes: limits.MaxBytes - budget.bytes})
		result.Groups = append(result.Groups, GroupMembershipTraversal{Source: e.client.config.Endpoint, Depth: item.depth, Links: links})
		node := &result.Groups[len(result.Groups)-1]
		budget.groups++
		for _, r := range links.Ranges {
			budget.ranges++
			if err := budget.attributes(r.Attributes); err != nil {
				result.LimitReached = true
				return result, errors.Join(readErr, err)
			}
		}
		for _, object := range links.Observation.Candidates {
			if err := budget.object(object); err != nil {
				result.LimitReached = true
				return result, errors.Join(readErr, err)
			}
		}
		if readErr != nil {
			result.LimitReached = errors.Is(readErr, ErrGroupMembershipLimit)
			return result, errors.Join(append(failures, readErr)...)
		}
		group, decodeErr := decodeMembershipPrincipal(*links.Observation.Object, e.client.config.Endpoint)
		if decodeErr != nil {
			return result, errors.Join(append(failures, decodeErr)...)
		}
		groups[group.SID.String()] = true
		observations := make([]MembershipResolution, 0, len(links.Members))
		for _, link := range links.Members {
			if budget.objects >= limits.MaxObjects {
				result.LimitReached = true
				return result, errors.Join(append(failures, ErrMembershipLimit)...)
			}
			observation, index := resolveMembershipLink(bounded, link.DistinguishedName, endpoints, options.Properties, &budget)
			node.Resolutions = append(node.Resolutions, observation)
			if observation.Error != nil {
				result.Unresolved = append(result.Unresolved, observation)
				failures = append(failures, observation.Error)
				if errors.Is(observation.Error, ErrMembershipLimit) {
					result.LimitReached = true
					return result, errors.Join(failures...)
				}
				continue
			}
			// The endpoint follows a resolved foreign principal, not its FSP.
			observation.Source = endpoints[index].client.config.Endpoint
			observations = append(observations, observation)
		}
		if e.root.Capabilities().Type == DirectoryADDS {
			if rid, domainGroup := membershipDomainRID(group.SID); domainGroup {
				if budget.objects >= limits.MaxObjects {
					result.LimitReached = true
					return result, errors.Join(append(failures, ErrMembershipLimit)...)
				}
				query := SearchOptions{Base: e.partition, Scope: ScopeSubtree, TypedFilter: FilterAnd(FilterPresent("objectSid"), FilterEqual("primaryGroupID", FilterText(fmt.Sprint(rid)))), Properties: membershipProperties(options.Properties), ResultLimit: limits.MaxObjects - budget.objects}
				primary, primaryErr := e.search(bounded, query)
				node.PrimaryMembers = primary
				for _, object := range primary.Objects {
					if err := budget.object(object); err != nil {
						result.LimitReached = true
						return result, errors.Join(primaryErr, err)
					}
				}
				if primaryErr != nil || !primary.Complete {
					result.LimitReached = primary.LimitReached
					return result, errors.Join(append(failures, primaryErr, ErrIncompleteResult)...)
				}
				for i := range primary.Objects {
					object := primary.Objects[i]
					sid, present, err := membershipPrimarySID(object)
					if err != nil || !present || sid.String() != group.SID.String() {
						return result, errors.Join(append(failures, err, ErrInvalidResult)...)
					}
					observations = append(observations, MembershipResolution{Source: e.client.config.Endpoint, Reference: object.DistinguishedName, Observation: IdentityResult{Source: e.client.config.Endpoint, Partition: e.partition, Object: &object, Candidates: []Object{object}, Complete: true}})
				}
			}
		}
		for _, observation := range observations {
			object := *observation.Observation.Object
			if values := object.Values("objectSid"); values.State != AttributePresent && !membershipHasClass(object, "user") && !membershipHasClass(object, "group") && !membershipHasClass(object, "foreignSecurityPrincipal") {
				continue
			}
			principal, err := decodeMembershipPrincipal(object, observation.Source)
			if err != nil {
				observation.Error = err
				result.Unresolved = append(result.Unresolved, observation)
				failures = append(failures, err)
				continue
			}
			key := principal.SID.String()
			if membershipHasClass(object, "group") && options.Recursive {
				if groups[key] {
					continue
				}
				groups[key] = true
				index, err := membershipDNEndpoint(object.DistinguishedName, endpoints)
				if err != nil {
					observation.Error = err
					result.Unresolved = append(result.Unresolved, observation)
					failures = append(failures, err)
					continue
				}
				queue = append(queue, queuedGroup{identity: objectGUIDIdentity(principal.GUID), endpoint: index, depth: item.depth + 1})
				continue
			}
			primary, hasPrimary, _ := membershipPrimarySID(object)
			principal.Primary = hasPrimary && primary.String() == group.SID.String()
			if previous, exists := principals[key]; exists {
				result.Members[previous].Primary = result.Members[previous].Primary || principal.Primary
				continue
			}
			principals[key] = len(result.Members)
			result.Members = append(result.Members, principal)
		}
	}
	err = errors.Join(failures...)
	result.Complete = err == nil
	return result, err
}

func resolveMembershipLink(ctx context.Context, dn string, endpoints []membershipEndpoint, properties []string, budget *membershipBudget) (result MembershipResolution, index int) {
	result.Reference = dn
	index, err := membershipDNEndpoint(dn, endpoints)
	if err != nil {
		result.Error = err
		return result, index
	}
	identity, _ := IdentityByDN(dn)
	e := endpoints[index]
	result.Source = e.client.config.Endpoint
	result.Observation, result.Error = e.resolve(ctx, identity, properties)
	for _, object := range result.Observation.Candidates {
		if err := budget.object(object); err != nil {
			result.Error = errors.Join(result.Error, err)
			return result, index
		}
	}
	if result.Error != nil || !membershipHasClass(*result.Observation.Object, "foreignSecurityPrincipal") {
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
	var match *IdentityResult
	matchedIndex := -1
	var failures []error
	for i, candidate := range endpoints {
		if i == index || candidate.root.Capabilities().Type != DirectoryADDS {
			continue
		}
		if budget.objects >= budget.limits.MaxObjects || budget.bytes >= budget.limits.MaxBytes {
			result.Error = ErrMembershipLimit
			return result, index
		}
		identity, _ := IdentityBySID(sid.String())
		observed, lookupErr := candidate.resolve(ctx, identity, properties)
		result.Lookups = append(result.Lookups, MembershipLookup{Observation: observed, Error: lookupErr})
		for _, object := range observed.Candidates {
			if err := budget.object(object); err != nil {
				result.Error = errors.Join(lookupErr, err)
				return result, index
			}
		}
		if errors.Is(lookupErr, ErrDirectoryObjectNotFound) {
			continue
		}
		if lookupErr != nil {
			failures = append(failures, lookupErr)
			continue
		}
		if membershipHasClass(*observed.Object, "foreignSecurityPrincipal") {
			continue
		}
		if match != nil {
			result.Error = errors.Join(ErrMembershipForeign, ErrAmbiguousIdentity)
			return result, index
		}
		match, matchedIndex = &observed, i
	}
	if len(failures) > 0 || match == nil {
		result.Error = errors.Join(append(failures, ErrMembershipForeign)...)
		return result, index
	}
	result.Observation = *match
	result.Source = endpoints[matchedIndex].client.config.Endpoint
	return result, matchedIndex
}
