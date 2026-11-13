package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type AccountAuthorizationGroupsOptions struct {
	Partition     string
	Contexts      []MembershipContext
	GlobalCatalog *Client
	Properties    []string
	Limits        MembershipLimits
}
type AuthorizationGroupSIDResult struct {
	SID     SID
	Lookups []MembershipSearch
	Error   error
}

// TokensComplete means the server returned every contiguous tokenGroups range.
// Complete additionally requires every SID to resolve to a security group in
// the supplied contexts. Neither is a Windows logon token or access-check result.
type AccountAuthorizationGroupsResult struct {
	Account                                IdentityResult
	SIDs                                   []SID
	Groups                                 []Group
	Resolutions                            []AuthorizationGroupSIDResult
	Ranges                                 []GroupMemberRange
	TokensComplete, Complete, LimitReached bool
}

func (c *Client) AccountAuthorizationGroups(ctx context.Context, identity Identity, options AccountAuthorizationGroupsOptions) (result AccountAuthorizationGroupsResult, err error) {
	defer func() { result.LimitReached = result.LimitReached || errors.Is(err, ErrMembershipLimit) }()
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
	result.Account, err = home.resolve(bounded, identity, nil)
	if err != nil {
		return result, err
	}
	account := *result.Account.Object
	if membershipHasClass(account, "group") || (!membershipHasClass(account, "user") && !membershipHasClass(account, "inetOrgPerson") && !membershipHasClass(account, "msDS-BindableObject")) {
		return result, ErrUnsupportedIdentity
	}
	if _, err := decodeMembershipPrincipal(account, c.config.Endpoint); err != nil {
		return result, err
	}
	endpoints, err := membershipContexts(bounded, home, options.Contexts)
	if err != nil {
		return result, err
	}
	if options.GlobalCatalog != nil {
		catalog, err := membershipCatalog(bounded, options.GlobalCatalog, home)
		if err != nil {
			return result, err
		}
		endpoints = append(endpoints, catalog)
	}
	budget := membershipBudget{limits: limits}
	if err := budget.object(account); err != nil {
		return result, err
	}
	err = home.client.read(bounded, func(ctx context.Context) error { return collectAuthorizationSIDs(ctx, home, account, &budget, &result) })
	if err != nil {
		result.LimitReached = errors.Is(err, ErrMembershipLimit)
		return result, err
	}
	var failures []error
	for _, sid := range result.SIDs {
		if cause := context.Cause(bounded); cause != nil {
			return result, errors.Join(append(failures, cause)...)
		}
		resolution := AuthorizationGroupSIDResult{SID: sid}
		var found *Group
		var lookupFailures []error
		for _, endpoint := range endpoints {
			if budget.objects >= limits.MaxObjects || budget.bytes >= limits.MaxBytes {
				resolution.Error = ErrMembershipLimit
				break
			}
			query := SearchOptions{Base: endpoint.partition, Scope: ScopeSubtree, TypedFilter: FilterAnd(FilterEqual("objectClass", FilterText("group")), FilterEqual("objectSid", FilterBytes(sid.Bytes()))), Properties: groupProperties(options.Properties), PageSize: 2, ResultLimit: 2}
			observed, lookupErr := endpoint.search(bounded, query)
			resolution.Lookups = append(resolution.Lookups, MembershipSearch{Source: endpoint.client.config.Endpoint, Query: query, Observation: observed, Error: lookupErr})
			for _, object := range observed.Objects {
				if err := budget.object(object); err != nil {
					lookupErr = errors.Join(lookupErr, err)
				}
			}
			if lookupErr != nil {
				lookupFailures = append(lookupFailures, lookupErr)
				if errors.Is(lookupErr, ErrMembershipLimit) {
					break
				}
				continue
			}
			if !observed.Complete || len(observed.Objects) > 1 {
				lookupFailures = append(lookupFailures, ErrAmbiguousIdentity)
				continue
			}
			if len(observed.Objects) == 0 {
				continue
			}
			group, decodeErr := decodeGroup(observed.Objects[0])
			if decodeErr != nil || group.SID == nil || group.SID.String() != sid.String() || group.Type == nil || !group.Type.Has(groupSecurityBit) || group.GUID == nil {
				lookupFailures = append(lookupFailures, errors.Join(decodeErr, ErrInvalidResult))
				continue
			}
			if found != nil && *found.GUID != *group.GUID {
				lookupFailures = append(lookupFailures, ErrAmbiguousIdentity)
				continue
			}
			found = &group
		}
		if resolution.Error == nil {
			resolution.Error = errors.Join(lookupFailures...)
			if found == nil {
				resolution.Error = errors.Join(resolution.Error, ErrDirectoryObjectNotFound)
			}
		}
		result.Resolutions = append(result.Resolutions, resolution)
		if resolution.Error != nil {
			failures = append(failures, resolution.Error)
		} else {
			if len(result.Groups) >= limits.MaxGroups {
				failures = append(failures, ErrMembershipLimit)
				result.LimitReached = true
				break
			}
			result.Groups = append(result.Groups, *found)
		}
		if errors.Is(resolution.Error, ErrMembershipLimit) {
			result.LimitReached = true
			break
		}
	}
	err = errors.Join(failures...)
	result.Complete = err == nil
	return result, err
}

func collectAuthorizationSIDs(ctx context.Context, home membershipEndpoint, account Object, budget *membershipBudget, result *AccountAuthorizationGroupsResult) error {
	reader, ok := home.client.session.(groupMemberReader)
	if !ok {
		return ErrUnsupported
	}
	guid, usn, err := groupMemberVersion(account)
	if err != nil {
		return err
	}
	start := uint64(0)
	seen := map[string]bool{}
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		remaining := budget.limits.MaxObjects - budget.objects
		if remaining <= 0 || budget.ranges >= budget.limits.MaxRanges || budget.bytes >= budget.limits.MaxBytes {
			return ErrMembershipLimit
		}
		property := fmt.Sprintf("tokenGroups;range=%d-%d", start, start+uint64(min(1500, remaining))-1)
		attributes, readErr := reader.groupMemberBaseObject(ctx, objectGUIDTarget(guid), []string{property, "objectGUID", "uSNChanged"}, false)
		result.Ranges = append(result.Ranges, GroupMemberRange{RequestedProperty: property, Attributes: attributes, ObservedAt: time.Now().UTC(), Error: readErr})
		budget.ranges++
		if err := budget.attributes(attributes); err != nil {
			return errors.Join(readErr, err)
		}
		// Reuse the strict contiguous-range parser without interpreting SID
		// bytes as member DNs. Original tokenGroups descriptions remain in Ranges.
		ranges := make(map[string][][]byte)
		for name, values := range attributes {
			lower := strings.ToLower(name)
			if lower == "tokengroups" || strings.HasPrefix(lower, "tokengroups;") {
				key := "member" + lower[len("tokengroups"):]
				if _, exists := ranges[key]; exists {
					return errors.Join(readErr, ErrInvalidResult)
				}
				ranges[key] = values
			}
		}
		values, next, terminal, present, rangeErr := groupMemberRange(ranges, start)
		if !present {
			rangeErr = errors.Join(rangeErr, ErrAuthorizationGroupsUnavailable)
		}
		for _, value := range values {
			if budget.objects >= budget.limits.MaxObjects {
				return errors.Join(readErr, rangeErr, ErrMembershipLimit)
			}
			budget.objects++
			sid, err := SIDFromBytes(value)
			if err != nil {
				rangeErr = errors.Join(rangeErr, err)
				continue
			}
			if !seen[sid.String()] {
				seen[sid.String()] = true
				result.SIDs = append(result.SIDs, sid)
			}
		}
		observedGUID, observedUSN, versionErr := groupMemberVersion(Object{Attributes: attributes})
		if versionErr == nil && (observedGUID != guid || observedUSN != usn) {
			versionErr = ErrGroupMembershipChanged
		}
		if err := errors.Join(readErr, rangeErr, versionErr); err != nil {
			return err
		}
		if terminal {
			result.TokensComplete = true
			return nil
		}
		start = next
	}
}
