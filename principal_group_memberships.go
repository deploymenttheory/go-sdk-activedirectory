package activedirectory

import (
	"context"
	"errors"
)

type PrincipalGroupMembershipOptions struct {
	Partition string
	// Default AD DS enumeration requires an explicitly authenticated GC client.
	// ResourceContext instead limits discovery to that one explicit NC/server.
	GlobalCatalog   *Client
	ResourceContext *MembershipContext
	Properties      []string
	Limits          MembershipLimits
}

// Complete covers these direct membership searches, not transitive membership,
// ACL visibility, replication convergence or authorization. ResourceContext
// returns only its specified NC. No automatic cross-forest lookup occurs.
type PrincipalGroupMembershipResult struct {
	Principal              IdentityResult
	Groups                 []Group
	PrimaryGroup           *MembershipLookup
	ResourcePrincipal      *MembershipLookup
	Searches               []MembershipSearch
	Complete, LimitReached bool
}

func membershipForestGUID(ctx context.Context, e membershipEndpoint) (GUID, error) {
	if e.root.ConfigurationNamingContext == nil {
		return GUID{}, ErrMembershipContext
	}
	var guid GUID
	err := e.client.read(ctx, func(ctx context.Context) error {
		attributes, err := e.client.session.baseObject(ctx, *e.root.ConfigurationNamingContext, []string{"objectGUID"})
		if err != nil {
			return err
		}
		value, err := (Object{Attributes: attributes}).Values("objectGUID").Single()
		if err != nil {
			return err
		}
		guid, err = value.GUID()
		return err
	})
	return guid, err
}
func membershipSameForest(ctx context.Context, a, b membershipEndpoint) (bool, error) {
	if a.client == b.client {
		return true, nil
	}
	left, err := membershipForestGUID(ctx, a)
	if err != nil {
		return false, err
	}
	right, err := membershipForestGUID(ctx, b)
	return err == nil && left == right, err
}
func membershipCatalog(ctx context.Context, c *Client, home membershipEndpoint) (membershipEndpoint, error) {
	e := membershipEndpoint{client: c}
	if c == nil || c.session == nil {
		return e, ErrMembershipGC
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		e.root = root
		if err != nil {
			return err
		}
		if root.Capabilities().Type != DirectoryADDS || root.IsGlobalCatalogReady == nil || !*root.IsGlobalCatalogReady || (c.config.Endpoint.Port != 3268 && c.config.Endpoint.Port != 3269) {
			return ErrMembershipGC
		}
		return nil
	})
	if err != nil {
		return e, errors.Join(ErrMembershipGC, err)
	}
	same, err := membershipSameForest(ctx, home, e)
	if err != nil || !same {
		return e, errors.Join(ErrMembershipGC, err)
	}
	return e, nil
}

func (c *Client) PrincipalGroupMembership(ctx context.Context, identity Identity, options PrincipalGroupMembershipOptions) (result PrincipalGroupMembershipResult, err error) {
	defer func() { result.LimitReached = result.LimitReached || errors.Is(err, ErrMembershipLimit) }()
	limits, err := normalizeMembershipLimits(options.Limits)
	if err != nil {
		return result, err
	}
	if options.ResourceContext != nil && options.GlobalCatalog != nil {
		return result, ErrInvalidMembership
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
	result.Principal, err = home.resolve(bounded, identity, nil)
	if err != nil {
		return result, err
	}
	principal, err := decodeMembershipPrincipal(*result.Principal.Object, c.config.Endpoint)
	if err != nil {
		return result, err
	}
	budget := membershipBudget{limits: limits}
	if err := budget.object(principal.Object); err != nil {
		return result, err
	}
	seen := map[GUID]bool{}
	appendGroups := func(objects []Object) error {
		for _, object := range objects {
			if err := budget.object(object); err != nil {
				return err
			}
			group, err := decodeGroup(object)
			if err != nil {
				return err
			}
			if group.GUID == nil {
				return ErrAttributeUnavailable
			}
			if !seen[*group.GUID] {
				if len(result.Groups) >= limits.MaxGroups {
					return ErrMembershipLimit
				}
				seen[*group.GUID] = true
				result.Groups = append(result.Groups, group)
			}
		}
		return nil
	}
	queryGroups := func(endpoint membershipEndpoint, base string, filter Filter) error {
		remaining := limits.MaxObjects - budget.objects
		if remaining <= 0 || budget.bytes >= limits.MaxBytes {
			return ErrMembershipLimit
		}
		query := SearchOptions{Base: base, Scope: ScopeSubtree, TypedFilter: filter, Properties: groupProperties(options.Properties), ResultLimit: remaining}
		observed, readErr := endpoint.search(bounded, query)
		result.Searches = append(result.Searches, MembershipSearch{Source: endpoint.client.config.Endpoint, Query: query, Observation: observed, Error: readErr})
		decodeErr := appendGroups(observed.Objects)
		if !observed.Complete {
			if observed.LimitReached {
				return errors.Join(readErr, decodeErr, ErrMembershipLimit)
			}
			return errors.Join(readErr, decodeErr, ErrIncompleteResult)
		}
		return errors.Join(readErr, decodeErr)
	}
	addPrimary := func() error {
		sid, present, err := membershipPrimarySID(principal.Object)
		if err != nil || !present {
			return err
		}
		if budget.objects >= limits.MaxObjects || budget.bytes >= limits.MaxBytes {
			return ErrMembershipLimit
		}
		identity, _ := IdentityBySID(sid.String())
		observed, readErr := home.resolve(bounded, identity, groupProperties(options.Properties))
		result.PrimaryGroup = &MembershipLookup{Observation: observed, Error: readErr}
		if readErr != nil {
			return readErr
		}
		return appendGroups([]Object{*observed.Object})
	}
	direct := func(reference string) Filter {
		return FilterAnd(FilterEqual("objectClass", FilterText("group")), FilterEqual("member", FilterText(reference)))
	}
	if options.ResourceContext != nil {
		resource := *options.ResourceContext
		resourceIdentity, parseErr := IdentityByDN(resource.Partition)
		if parseErr != nil {
			return result, errors.Join(ErrMembershipContext, parseErr)
		}
		endpoint, readErr := newMembershipEndpoint(bounded, resource.Client, resourceIdentity, resource.Partition, true)
		if readErr != nil {
			return result, readErr
		}
		sameForest, readErr := membershipSameForest(bounded, home, endpoint)
		if readErr != nil {
			return result, readErr
		}
		reference := principal.Object.DistinguishedName
		if !sameForest {
			if endpoint.root.Capabilities().Type != DirectoryADDS {
				return result, ErrMembershipForeign
			}
			if budget.objects >= limits.MaxObjects || budget.bytes >= limits.MaxBytes {
				return result, ErrMembershipLimit
			}
			sidIdentity, _ := IdentityBySID(principal.SID.String())
			observed, lookupErr := endpoint.resolve(bounded, sidIdentity, nil)
			result.ResourcePrincipal = &MembershipLookup{Observation: observed, Error: lookupErr}
			for _, object := range observed.Candidates {
				if err := budget.object(object); err != nil {
					return result, errors.Join(lookupErr, err)
				}
			}
			if lookupErr != nil {
				return result, errors.Join(ErrMembershipForeign, lookupErr)
			}
			if !membershipHasClass(*observed.Object, "foreignSecurityPrincipal") {
				return result, ErrMembershipForeign
			}
			reference = observed.Object.DistinguishedName
		}
		err = queryGroups(endpoint, endpoint.partition, direct(reference))
		if err == nil && sameForest && membershipSameDN(home.partition, endpoint.partition) && home.root.Capabilities().Type == DirectoryADDS {
			err = addPrimary()
		}
	} else {
		if home.root.Capabilities().Type != DirectoryADDS {
			return result, ErrMembershipContext
		}
		catalog, readErr := membershipCatalog(bounded, options.GlobalCatalog, home)
		if readErr != nil {
			return result, readErr
		}
		err = queryGroups(home, home.partition, FilterAnd(direct(principal.Object.DistinguishedName), FilterBitOr("groupType", 7)))
		if err == nil {
			err = addPrimary()
		}
		if err == nil {
			err = queryGroups(catalog, "", FilterAnd(direct(principal.Object.DistinguishedName), FilterBitAnd("groupType", 8)))
		}
	}
	result.LimitReached = errors.Is(err, ErrMembershipLimit)
	result.Complete = err == nil
	return result, err
}
