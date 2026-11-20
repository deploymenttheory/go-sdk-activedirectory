package engine

import (
	"context"
	"errors"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// MembershipContext explicitly supplies an authenticated connection and NC.
// The SDK does not dial, forward credentials, chase referrals, or close it.
type MembershipContext struct {
	Client    *Client
	Partition string
}

type InternalMembershipEndpoint struct {
	InternalClient    *Client
	InternalRoot      admodel.RootDSE
	InternalPartition string
}

func InternalNewMembershipEndpoint(
	ctx context.Context,
	c *Client,
	identity admodel.Identity,
	partition string,
	full bool,
) (InternalMembershipEndpoint, error) {
	e := InternalMembershipEndpoint{InternalClient: c}
	if c == nil || c.session == nil {
		return e, admodel.ErrClosed
	}
	err := InternalClientRead(c, ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(ctx, c.session)
		e.InternalRoot = root
		if err != nil {
			return err
		}
		if root.Capabilities().Type == admodel.DirectoryUnknown {
			return root.Capabilities().RequireADDS("Membership")
		}
		selected := partition
		if selected == "" {
			selected = c.config.Partition
		}
		index, _, err := admodel.InternalIdentityPartition(identity, selected, root)
		if err != nil {
			return err
		}
		e.InternalPartition = root.NamingContexts[index]
		if full && root.Capabilities().Type == admodel.DirectoryADDS {
			if c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269 {
				return admodel.ErrGroupMembershipTarget
			}
			if root.DefaultNamingContext == nil ||
				!admodel.InternalMembershipSameDN(e.InternalPartition, *root.DefaultNamingContext) {
				return admodel.ErrMembershipContext
			}
		}
		return nil
	})
	return e, err
}

func InternalMembershipContexts(
	ctx context.Context,
	home InternalMembershipEndpoint,
	contexts []MembershipContext,
) ([]InternalMembershipEndpoint, error) {
	if len(contexts) > 64 {
		return nil, admodel.ErrMembershipLimit
	}
	result := []InternalMembershipEndpoint{home}
	for _, item := range contexts {
		identity, err := admodel.IdentityByDN(item.Partition)
		if err != nil {
			return result, errors.Join(admodel.ErrMembershipContext, err)
		}
		for _, old := range result {
			if admodel.InternalMembershipSameDN(old.InternalPartition, item.Partition) {
				return result, admodel.ErrMembershipContext
			}
		}
		endpoint, err := InternalNewMembershipEndpoint(
			ctx,
			item.Client,
			identity,
			item.Partition,
			true,
		)
		if err != nil {
			return result, err
		}
		result = append(result, endpoint)
	}
	return result, nil
}

func InternalMembershipDNEndpoint(dn string, endpoints []InternalMembershipEndpoint) (int, error) {
	identity, err := admodel.IdentityByDN(dn)
	if err != nil {
		return -1, err
	}
	best, depth := -1, -1
	for i, e := range endpoints {
		parsed, _ := admodel.InternalParseIdentityDN(e.InternalPartition)
		_, _, err := admodel.InternalIdentityPartition(
			identity,
			e.InternalPartition,
			e.InternalRoot,
		)
		if err == nil && len(parsed) > depth {
			best, depth = i, len(parsed)
		}
	}
	if best < 0 {
		return -1, admodel.ErrMembershipContext
	}
	return best, nil
}

func (e InternalMembershipEndpoint) InternalResolve(
	ctx context.Context,
	identity admodel.Identity,
	extra []string,
) (admodel.IdentityResult, error) {
	var result admodel.IdentityResult
	err := InternalClientRead(e.InternalClient, ctx, func(ctx context.Context) error {
		var err error
		result, err = admodel.InternalResolveIdentitySession(
			ctx,
			e.InternalClient.session,
			e.InternalClient.config,
			e.InternalRoot,
			identity,
			admodel.InternalMembershipResolveOptions(identity, e.InternalPartition, extra),
		)
		return err
	})
	return result, err
}

func (e InternalMembershipEndpoint) InternalSearch(
	ctx context.Context,
	query admodel.SearchOptions,
) (admodel.SearchResult, error) {
	var result admodel.SearchResult
	err := InternalClientRead(e.InternalClient, ctx, func(ctx context.Context) error {
		var err error
		// A nonempty membership base selects one naming context. AD DS can
		// otherwise return continuation references for subordinate partitions,
		// even when every matching principal in this context was returned.
		// A critical domain-scope control requires the server to honor this
		// boundary; unsupported controls and unexpected references still fail.
		// The explicit catalog-wide query uses an empty base and must retain
		// its forest-wide scope across naming contexts.
		session := e.InternalClient.session
		if query.Base != "" {
			session = admodel.InternalControlledSearchSession{
				InternalDirectorySession: session,
				InternalControls: []admodel.InternalLdapWriteControl{
					{InternalOid: "1.2.840.113556.1.4.1339", InternalCritical: true},
				},
			}
		}
		result, err = admodel.InternalSearchIdentitySession(ctx, session, query)
		return err
	})
	return result, err
}
