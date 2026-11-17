package engine

import (
	"context"
	"errors"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type PrincipalGroupMembershipOptions struct {
	Partition string
	// Default AD DS enumeration requires an explicitly authenticated GC client.
	// ResourceContext instead limits discovery to that one explicit NC/server.
	GlobalCatalog   *Client
	ResourceContext *MembershipContext
	Properties      []string
	Limits          admodel.MembershipLimits
}

func InternalMembershipForestGUID(
	ctx context.Context,
	e InternalMembershipEndpoint,
) (admodel.GUID, error) {
	if e.InternalRoot.ConfigurationNamingContext == nil {
		return admodel.GUID{}, admodel.ErrMembershipContext
	}
	var guid admodel.GUID
	err := InternalClientRead(e.InternalClient, ctx, func(ctx context.Context) error {
		attributes, err := e.InternalClient.session.InternalBaseObject(
			ctx,
			*e.InternalRoot.ConfigurationNamingContext,
			[]string{"objectGUID"},
		)
		if err != nil {
			return err
		}
		value, err := (admodel.Object{Attributes: attributes}).Values("objectGUID").Single()
		if err != nil {
			return err
		}
		guid, err = value.GUID()
		return err
	})
	return guid, err
}

func InternalMembershipSameForest(
	ctx context.Context,
	a, b InternalMembershipEndpoint,
) (bool, error) {
	if a.InternalClient == b.InternalClient {
		return true, nil
	}
	left, err := InternalMembershipForestGUID(ctx, a)
	if err != nil {
		return false, err
	}
	right, err := InternalMembershipForestGUID(ctx, b)
	return err == nil && left == right, err
}

func InternalMembershipCatalog(
	ctx context.Context,
	c *Client,
	home InternalMembershipEndpoint,
) (InternalMembershipEndpoint, error) {
	e := InternalMembershipEndpoint{InternalClient: c}
	if c == nil || c.session == nil {
		return e, admodel.ErrMembershipGC
	}
	err := InternalClientRead(c, ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(ctx, c.session)
		e.InternalRoot = root
		if err != nil {
			return err
		}
		if root.Capabilities().Type != admodel.DirectoryADDS || root.IsGlobalCatalogReady == nil ||
			!*root.IsGlobalCatalogReady ||
			(c.config.Endpoint.Port != 3268 && c.config.Endpoint.Port != 3269) {
			return admodel.ErrMembershipGC
		}
		return nil
	})
	if err != nil {
		return e, errors.Join(admodel.ErrMembershipGC, err)
	}
	same, err := InternalMembershipSameForest(ctx, home, e)
	if err != nil || !same {
		return e, errors.Join(admodel.ErrMembershipGC, err)
	}
	return e, nil
}
