package replication

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func (c *Service) ReplicationSite(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (ReplicationSiteResult, error) {
	var result admodel.ReplicationSiteResult
	if err := admodel.InternalTopologyIdentity(identity, options); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		result, err = admodel.InternalReadReplicationSite(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		return err
	})
	result.Complete = result.Complete && err == nil
	return result, err
}

func (c *Service) ReplicationSites(
	ctx context.Context,
	options adshared.SearchOptions,
) (ReplicationSitesResult, error) {
	var result admodel.ReplicationSitesResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err := admodel.InternalTopologyConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			"",
		)
		if err != nil {
			return err
		}
		query, err := admodel.InternalTopologySearch(options, "CN=Sites,"+configuration, "site")
		if err != nil {
			return err
		}
		query.Properties = admodel.InternalTopologySiteProperties(options.Properties)
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			query,
		)
		for _, object := range result.Observation.Objects {
			entry := admodel.ReplicationSiteResult{
				Observation: admodel.IdentityResult{
					Object:     &object,
					Candidates: []admodel.Object{object},
					Partition:  configuration,
					Complete:   true,
				},
			}
			site, e := admodel.InternalDecodeReplicationSite(object)
			entry.Site = &site
			err = errors.Join(
				err,
				e,
				admodel.InternalTopologyDirectChild(object, query.Base, "site"),
			)
			result.Sites = append(result.Sites, entry)
		}
		// Listing returns only site-object projections; ReplicationSite reads the
		// settings and complete server/subnet associations on demand.
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}
