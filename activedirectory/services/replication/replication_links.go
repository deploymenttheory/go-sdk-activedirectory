package replication

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// internalServiceReadReplicationLink reads a site link or bridge and its bounded topology references.
func internalServiceReadReplicationLink(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ReplicationLinkReadOptions,
	bridge bool,
) (admodel.IdentityResult, admodel.ReplicationReferencesResult, error) {
	var observed admodel.IdentityResult
	var refs admodel.ReplicationReferencesResult
	limits, err := admodel.InternalNormalizeReplicationReferenceLimits(options.References)
	if err != nil {
		return observed, refs, err
	}
	if err := admodel.InternalTopologyIdentity(
		identity,
		options.ResolveIdentityOptions,
	); err != nil {
		return observed, refs, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
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
			options.Partition,
		)
		if err != nil {
			return err
		}
		resolve := options.ResolveIdentityOptions
		resolve.Partition = configuration
		resolve.Properties = admodel.InternalReplicationLinkProperties(resolve.Properties, bridge)
		observed, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			resolve,
		)
		if err != nil {
			return err
		}
		class, attr := "siteLink", "siteList"
		if bridge {
			class, attr = "siteLinkBridge", "siteLinkList"
		}
		transport, err := admodel.InternalReplicationObjectTransport(
			*observed.Object,
			configuration,
		)
		if err != nil {
			return err
		}
		parent, err := admodel.InternalReplicationTransportParent(
			root,
			adengine.InternalClientConfig(c.engine()),
			configuration,
			transport,
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalTopologyDirectChild(*observed.Object, parent, class); err != nil {
			return err
		}
		refs, err = admodel.InternalCollectReplicationReferences(
			ctx,
			adengine.InternalClientSession(c.engine()),
			*observed.Object,
			attr,
			limits,
		)
		return err
	})
	return observed, refs, err
}

// ReplicationSiteLink reads one site link and its referenced sites from the configuration partition.
// Options select additional properties and bound reference expansion; partial references remain
// visible in the result.
//
// Related cmdlet: Get-ADReplicationSiteLink.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationsitelink?view=windowsserver2025-ps
func (c *Service) ReplicationSiteLink(
	ctx context.Context,
	identity adshared.Identity,
	options ReplicationLinkReadOptions,
) (ReplicationSiteLinkResult, error) {
	var result admodel.ReplicationSiteLinkResult
	var err error
	result.Observation, result.Sites, err = internalServiceReadReplicationLink(c,
		ctx,
		identity,
		options,
		false,
	)
	if result.Observation.Object != nil {
		value, e := admodel.InternalDecodeReplicationLink(
			*result.Observation.Object,
			result.Observation.Partition,
		)
		result.Link = &value
		err = errors.Join(err, e)
	}
	return result, err
}

// ReplicationSiteLinkBridge reads one site-link bridge and its referenced site links. Options select
// additional properties and reference limits; incomplete observations may accompany an error.
//
// Related cmdlet: Get-ADReplicationSiteLinkBridge.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationsitelinkbridge?view=windowsserver2025-ps
func (c *Service) ReplicationSiteLinkBridge(
	ctx context.Context,
	identity adshared.Identity,
	options ReplicationLinkReadOptions,
) (ReplicationSiteLinkBridgeResult, error) {
	var result admodel.ReplicationSiteLinkBridgeResult
	var err error
	result.Observation, result.SiteLinks, err = internalServiceReadReplicationLink(c,
		ctx,
		identity,
		options,
		true,
	)
	if result.Observation.Object != nil {
		value, e := admodel.InternalDecodeReplicationBridge(
			*result.Observation.Object,
			result.Observation.Partition,
		)
		result.Bridge = &value
		err = errors.Join(err, e)
	}
	return result, err
}

// internalServiceSearchReplicationLinks retains each row and its bounded reference observations on
// failure.
func internalServiceSearchReplicationLinks(c *Service,
	ctx context.Context,
	transport admodel.ReplicationTransport,
	options admodel.SearchOptions,
	limits admodel.ReplicationReferenceLimits,
	bridge bool,
) (admodel.SearchResult, []admodel.ReplicationReferencesResult, string, error) {
	var result admodel.SearchResult
	var refs []admodel.ReplicationReferencesResult
	var configuration string
	limits, err := admodel.InternalNormalizeReplicationReferenceLimits(limits)
	if err != nil {
		return result, refs, configuration, err
	}
	if err := options.Validate(); err != nil {
		return result, refs, configuration, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err = admodel.InternalTopologyConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			"",
		)
		if err != nil {
			return err
		}
		parent, err := admodel.InternalReplicationTransportParent(
			root,
			adengine.InternalClientConfig(c.engine()),
			configuration,
			transport,
		)
		if err != nil {
			return err
		}
		class, attr := "siteLink", "siteList"
		if bridge {
			class, attr = "siteLinkBridge", "siteLinkList"
		}
		query, err := admodel.InternalTopologySearch(options, parent, class)
		if err != nil {
			return err
		}
		query.Properties = admodel.InternalReplicationLinkProperties(options.Properties, bridge)
		result, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			query,
		)
		for _, object := range result.Objects {
			var values admodel.ReplicationReferencesResult
			e := admodel.InternalTopologyDirectChild(object, parent, class)
			if e == nil {
				values, e = admodel.InternalCollectReplicationReferences(
					ctx,
					adengine.InternalClientSession(c.engine()),
					object,
					attr,
					limits,
				)
			}
			refs = append(refs, values)
			err = errors.Join(err, e)
		}
		return err
	})
	if err != nil {
		result.Complete = false
	}
	return result, refs, configuration, err
}

// ReplicationSiteLinks searches site links under the selected inter-site transport. Options bound the
// search and limits bound site-reference expansion; partial search and reference observations are
// retained.
//
// Related cmdlet: Get-ADReplicationSiteLink.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationsitelink?view=windowsserver2025-ps
func (c *Service) ReplicationSiteLinks(
	ctx context.Context,
	transport ReplicationTransport,
	options adshared.SearchOptions,
	limits ReplicationReferenceLimits,
) (ReplicationSiteLinksResult, error) {
	var result admodel.ReplicationSiteLinksResult
	observed, refs, configuration, err := internalServiceSearchReplicationLinks(c,
		ctx,
		transport,
		options,
		limits,
		false,
	)
	result.Observation = observed
	for i, object := range observed.Objects {
		link, e := admodel.InternalDecodeReplicationLink(object, configuration)
		err = errors.Join(err, e)
		result.Links = append(
			result.Links,
			admodel.ReplicationSiteLinkResult{
				Link: &link,
				Observation: admodel.IdentityResult{
					Object:    &object,
					Partition: configuration,
					Complete:  true,
				},
				Sites: refs[i],
			},
		)
	}
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}

// ReplicationSiteLinkBridges searches site-link bridges under the selected inter-site transport.
// Options bound the search and limits bound referenced-link expansion; incomplete observations remain
// explicit.
//
// Related cmdlet: Get-ADReplicationSiteLinkBridge.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationsitelinkbridge?view=windowsserver2025-ps
func (c *Service) ReplicationSiteLinkBridges(
	ctx context.Context,
	transport ReplicationTransport,
	options adshared.SearchOptions,
	limits ReplicationReferenceLimits,
) (ReplicationSiteLinkBridgesResult, error) {
	var result admodel.ReplicationSiteLinkBridgesResult
	observed, refs, configuration, err := internalServiceSearchReplicationLinks(c,
		ctx,
		transport,
		options,
		limits,
		true,
	)
	result.Observation = observed
	for i, object := range observed.Objects {
		bridge, e := admodel.InternalDecodeReplicationBridge(object, configuration)
		err = errors.Join(err, e)
		result.Bridges = append(
			result.Bridges,
			admodel.ReplicationSiteLinkBridgeResult{
				Bridge: &bridge,
				Observation: admodel.IdentityResult{
					Object:    &object,
					Partition: configuration,
					Complete:  true,
				},
				SiteLinks: refs[i],
			},
		)
	}
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
