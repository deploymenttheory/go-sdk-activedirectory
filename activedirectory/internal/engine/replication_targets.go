package engine

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ResolveReplicationTargets expands a server/domain/forest/site selection using
// the configured authenticated LDAP endpoint. Resolution is independent of the
// targets' replication health and never follows a trust or LDAP referral.
func ResolveReplicationTargets(
	ctx context.Context,
	config admodel.Config,
	selection admodel.ReplicationSelection,
) (admodel.ReplicationTargets, error) {
	return InternalResolveReplicationTargets(ctx, config, selection, Dial)
}

func InternalResolveReplicationTargets(
	ctx context.Context,
	config admodel.Config,
	selection admodel.ReplicationSelection,
	dial func(context.Context, admodel.Config) (*Client, error),
) (result admodel.ReplicationTargets, err error) {
	config, err = admodel.InternalConfigNormalized(config)
	if err != nil {
		return result, err
	}
	if err = admodel.InternalReplicationSelectionValidate(selection); err != nil {
		return result, err
	}
	if err = internalReplicationAnchorPrincipals(config, selection); err != nil {
		return result, err
	}
	selection.Servers = slices.Clone(selection.Servers)
	selection.ServicePrincipals = maps.Clone(selection.ServicePrincipals)
	result.Requested = selection
	if err = context.Cause(ctx); err != nil {
		return result, fmt.Errorf("resolve replication targets: %w", err)
	}
	if selection.Scope == admodel.ReplicationScopeServer {
		result.Servers, err = internalReplicationServerTargets(config, selection)
		if err != nil {
			return admodel.ReplicationTargets{}, err
		}
		result.Complete = true
		return result, nil
	}
	client, err := dial(ctx, config)
	if err != nil {
		return result, admodel.InternalReplicationTargetError(config.Endpoint, err)
	}
	defer func() {
		err = errors.Join(err, client.Close())
		result.Complete = err == nil && result.Observation.Complete
	}()
	r, err := InternalDirectoryServiceBegin(
		client.Directory(),
		ctx,
		"resolve replication targets",
		true,
	)
	if err != nil {
		return result, err
	}
	defer func() { err = r.InternalFinish(&result.Observation) }()
	if !r.InternalReady {
		return result, nil
	}
	configuration := r.InternalRequire(
		r.InternalObservation.RootDSE.ConfigurationNamingContext,
		"configurationNamingContext",
	)
	if configuration == "" {
		return result, nil
	}
	base := "CN=Sites," + configuration
	filter := "(objectClass=nTDSDSA)"
	switch selection.Scope {
	case admodel.ReplicationScopeDomain:
		var domain string
		if selection.DomainDNS != "" {
			domain = r.InternalReplicationDomain(configuration, selection.DomainDNS, "")
		} else {
			domain = r.InternalRequire(
				r.InternalObservation.RootDSE.DefaultNamingContext,
				"defaultNamingContext",
			)
		}
		if domain == "" {
			return result, nil
		}
		filter = "(&" + filter + "(msDS-HasDomainNCs=" + admodel.InternalLdapLiteral(domain) + "))"
	case admodel.ReplicationScopeForest:
		if selection.ForestDNS != "" {
			root := r.InternalRequire(
				r.InternalObservation.RootDSE.RootDomainNamingContext,
				"rootDomainNamingContext",
			)
			if root == "" ||
				r.InternalReplicationDomain(configuration, selection.ForestDNS, root) == "" {
				return result, nil
			}
		}
	case admodel.ReplicationScopeSite:
		sites := r.InternalSearch(
			admodel.SearchOptions{
				Base:  base,
				Scope: admodel.ScopeOneLevel,
				Filter: "(&(objectClass=site)(name=" + admodel.InternalLdapLiteral(
					selection.SiteName,
				) + "))",
				Properties: []string{"name"},
			},
		)
		var selected []string
		for _, site := range sites.Objects {
			decoder := admodel.InternalRootDSEDecoder{InternalAttributes: site.Attributes}
			name := decoder.InternalText("name")
			r.InternalAdd(errors.Join(decoder.InternalErrors...))
			if name != nil && strings.EqualFold(*name, selection.SiteName) {
				selected = append(selected, site.DistinguishedName)
			}
		}
		if len(selected) != 1 {
			r.InternalAdd(admodel.ErrDirectoryObjectNotFound)
			return result, nil
		}
		base = "CN=Servers," + selected[0]
	}
	dsas := r.InternalSearch(
		admodel.SearchOptions{
			Base:       base,
			Scope:      admodel.ScopeSubtree,
			Filter:     filter,
			Properties: []string{"objectGUID"},
		},
	)
	for _, dsa := range dsas.Objects {
		if err := context.Cause(r.InternalCtx); err != nil { //nolint:contextcheck // DirectoryServiceBegin derives this bounded context from caller ctx.
			r.InternalAdd(err)
			break
		}
		parent := r.InternalParent(dsa.DistinguishedName)
		if parent == "" {
			continue
		}
		server := r.InternalOne(parent, "(objectClass=server)", []string{"dnsHostName"})
		decoder := admodel.InternalRootDSEDecoder{InternalAttributes: server.Attributes}
		host := r.InternalRequire(decoder.InternalText("dnsHostName"), "dnsHostName")
		r.InternalAdd(errors.Join(decoder.InternalErrors...))
		if host == "" {
			continue
		}
		endpoint, validationErr := internalReplicationTopologyTarget(config, selection, host)
		if validationErr != nil {
			r.InternalAdd(errors.Join(admodel.ErrInvalidResult, validationErr))
			continue
		}
		result.Servers = admodel.InternalAppendReplicationEndpoint(result.Servers, endpoint)
	}
	return result, nil
}

func (r *InternalDirectoryRead) InternalReplicationDomain(
	configuration, dns, requiredNC string,
) string {
	refs := r.InternalSearch(
		admodel.SearchOptions{
			Base:  "CN=Partitions," + configuration,
			Scope: admodel.ScopeOneLevel,
			Filter: "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2)(dnsRoot=" + admodel.InternalLdapLiteral(
				dns,
			) + "))",
			Properties: []string{"nCName", "dnsRoot", "systemFlags"},
		},
	)
	var matches []string
	for _, ref := range refs.Objects {
		decoder := admodel.InternalRootDSEDecoder{InternalAttributes: ref.Attributes}
		name, nc := decoder.InternalText("dnsRoot"), decoder.InternalText("nCName")
		flags := admodel.InternalDecodeScalar(
			&decoder,
			"systemFlags",
			admodel.InternalParseDirectoryMask,
		)
		r.InternalAdd(errors.Join(decoder.InternalErrors...))
		if name != nil && strings.EqualFold(*name, dns) && nc != nil && *nc != "" && flags != nil &&
			*flags&2 != 0 &&
			(requiredNC == "" || strings.EqualFold(*nc, requiredNC)) {
			matches = append(matches, *nc)
		}
	}
	if len(matches) != 1 {
		r.InternalAdd(admodel.ErrDirectoryObjectNotFound)
		return ""
	}
	return matches[0]
}

// Topology advertises server hosts, not the anchor's custom LDAP port. Reuse
// explicit-server validation so each selected peer SPN precedes host/SPN
// normalization; unmapped peers remain for precise per-server refusal without I/O.
func internalReplicationTopologyTarget(config admodel.Config, selection admodel.ReplicationSelection, host string) (admodel.Endpoint, error) {
	config.Endpoint.Port = 389
	if config.Transport == admodel.TransportLDAPS {
		config.Endpoint.Port = 636
	}
	selection.Servers = []admodel.Endpoint{{Host: host}}
	candidates, err := internalReplicationServerTargets(config, selection)
	if err != nil {
		return admodel.Endpoint{}, err
	}
	if len(candidates) != 1 {
		return admodel.Endpoint{}, admodel.ErrInvalidResult
	}
	return candidates[0], nil
}
