package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// ResolveReplicationTargets expands a server/domain/forest/site selection using
// the configured authenticated LDAP endpoint. Resolution is independent of the
// targets' replication health and never follows a trust or LDAP referral.
func ResolveReplicationTargets(ctx context.Context, config Config, selection ReplicationSelection) (ReplicationTargets, error) {
	return resolveReplicationTargets(ctx, config, selection, Dial)
}

func resolveReplicationTargets(ctx context.Context, config Config, selection ReplicationSelection, dial func(context.Context, Config) (*Client, error)) (result ReplicationTargets, err error) {
	config, err = config.normalized()
	if err != nil {
		return result, err
	}
	if err = selection.validate(); err != nil {
		return result, err
	}
	selection.Servers = slices.Clone(selection.Servers)
	result.Requested = selection
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	if selection.Scope == ReplicationScopeServer {
		servers := selection.Servers
		if len(servers) == 0 {
			servers = []Endpoint{config.Endpoint}
		}
		for _, endpoint := range servers {
			candidate := config
			candidate.Endpoint = endpoint
			candidate, err = candidate.normalized()
			if err != nil {
				return ReplicationTargets{}, err
			}
			result.Servers = appendReplicationEndpoint(result.Servers, candidate.Endpoint)
		}
		result.Complete = true
		return result, nil
	}
	client, err := dial(ctx, config)
	if err != nil {
		return result, replicationTargetError(config.Endpoint, err)
	}
	defer func() {
		err = errors.Join(err, client.Close())
		result.Complete = err == nil && result.Observation.Complete
	}()
	r, err := client.Directory().begin(ctx, "resolve replication targets", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.finish(&result.Observation) }()
	if !r.ready {
		return result, nil
	}
	configuration := r.require(r.observation.RootDSE.ConfigurationNamingContext, "configurationNamingContext")
	if configuration == "" {
		return result, nil
	}
	base := "CN=Sites," + configuration
	filter := "(objectClass=nTDSDSA)"
	switch selection.Scope {
	case ReplicationScopeDomain:
		var domain string
		if selection.DomainDNS != "" {
			domain = r.replicationDomain(configuration, selection.DomainDNS, "")
		} else {
			domain = r.require(r.observation.RootDSE.DefaultNamingContext, "defaultNamingContext")
		}
		if domain == "" {
			return result, nil
		}
		filter = "(&" + filter + "(msDS-HasDomainNCs=" + ldapLiteral(domain) + "))"
	case ReplicationScopeForest:
		if selection.ForestDNS != "" {
			root := r.require(r.observation.RootDSE.RootDomainNamingContext, "rootDomainNamingContext")
			if root == "" || r.replicationDomain(configuration, selection.ForestDNS, root) == "" {
				return result, nil
			}
		}
	case ReplicationScopeSite:
		sites := r.search(SearchOptions{Base: base, Scope: ScopeOneLevel, Filter: "(&(objectClass=site)(name=" + ldapLiteral(selection.SiteName) + "))", Properties: []string{"name"}})
		var selected []string
		for _, site := range sites.Objects {
			decoder := rootDSEDecoder{attributes: site.Attributes}
			name := decoder.text("name")
			r.add(errors.Join(decoder.errors...))
			if name != nil && strings.EqualFold(*name, selection.SiteName) {
				selected = append(selected, site.DistinguishedName)
			}
		}
		if len(selected) != 1 {
			r.add(ErrDirectoryObjectNotFound)
			return result, nil
		}
		base = "CN=Servers," + selected[0]
	}
	dsas := r.search(SearchOptions{Base: base, Scope: ScopeSubtree, Filter: filter, Properties: []string{"objectGUID"}})
	for _, dsa := range dsas.Objects {
		if err := context.Cause(r.ctx); err != nil {
			r.add(err)
			break
		}
		parent := r.parent(dsa.DistinguishedName)
		if parent == "" {
			continue
		}
		server := r.one(parent, "(objectClass=server)", []string{"dnsHostName"})
		decoder := rootDSEDecoder{attributes: server.Attributes}
		host := r.require(decoder.text("dnsHostName"), "dnsHostName")
		r.add(errors.Join(decoder.errors...))
		if host == "" {
			continue
		}
		candidate := config
		candidate.Endpoint = Endpoint{Host: host}
		candidate, validationErr := candidate.normalized()
		if validationErr != nil {
			r.add(ErrInvalidResult)
			continue
		}
		result.Servers = appendReplicationEndpoint(result.Servers, candidate.Endpoint)
	}
	return result, nil
}

func (r *directoryRead) replicationDomain(configuration, dns, requiredNC string) string {
	refs := r.search(SearchOptions{Base: "CN=Partitions," + configuration, Scope: ScopeOneLevel, Filter: "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2)(dnsRoot=" + ldapLiteral(dns) + "))", Properties: []string{"nCName", "dnsRoot", "systemFlags"}})
	var matches []string
	for _, ref := range refs.Objects {
		decoder := rootDSEDecoder{attributes: ref.Attributes}
		name, nc := decoder.text("dnsRoot"), decoder.text("nCName")
		flags := decodeScalar(&decoder, "systemFlags", parseDirectoryMask)
		r.add(errors.Join(decoder.errors...))
		if name != nil && strings.EqualFold(*name, dns) && nc != nil && *nc != "" && flags != nil && *flags&2 != 0 && (requiredNC == "" || strings.EqualFold(*nc, requiredNC)) {
			matches = append(matches, *nc)
		}
	}
	if len(matches) != 1 {
		r.add(ErrDirectoryObjectNotFound)
		return ""
	}
	return matches[0]
}

func (s ReplicationSelection) validate() error {
	if s.Scope > ReplicationScopeSite || !validDirectoryText(s.DomainDNS) || !validDirectoryText(s.ForestDNS) || !validDirectoryText(s.SiteName) {
		return ErrInvalidReplicationQuery
	}
	if s.DomainDNS != "" && (s.Scope != ReplicationScopeDomain || !validServerHost(s.DomainDNS)) {
		return ErrInvalidReplicationQuery
	}
	if s.ForestDNS != "" && (s.Scope != ReplicationScopeForest || !validServerHost(s.ForestDNS)) {
		return ErrInvalidReplicationQuery
	}
	if s.SiteName != "" && s.Scope != ReplicationScopeSite || s.Scope == ReplicationScopeSite && s.SiteName == "" {
		return ErrInvalidReplicationQuery
	}
	if s.Scope != ReplicationScopeServer && len(s.Servers) != 0 {
		return ErrInvalidReplicationQuery
	}
	return nil
}

func appendReplicationEndpoint(endpoints []Endpoint, endpoint Endpoint) []Endpoint {
	for _, existing := range endpoints {
		if strings.EqualFold(existing.Host, endpoint.Host) && existing.Port == endpoint.Port {
			return endpoints
		}
	}
	return append(endpoints, endpoint)
}

func replicationTargetError(endpoint Endpoint, err error) error {
	if err == nil {
		return nil
	}
	return &ReplicationReadError{Operation: "resolve replication targets", Server: endpoint, Cause: errors.Join(ErrIncompleteResult, err)}
}
