package model

import (
	"errors"
	"strings"
)

func InternalReplicationSelectionValidate(s ReplicationSelection) error {
	if s.Scope > ReplicationScopeSite || !InternalValidDirectoryText(s.DomainDNS) ||
		!InternalValidDirectoryText(s.ForestDNS) ||
		!InternalValidDirectoryText(s.SiteName) {
		return ErrInvalidReplicationQuery
	}
	if s.DomainDNS != "" &&
		(s.Scope != ReplicationScopeDomain || !InternalValidServerHost(s.DomainDNS)) {
		return ErrInvalidReplicationQuery
	}
	if s.ForestDNS != "" &&
		(s.Scope != ReplicationScopeForest || !InternalValidServerHost(s.ForestDNS)) {
		return ErrInvalidReplicationQuery
	}
	if s.SiteName != "" && s.Scope != ReplicationScopeSite ||
		s.Scope == ReplicationScopeSite && s.SiteName == "" {
		return ErrInvalidReplicationQuery
	}
	if s.Scope != ReplicationScopeServer && len(s.Servers) != 0 {
		return ErrInvalidReplicationQuery
	}
	return nil
}

func InternalAppendReplicationEndpoint(endpoints []Endpoint, endpoint Endpoint) []Endpoint {
	for _, existing := range endpoints {
		if strings.EqualFold(existing.Host, endpoint.Host) && existing.Port == endpoint.Port {
			return endpoints
		}
	}
	return append(endpoints, endpoint)
}

func InternalReplicationTargetError(endpoint Endpoint, err error) error {
	if err == nil {
		return nil
	}
	return &ReplicationReadError{
		Operation: "resolve replication targets",
		Server:    endpoint,
		Cause:     errors.Join(ErrIncompleteResult, err),
	}
}
