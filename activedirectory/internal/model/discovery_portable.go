package model

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
)

var (
	ErrDiscoveryNoCandidates = errors.New("DNS discovery returned no usable domain controller candidates")
	ErrDiscoveryAmbiguous    = errors.New("domain controller selection is ambiguous")
	ErrDiscoveryIdentity     = errors.New("authenticated controller identity differs from the explicit selection")
)

// DNSDiscoveryOptions names an explicit AD DNS domain and optional literal DNS
// site label. No computer join state, security identity or search suffix is used.
// Timeout bounds the complete SRV, canonical-name and address observation.
type DNSDiscoveryOptions struct {
	DomainDNS string
	SiteName  string
	Timeout   time.Duration
}

// DNSSRVRecord preserves priority/weight advertisements, not verified services.
// The lookup API never uses these values to authenticate or try another host.
type DNSSRVRecord struct {
	Target           string
	Port             uint16
	Priority, Weight uint16
}

// DNSControllerCandidate groups one advertised LDAP host/port and its records.
// Addresses are copied DNS observations, not proof of identity or membership.
// A DC can use a disjoint hostname suffix; only authenticated LDAP establishes
// the selected domain. Endpoint.Port preserves the advertised LDAP port and
// never selects TLS or replaces the caller's separately configured transport port.
type DNSControllerCandidate struct {
	DomainDNS string
	SiteName  string
	Endpoint  Endpoint
	Records   []DNSSRVRecord
	Addresses []netip.Addr
}

// DNSDiscoveryResult contains bounded unauthenticated candidates. Complete means
// the planned DNS observations finished, never that any endpoint is trusted.
type DNSDiscoveryResult struct {
	Requested     DNSDiscoveryOptions
	QueryName     string
	CanonicalName string
	// Records retains bounded decoded advertisements even when a later record
	// or resolver error prevents complete candidate/address validation.
	Records    []DNSSRVRecord
	Candidates []DNSControllerCandidate
	Complete   bool
}

// Select requires an explicit host. Port zero is accepted only when that host
// has exactly one advertised endpoint. It never chooses a different host or
// converts an incomplete DNS response into a usable authentication selection.
func (r DNSDiscoveryResult) Select(endpoint Endpoint) (DNSControllerCandidate, error) {
	if !r.Complete {
		return DNSControllerCandidate{}, ErrIncompleteResult
	}
	if !InternalValidDiscoveryHost(endpoint.Host) {
		return DNSControllerCandidate{}, ErrInvalidDiscovery
	}
	var matches []DNSControllerCandidate
	for _, candidate := range r.Candidates {
		if strings.EqualFold(strings.TrimSuffix(candidate.Endpoint.Host, "."), strings.TrimSuffix(endpoint.Host, ".")) &&
			(endpoint.Port == 0 || endpoint.Port == candidate.Endpoint.Port) {
			matches = append(matches, candidate)
		}
	}
	if len(matches) == 0 {
		return DNSControllerCandidate{}, ErrDiscoveryNoCandidates
	}
	if len(matches) != 1 {
		return DNSControllerCandidate{}, ErrDiscoveryAmbiguous
	}
	selected := matches[0]
	if !InternalDiscoveryCandidateValid(selected) {
		return DNSControllerCandidate{}, ErrInvalidResult
	}
	selected.Records = slices.Clone(selected.Records)
	selected.Addresses = slices.Clone(selected.Addresses)
	return selected, nil
}

// DomainControllerSelection constrains one explicitly configured LDAP endpoint.
// DomainDNS is the actual AD domain name, independent of the DC hostname suffix.
// Optional GUID/SID pins compare authenticated values. Candidate is an optional
// copied DNS observation; it is validated again and never substitutes identity.
// Its advertised LDAP port remains independent of Config.Endpoint.Port: callers
// explicitly choose the transport and its connection port (for example, an LDAP
// advertisement on 389 and an LDAPS connection to the same selected host on 636).
type DomainControllerSelection struct {
	DomainDNS          string
	SiteName           string
	ExpectedDomainGUID string
	ExpectedDomainSID  string
	ExpectedDSAGUID    string
	Candidate          *DNSControllerCandidate
}

// AuthenticatedController preserves partial identity reads and measured session
// protection. Complete requires every identity constraint, not all topology
// attributes. Domain/Forest/DomainController projections remain separate reads
// on the same owning client and are not an atomic snapshot.
type AuthenticatedController struct {
	Requested      DomainControllerSelection
	Observation    DirectoryObservation
	Protection     SessionProtection
	DomainDNS      *string
	DomainDN       *string
	DomainGUID     *string
	DomainSID      *string
	ServerDN       *string
	ServerGUID     *string
	DSADN          *string
	DSAGUID        *string
	ComputerDN     *string
	ComputerGUID   *string
	HostName       *string
	SiteName       *string
	CrossReference *CrossReference
	Complete       bool
}
