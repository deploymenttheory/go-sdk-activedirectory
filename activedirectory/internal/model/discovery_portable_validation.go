package model

import (
	"math"
	"net/netip"
	"strings"
	"time"
)

// InternalDiscoveryDNSName validates literal ASCII DNS labels, including an
// explicitly absolute name. It performs no IDNA or domain-suffix substitution.
func InternalDiscoveryDNSName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !InternalDiscoveryDNSLabel(label) {
			return false
		}
	}
	_, err := netip.ParseAddr(name)
	return err != nil
}

func InternalDiscoveryDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, ch := range label {
		if ch != '-' && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

func InternalValidDiscoveryHost(host string) bool {
	return InternalDiscoveryDNSName(host) && InternalValidServerHost(host)
}

func InternalDNSDiscoveryNormalized(options DNSDiscoveryOptions) (DNSDiscoveryOptions, error) {
	if !InternalDiscoveryDNSName(options.DomainDNS) || options.SiteName != "" && !InternalDiscoveryDNSLabel(options.SiteName) || options.Timeout < 0 ||
		options.Timeout > time.Duration(math.MaxInt32)*time.Second {
		return DNSDiscoveryOptions{}, ErrInvalidDiscovery
	}
	options.DomainDNS = strings.ToLower(strings.TrimSuffix(options.DomainDNS, "."))
	if len(InternalDNSDiscoveryQuery(options)) > 254 {
		return DNSDiscoveryOptions{}, ErrInvalidDiscovery
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	return options, nil
}

func InternalDNSDiscoveryQuery(options DNSDiscoveryOptions) string {
	name := "_ldap._tcp."
	if options.SiteName != "" {
		name += options.SiteName + "._sites."
	}
	return name + "dc._msdcs." + options.DomainDNS + "."
}

// Validate checks DNS input locally, without asking a locator or resolver.
func (o DNSDiscoveryOptions) Validate() error {
	_, err := InternalDNSDiscoveryNormalized(o)
	return err
}

func InternalDiscoveryCandidateValid(candidate DNSControllerCandidate) bool {
	if !InternalDiscoveryDNSName(candidate.DomainDNS) || !InternalValidDiscoveryHost(candidate.Endpoint.Host) || candidate.Endpoint.Port == 0 || len(candidate.Records) == 0 ||
		len(candidate.Addresses) == 0 ||
		candidate.SiteName != "" && !InternalDiscoveryDNSLabel(candidate.SiteName) {
		return false
	}
	for _, address := range candidate.Addresses {
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return false
		}
	}
	for _, record := range candidate.Records {
		if !InternalValidDiscoveryHost(record.Target) || !strings.EqualFold(strings.TrimSuffix(record.Target, "."), strings.TrimSuffix(candidate.Endpoint.Host, ".")) ||
			record.Port != candidate.Endpoint.Port {
			return false
		}
	}
	return true
}

func InternalDomainControllerSelection(selection DomainControllerSelection, endpoint Endpoint) (DomainControllerSelection, error) {
	if !InternalDiscoveryDNSName(selection.DomainDNS) || !InternalValidDiscoveryHost(endpoint.Host) || selection.SiteName != "" && !InternalValidDiscoveryText(selection.SiteName) {
		return DomainControllerSelection{}, ErrInvalidDiscovery
	}
	selection.DomainDNS = strings.ToLower(strings.TrimSuffix(selection.DomainDNS, "."))
	for _, pin := range []string{selection.ExpectedDomainGUID, selection.ExpectedDSAGUID} {
		if pin != "" {
			value, err := ParseGUID(pin)
			if err != nil || value == (GUID{}) {
				return DomainControllerSelection{}, ErrInvalidDiscovery
			}
		}
	}
	if selection.ExpectedDomainSID != "" {
		value, err := ParseSID(selection.ExpectedDomainSID)
		if err != nil || !InternalValidDomainSID(value.Bytes()) {
			return DomainControllerSelection{}, ErrInvalidDiscovery
		}
	}

	if selection.Candidate != nil {
		candidate := *selection.Candidate
		if !InternalDiscoveryCandidateValid(candidate) || !strings.EqualFold(strings.TrimSuffix(candidate.DomainDNS, "."), selection.DomainDNS) ||
			!strings.EqualFold(strings.TrimSuffix(candidate.Endpoint.Host, "."), strings.TrimSuffix(endpoint.Host, ".")) ||
			!strings.EqualFold(candidate.SiteName, selection.SiteName) {
			return DomainControllerSelection{}, ErrInvalidDiscovery
		}
		candidate.Records = append([]DNSSRVRecord(nil), candidate.Records...)
		candidate.Addresses = append([]netip.Addr(nil), candidate.Addresses...)
		selection.Candidate = &candidate
	}
	return selection, nil
}

// Validate checks the explicit domain/controller constraints before DNS,
// credential-file access or authentication. It does not prove membership.
func (s DomainControllerSelection) Validate(endpoint Endpoint) error {
	_, err := InternalDomainControllerSelection(s, endpoint)
	return err
}
