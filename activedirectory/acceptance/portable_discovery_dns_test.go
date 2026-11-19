package acceptance

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
)

func TestPortableDiscoveryActualDNSDisjointTargetAndMultipleAddresses(t *testing.T) {
	for _, scenario := range []string{"valid", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			wire := newPortableDiscoveryDNSWire(t, scenario)
			result, err := adengine.InternalLookupDomainControllers(t.Context(), discovery.DNSDiscoveryOptions{DomainDNS: "EXAMPLE.TEST."}, wire.resolver())
			if err != nil || !result.Complete || len(result.Candidates) != 1 {
				t.Fatalf("DNS observations incomplete: %v", err)
			}
			candidate, err := result.Select(admodel.Endpoint{Host: "DC.AD.SDK.TEST."})
			if err != nil || candidate.DomainDNS != "example.test" || candidate.Endpoint.Host != portableTLSHost || candidate.Endpoint.Port != 389 || len(candidate.Records) != 2 ||
				len(candidate.Addresses) != 3 {
				t.Fatal("disjoint namespace, records or multi-address identity changed", err)
			}
			if candidate.Records[0].Priority != 0 || candidate.Records[1].Priority != 1 || candidate.Records[0].Weight != 10 {
				t.Fatal("SRV advertisements changed")
			}
			candidate.Records[0].Target = "mutated.invalid."
			if result.Candidates[0].Records[0].Target == candidate.Records[0].Target {
				t.Fatal("selected candidate aliases caller-visible DNS records")
			}
			if _, err = result.Select(admodel.Endpoint{}); !errors.Is(err, discovery.ErrInvalidDiscovery) {
				t.Fatal("missing explicit host became an automatic selection")
			}
			if _, err = result.Select(admodel.Endpoint{Host: "guessed.example.test"}); !errors.Is(err, discovery.ErrDiscoveryNoCandidates) {
				t.Fatal("unknown host became a DNS candidate")
			}
			wire.mu.Lock()
			defer wire.mu.Unlock()
			if !slices.Contains(wire.queries, "_ldap._tcp.dc._msdcs.example.test.") {
				t.Fatal("explicit absolute query was not used")
			}
			if scenario == "truncated" {
				var udpQuery, tcpQuery bool
				for index, query := range wire.queries {
					if query == "_ldap._tcp.dc._msdcs.example.test." {
						udpQuery = udpQuery || wire.networks[index] == "udp"
						tcpQuery = tcpQuery || wire.networks[index] == "tcp"
					}
				}
				if !udpQuery || !tcpQuery {
					t.Fatal("actual same-query UDP truncation and TCP completion were not exercised")
				}
			}
		})
	}
}

func TestPortableDiscoveryActualDNSRefusalsRemainIncomplete(t *testing.T) {
	for _, scenario := range []string{"missing", "empty", "unavailable", "wrong-owner", "bad-host", "alias", "missing-address", "partial-invalid"} {
		t.Run(scenario, func(t *testing.T) {
			wire := newPortableDiscoveryDNSWire(t, scenario)
			result, err := adengine.InternalLookupDomainControllers(t.Context(), discovery.DNSDiscoveryOptions{DomainDNS: "example.test", Timeout: time.Second}, wire.resolver())
			if err == nil || result.Complete {
				t.Fatalf("untrusted/absent DNS became authoritative: %v", err)
			}
			if scenario == "partial-invalid" && (len(result.Records) != 1 || result.Records[0].Target != "DC.AD.SDK.TEST.") {
				t.Fatal("resolver's valid decoded DNS prefix was discarded")
			}
			if _, err = result.Select(admodel.Endpoint{Host: portableTLSHost}); !errors.Is(err, admodel.ErrIncompleteResult) {
				t.Fatal("partial DNS permitted endpoint selection")
			}
		})
	}
}

func TestPortableDiscoveryConflictingPortsRequireExplicitDisambiguation(t *testing.T) {
	wire := newPortableDiscoveryDNSWire(t, "two-ports")
	result, err := adengine.InternalLookupDomainControllers(t.Context(), discovery.DNSDiscoveryOptions{DomainDNS: "example.test"}, wire.resolver())
	if err != nil || !result.Complete || len(result.Candidates) != 2 {
		t.Fatal("valid advertised endpoints collapsed", err)
	}
	if _, err = result.Select(admodel.Endpoint{Host: portableTLSHost}); !errors.Is(err, discovery.ErrDiscoveryAmbiguous) {
		t.Fatal("ambiguous port was guessed")
	}
	selected, err := result.Select(admodel.Endpoint{Host: portableTLSHost, Port: 1389})
	if err != nil || selected.Endpoint.Port != 1389 {
		t.Fatal("explicit advertised port was not preserved", err)
	}
}

func TestPortableDiscoveryCancellationAndInvalidQueriesDoNotGuessDNS(t *testing.T) {
	wire := newPortableDiscoveryDNSWire(t, "valid")
	for _, domain := range []string{"", "ldap://user:secret@example.test", "ad..test", "127.0.0.1"} {
		if _, err := adengine.InternalLookupDomainControllers(
			t.Context(),
			discovery.DNSDiscoveryOptions{DomainDNS: domain},
			wire.resolver(),
		); !errors.Is(
			err,
			discovery.ErrInvalidDiscovery,
		) {
			t.Fatal("invalid domain crossed DNS boundary")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := adengine.InternalLookupDomainControllers(ctx, discovery.DNSDiscoveryOptions{DomainDNS: "example.test"}, wire.resolver()); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation lost")
	}
	wire.mu.Lock()
	count := len(wire.queries)
	wire.mu.Unlock()
	if count != 0 {
		t.Fatal("invalid/cancelled discovery queried DNS")
	}
	stalled := newPortableDiscoveryDNSWire(t, "stalled")
	result, err := adengine.InternalLookupDomainControllers(
		t.Context(),
		discovery.DNSDiscoveryOptions{DomainDNS: "example.test", Timeout: 40 * time.Millisecond},
		stalled.resolver(),
	)
	if !errors.Is(err, context.DeadlineExceeded) || result.Complete {
		t.Fatal("configured DNS deadline lost", err)
	}
}
