package acceptance

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
)

func TestPortableDiscoveryActualDNSAndAuthenticatedLDAPTopology(t *testing.T) {
	for _, transport := range []admodel.Transport{admodel.TransportLDAPS, admodel.TransportStartTLS} {
		t.Run(transportName(transport), func(t *testing.T) {
			dns := newPortableDiscoveryDNSWire(t, "valid")
			candidates, err := adengine.InternalLookupDomainControllers(t.Context(), discovery.DNSDiscoveryOptions{DomainDNS: "example.test"}, dns.resolver())
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := candidates.Select(admodel.Endpoint{Host: portableTLSHost, Port: 389})
			if err != nil {
				t.Fatal(err)
			}
			config, wire, _ := newPortableDiscoveryLDAP(t, "valid", transport)
			config.Endpoint.Port = 389
			if transport == admodel.TransportLDAPS {
				config.Endpoint.Port = 636
			}
			password := bytes.Clone(config.Credentials.Password)
			selection := discovery.DomainControllerSelection{
				DomainDNS:          "example.test",
				ExpectedDomainGUID: "01010101-0101-0101-0101-010101010101",
				ExpectedDomainSID:  "S-1-5-21-101-202-303",
				ExpectedDSAGUID:    "02020202-0202-0202-0202-020202020202",
				Candidate:          &candidate,
			}
			connection, observed, err := adengine.InternalDialDomainController(t.Context(), config, selection, portableDiscoveryDialer(wire))
			if err != nil || connection == nil || !observed.Complete || !observed.Observation.Complete || !observed.Protection.TLSVerified || !observed.Protection.Complete ||
				observed.DomainDNS == nil ||
				*observed.DomainDNS != "example.test" ||
				observed.HostName == nil ||
				*observed.HostName != portableTLSHost ||
				observed.DomainSID == nil ||
				*observed.DomainSID != selection.ExpectedDomainSID ||
				observed.DSAGUID == nil ||
				*observed.DSAGUID != selection.ExpectedDSAGUID {
				t.Fatalf("same-session authenticated disjoint DC identity incomplete: %v", err)
			}
			if observed.Requested.Candidate.Endpoint.Port != 389 || observed.Requested.Candidate.Records[0].Port != 389 || candidate.Endpoint.Port != 389 {
				t.Fatal("transport selection overwrote the LDAP SRV advertisement")
			}
			if observed.ComputerGUID == nil || observed.ServerGUID == nil || len(observed.Observation.Objects) != 5 {
				t.Fatal("typed/raw identity observations missing")
			}
			observed.Requested.Candidate.Records[0].Target = "mutated.invalid."
			if selection.Candidate.Records[0].Target == observed.Requested.Candidate.Records[0].Target {
				t.Fatal("selection retained caller-owned slices")
			}
			directory := discovery.New(connection)
			domain, err := directory.Domain(t.Context(), discovery.DomainOptions{})
			if err != nil || !domain.Observation.Complete || domain.DNSRoot == nil || *domain.DNSRoot != "example.test" || len(domain.Replicas) != 2 {
				t.Fatalf("portable authenticated domain projection incomplete: %v", err)
			}
			forest, err := directory.Forest(t.Context())
			if err != nil || !forest.Observation.Complete || forest.Name == nil || *forest.Name != "example.test" || len(forest.Sites) != 1 {
				t.Fatalf("portable authenticated forest projection incomplete: %v", err)
			}
			controller, err := directory.DomainController(t.Context(), discovery.DomainControllerOptions{})
			if err != nil || !controller.Observation.Complete || controller.Controller.HostName == nil || *controller.Controller.HostName != portableTLSHost {
				t.Fatalf("portable authenticated controller projection incomplete: %v", err)
			}
			controllers, err := directory.DomainControllers(t.Context(), discovery.DomainControllersQuery{PageSize: 8})
			if err != nil || !controllers.Observation.Complete || len(controllers.Controllers) != 2 {
				t.Fatalf("portable topology collection incomplete: %v", err)
			}
			if !bytes.Equal(password, config.Credentials.Password) {
				t.Fatal("caller password changed")
			}
			if err = connection.Close(); err != nil {
				t.Fatal(err)
			}
			wire.wait(t)
		})
	}
}

func transportName(value admodel.Transport) string {
	if value == admodel.TransportLDAPS {
		return "ldaps"
	}
	return "starttls"
}

func TestPortableDiscoveryAuthenticatedIdentityRefusalsKeepPartialReadsAndClose(t *testing.T) {
	for _, scenario := range []string{"wrong-domain", "wrong-root-host", "wrong-dsa-parent", "missing-domain-sid", "wrong-crossref-domain", "wrong-crossref-class", "external-crossref", "disabled-crossref", "wrong-computer-host", "foreign-computer-reference", "wrong-computer-sid", "wrong-dsa-domain", "wrong-returned-domain-dn", "ambiguous-crossref", "denied", "referral", "lost"} {
		t.Run(scenario, func(t *testing.T) {
			config, wire, fixture := newPortableDiscoveryLDAP(t, scenario, admodel.TransportLDAPS)
			retiring := &atomic.Bool{}
			retiring.Store(true)
			wire.retiring = retiring
			connection, observed, err := adengine.InternalDialDomainController(
				t.Context(),
				config,
				discovery.DomainControllerSelection{DomainDNS: "example.test"},
				portableDiscoveryDialer(wire),
			)
			if err == nil || connection != nil || observed.Complete || observed.Observation.Complete || !observed.Protection.Complete {
				t.Fatalf("refused discovery became usable: %v", err)
			}
			if observed.Observation.RootDSE.DefaultNamingContext == nil {
				t.Fatal("authenticated RootDSE partial observation lost")
			}
			if scenario == "missing-domain-sid" &&
				(observed.DomainSID != nil || observed.DomainGUID == nil || errors.Is(err, discovery.ErrDiscoveryIdentity) || errors.Is(err, admodel.ErrInvalidResult)) {
				t.Fatal("unreturned identity became a malformed value or observed mismatch")
			}
			var status *admodel.LDAPError
			if scenario == "denied" || scenario == "referral" {
				want := uint32(50)
				if scenario == "referral" {
					want = 10
				}
				if !errors.As(err, &status) || status.Code != want || observed.DomainGUID == nil || observed.DomainSID == nil {
					t.Fatal("actual refusal or preceding identity fields lost", err)
				}
				if scenario == "denied" && admodel.Classify(err) != admodel.ClassDenied {
					t.Fatal("denial became an empty/missing result")
				}
			}
			fixture.mu.Lock()
			queries := slices.Clone(fixture.queries)
			fixture.mu.Unlock()
			if scenario == "wrong-domain" && len(queries) != 1 {
				t.Fatal("wrong-domain RootDSE caused guessed base reads")
			}
			if slices.ContainsFunc(queries, func(base string) bool { return strings.Contains(base, "DC=foreign") }) {
				t.Fatal("foreign linked identity was followed")
			}
			wire.wait(t)
		})
	}
}

func TestPortableDiscoveryCancellationClosesExactlyOneAuthenticatedConnection(t *testing.T) {
	config, wire, fixture := newPortableDiscoveryLDAP(t, "cancel", admodel.TransportLDAPS)
	retiring := &atomic.Bool{}
	retiring.Store(true)
	wire.retiring = retiring
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		select {
		case <-fixture.stalled:
			cancel()
		case <-ctx.Done():
		}
	}()
	connection, observed, err := adengine.InternalDialDomainController(ctx, config, discovery.DomainControllerSelection{DomainDNS: "example.test"}, portableDiscoveryDialer(wire))
	if !errors.Is(err, context.Canceled) || connection != nil || observed.Complete || observed.DomainGUID == nil {
		t.Fatal("cancelled validation lost cause/partial identity or retained a client", err)
	}
	wire.wait(t)
}

func TestPortableDiscoveryAuthenticatedGUIDSIDAndSitePinsAreEnforced(t *testing.T) {
	for _, pin := range []string{"domain-guid", "domain-sid", "dsa-guid", "wrong-site", "literal-site"} {
		t.Run(pin, func(t *testing.T) {
			config, wire, _ := newPortableDiscoveryLDAP(t, "valid", admodel.TransportLDAPS)
			selection := discovery.DomainControllerSelection{DomainDNS: "example.test"}
			switch pin {
			case "domain-guid":
				selection.ExpectedDomainGUID = "11111111-2222-3333-4444-555555555555"
			case "domain-sid":
				selection.ExpectedDomainSID = "S-1-5-21-404-505-606"
			case "dsa-guid":
				selection.ExpectedDSAGUID = "11111111-2222-3333-4444-555555555555"
			case "wrong-site":
				selection.SiteName = "Different Site"
			case "literal-site":
				selection.SiteName = "London, UK"
			}
			connection, observed, err := adengine.InternalDialDomainController(t.Context(), config, selection, portableDiscoveryDialer(wire))
			if pin == "literal-site" {
				if err != nil || connection == nil || !observed.Complete || observed.SiteName == nil || *observed.SiteName != selection.SiteName {
					t.Fatal("explicit LDAP site name was constrained as a DNS label", err)
				}
				if err = connection.Close(); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, discovery.ErrDiscoveryIdentity) || connection != nil || observed.Complete || observed.DomainGUID == nil {
				t.Fatal("well-formed identity pin was ignored", err)
			}
			wire.wait(t)
		})
	}
}

func TestPortableDiscoveryUntrustedTLSNeverSendsCredentialsOrIdentityReads(t *testing.T) {
	config, wire, _ := newPortableDiscoveryLDAP(t, "valid", admodel.TransportLDAPS)
	config.TLS.RootCAs = x509.NewCertPool()
	connection, observed, err := adengine.InternalDialDomainController(
		t.Context(),
		config,
		discovery.DomainControllerSelection{DomainDNS: "example.test"},
		portableDiscoveryDialer(wire),
	)
	if err == nil || connection != nil || observed.Complete || wire.requests.Load() != 0 || wire.attempts.Load() != 1 || wire.closes.Load() != 1 {
		t.Fatal("untrusted peer crossed credential/identity boundary")
	}
	select {
	case <-wire.done:
	case <-time.After(3 * time.Second):
		t.Fatal("untrusted owned TLS peer did not retire")
	}
}

func TestPortableDiscoverySelectionPreflightPreventsCredentialIOAndFallback(t *testing.T) {
	for _, scenario := range []string{"missing-domain", "invalid-guid", "invalid-sid", "native-backend", "wrong-spn-host", "wrong-partition", "wrong-candidate-domain"} {
		t.Run(scenario, func(t *testing.T) {
			config := kerberosContractConfig(admodel.KerberosKeytabFile)
			config.Kerberos.KeytabPath = "must-not-read-discovery.keytab"
			selection := discovery.DomainControllerSelection{DomainDNS: "example.test"}
			switch scenario {
			case "missing-domain":
				selection.DomainDNS = ""
			case "invalid-guid":
				selection.ExpectedDomainGUID = "00000000-0000-0000-0000-000000000000"
			case "invalid-sid":
				selection.ExpectedDomainSID = "S-1-5-32"
			case "native-backend":
				config.Backend = admodel.BackendNative
				config.Authentication = admodel.AuthenticationNegotiate
				config.Kerberos = nil
			case "wrong-spn-host":
				config.Kerberos.SPN = "ldap/other.example.test"
			case "wrong-partition":
				config.Partition = "DC=other,DC=test"
			case "wrong-candidate-domain":
				selection.Candidate = &discovery.DNSControllerCandidate{
					DomainDNS: "wrong.test",
					Endpoint:  admodel.Endpoint{Host: config.Endpoint.Host, Port: 389},
					Records:   []discovery.DNSSRVRecord{{Target: config.Endpoint.Host + ".", Port: 389}},
					Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
				}
			}
			// This is the normal public constructor. Every scenario is rejected
			// before any file access, DNS resolution, locator or transport action.
			connection, observed, err := ad.DialDomainController(t.Context(), config, selection)
			if err == nil || connection != nil || observed.Complete || errors.Is(err, admodel.ErrKerberosAuthentication) {
				t.Fatal("invalid selection crossed preflight", err)
			}
		})
	}
}
