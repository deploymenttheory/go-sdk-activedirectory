package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
)

func TestDiscoveryInputRejectsDuplicateUnknownTrailingAndOversizedDataWithoutEcho(t *testing.T) {
	for _, input := range []string{"", `[]`, `{} {}`, `{"domain_dns":"one.test","domain_dns":"two.test"}`, `{"domain_dns":"one.test","DOMAIN_DNS":"two.test"}`, `{"password_base64":"U0VDUkVULVBSSVZBVEU=","unknown_secret":"SECRET-PRIVATE"}`, strings.Repeat("x", 128*1024+1)} {
		_, err := readRequest(strings.NewReader(input))
		if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "U0VDUkVU") {
			t.Fatal("ambiguous/invalid input accepted or private contents echoed")
		}
	}
}

func TestDiscoveryExampleRequiresExplicitSecureAuthentication(t *testing.T) {
	input := request{
		DomainDNS:      "example.test",
		Endpoint:       "dc.disjoint.test",
		Transport:      "ldaps",
		Authentication: "kerberos",
		Source:         "keytab",
		Username:       "reader",
		Realm:          "EXAMPLE.TEST",
		SPN:            "ldap/dc.disjoint.test",
		KeytabPath:     "caller-owned.keytab",
	}
	config, selection, err := requestConfig(input)
	if err != nil || config.Backend != ad.BackendPortable || config.Authentication != ad.AuthenticationKerberos || selection.DomainDNS != "example.test" {
		t.Fatal("explicit protected disjoint controller rejected", err)
	}
	for _, transport := range []string{"ldap", "insecure", ""} {
		input.Transport = transport
		if _, _, err = requestConfig(input); err == nil {
			t.Fatal("unprotected transport accepted")
		}
	}
	input.Transport = "ldap-sign"
	input.Authentication = "simple"
	input.Source = "password"
	input.KeytabPath = ""
	input.Realm = ""
	input.SPN = ""
	input.Password = []byte("owned-example-fixture")
	if _, _, err = requestConfig(input); err == nil {
		t.Fatal("simple plaintext authentication accepted")
	}
	input.Transport = "starttls"
	config, _, err = requestConfig(input)
	if err != nil || config.Authentication != ad.AuthenticationSimple {
		t.Fatal("explicit simple over verified StartTLS rejected", err)
	}
}

func TestDiscoveryReportPreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preserved-file")
	if err := os.WriteFile(path, []byte("preserved-owned-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(strings.NewReader(`{"result":"`+filepath.ToSlash(path)+`"}`), &output); err == nil {
		t.Fatal("existing report/credential file overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserved-owned-fixture" {
		t.Fatal("existing file changed")
	}
}

func TestDiscoveryBadExplicitSelectionFailsBeforeDNSAndPrivateSourceRead(t *testing.T) {
	input := request{
		DomainDNS:      "ldap://user:SECRET-PRIVATE@example.test",
		Endpoint:       "must-not-resolve.invalid",
		LookupDNS:      true,
		Transport:      "ldaps",
		Authentication: "kerberos",
		Source:         "keytab",
		Username:       "reader",
		Realm:          "EXAMPLE.TEST",
		SPN:            "ldap/must-not-resolve.invalid",
		KeytabPath:     "must-not-be-opened.keytab",
	}
	result, err := probe(context.Background(), input)
	if err == nil || result.Success || result.DNS != nil || result.Identity.Complete || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("bad identity crossed preflight or echoed private invalid input")
	}
}

func TestDiscoverySRVLDAP389AndExplicitLDAPS636RemainIndependent(t *testing.T) {
	input := request{
		DomainDNS: "example.test", Endpoint: "dc.disjoint.test:636", LookupDNS: true, DNSPort: 389,
		Transport: "ldaps", Authentication: "kerberos", Source: "keytab", Username: "reader", Realm: "EXAMPLE.TEST",
		SPN: "ldap/dc.disjoint.test", KeytabPath: "caller-owned.keytab",
	}
	config, selection, err := requestConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	dns := discovery.DNSDiscoveryResult{Complete: true, Candidates: []discovery.DNSControllerCandidate{{
		DomainDNS: input.DomainDNS, Endpoint: ad.Endpoint{Host: "dc.disjoint.test", Port: 389},
		Records: []discovery.DNSSRVRecord{{Target: "dc.disjoint.test.", Port: 389}}, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
	}}}
	candidate, err := dns.Select(ad.Endpoint{Host: config.Endpoint.Host, Port: input.DNSPort})
	if err != nil {
		t.Fatal(err)
	}
	selection.Candidate = &candidate
	if err = selection.Validate(config.Endpoint); err != nil {
		t.Fatal(err)
	}
	if config.Transport != ad.TransportLDAPS || config.Endpoint.Port != 636 || selection.Candidate.Endpoint.Port != 389 || selection.Candidate.Records[0].Port != 389 {
		t.Fatal("explicit transport port and advertised LDAP port were conflated")
	}
	if _, err = dns.Select(ad.Endpoint{Host: config.Endpoint.Host, Port: 636}); !errors.Is(err, discovery.ErrDiscoveryNoCandidates) {
		t.Fatal("LDAP SRV advertisement silently reinterpreted as LDAPS")
	}
}
