package activedirectory

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDiscoveryValidationPreservesIntent(t *testing.T) {
	domain := DomainName{Name: "ad.sdk.test.", Format: DomainNameDNS}
	options := DiscoveryOptions{Domain: &domain, SiteName: "London 研发 🐉", Services: ServicePrimaryDC | ServiceTime,
		Writable: true, AvoidSelf: true, ForceDiscover: true, PreferReliableTimeService: true, MinimumVersion: DirectoryServiceWindows2016}
	got, err := options.normalized()
	if err != nil || got.Domain == options.Domain || *got.Domain != domain || got.Services != options.Services || got.SiteName != options.SiteName {
		t.Fatalf("normalization: %#v, %v", got, err)
	}
	domain.Name = "changed.test"
	if got.Domain.Name != "ad.sdk.test." {
		t.Fatal("normalized request aliases caller domain")
	}
	for _, options := range []DiscoveryOptions{
		{}, {NextClosestSite: true}, {Services: ServiceGlobalCatalog}, {Services: ServiceKDC | ServiceADWS},
		{Domain: &DomainName{Name: "研发", Format: DomainNameNetBIOS}},
		{Domain: &DomainName{Name: "AD.LEGACY", Format: DomainNameNetBIOS}},
		{Domain: &DomainName{Name: "singlelabel", Format: DomainNameDNS}},
	} {
		if err := options.Validate(); err != nil {
			t.Fatalf("valid options: %v", err)
		}
	}
}

func TestDiscoveryRejectsInvalidSelectorsBeforeExecution(t *testing.T) {
	for _, options := range []DiscoveryOptions{
		{Domain: &DomainName{}}, {Domain: &DomainName{Name: "ad.test", Format: 255}},
		{Services: ServiceGlobalCatalog | ServiceKDC}, {Services: ServicePrimaryDC | ServiceGlobalCatalog},
		{Services: ServicePrimaryDC | ServiceKDC}, {Services: 128}, {MinimumVersion: 255},
		{SiteName: "site\x00suffix"}, {SiteName: "bad\nsite"}, {SiteName: "\xff"},
		{SiteName: strings.Repeat("x", 256)}, {SiteName: "one", NextClosestSite: true},
		{Services: ServicePrimaryDC, NextClosestSite: true},
	} {
		_, err := DiscoverDomainController(context.Background(), options)
		if !errors.Is(err, ErrInvalidDiscovery) {
			t.Fatalf("invalid options reached native execution: %#v, %v", options, err)
		}
	}
	for _, name := range []string{"", "ad\x00.test", "\xff", "ad..test", ".ad.test", "ad test", "ldap://user:secret@ad.test", "ad.test:389", `AD\USER`} {
		options := DiscoveryOptions{Domain: &DomainName{Name: name}}
		if err := options.Validate(); !errors.Is(err, ErrInvalidDiscovery) {
			t.Fatalf("invalid domain returned %v", err)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("error exposed invalid input")
		}
	}
	for _, name := range []string{".AD", strings.Repeat("x", 16)} {
		if err := (DiscoveryOptions{Domain: &DomainName{Name: name, Format: DomainNameNetBIOS}}).Validate(); !errors.Is(err, ErrInvalidDiscovery) {
			t.Fatalf("invalid NetBIOS domain returned %v", err)
		}
	}
}

func TestDiscoveryEndpointUsesControllerName(t *testing.T) {
	result := DiscoveredController{ControllerName: `\\dc1.ad.sdk.test`, ControllerAddress: `\\10.77.23.10`}
	endpoint, err := result.Endpoint()
	if err != nil || endpoint.Host != "dc1.ad.sdk.test" || endpoint.Port != 0 {
		t.Fatalf("endpoint: %#v, %v", endpoint, err)
	}
	for _, name := range []string{"", `\\dc1`, `\\10.77.23.10`, `\\dc1.ad.test:389`, `\\dc1.ad.test\other`, `ldap://user:secret@dc1.ad.test`} {
		if _, err := (DiscoveredController{ControllerName: name}).Endpoint(); !errors.Is(err, ErrInvalidNativeResult) {
			t.Fatalf("invalid native hostname returned %v", err)
		}
	}
}

func TestDiscoveryCancellationAndCurrentModeArePortable(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("caller canceled discovery")
	cancel(cause)
	if _, err := DiscoverDomainController(ctx, DiscoveryOptions{}); !errors.Is(err, cause) {
		t.Fatal(err)
	}
	if _, err := CurrentDomain(ctx, CurrentLoggedOnUser); !errors.Is(err, cause) {
		t.Fatal(err)
	}
	if _, err := CurrentDomain(context.Background(), 0); !errors.Is(err, ErrInvalidDiscovery) {
		t.Fatal(err)
	}
}
