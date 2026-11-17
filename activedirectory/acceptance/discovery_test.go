package acceptance

import (
	"context"
	"errors"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestDiscoveryValidationPreservesIntent(t *testing.T) {
	domain := admodel.DomainName{Name: "ad.sdk.test.", Format: admodel.DomainNameDNS}
	options := admodel.DiscoveryOptions{
		Domain:                    &domain,
		SiteName:                  "London 研发 🐉",
		Services:                  admodel.ServicePrimaryDC | admodel.ServiceTime,
		Writable:                  true,
		AvoidSelf:                 true,
		ForceDiscover:             true,
		PreferReliableTimeService: true,
		MinimumVersion:            admodel.DirectoryServiceWindows2016,
	}
	got, err := admodel.InternalDiscoveryOptionsNormalized(options)
	if err != nil || got.Domain == options.Domain || *got.Domain != domain ||
		got.Services != options.Services ||
		got.SiteName != options.SiteName {
		t.Fatalf("normalization: %#v, %v", got, err)
	}
	domain.Name = "changed.test"
	if got.Domain.Name != "ad.sdk.test." {
		t.Fatal("normalized request aliases caller domain")
	}
	for _, options := range []admodel.DiscoveryOptions{
		{},
		{NextClosestSite: true},
		{Services: admodel.ServiceGlobalCatalog},
		{Services: admodel.ServiceKDC | admodel.ServiceADWS},
		{Domain: &admodel.DomainName{Name: "研发", Format: admodel.DomainNameNetBIOS}},
		{Domain: &admodel.DomainName{Name: "AD.LEGACY", Format: admodel.DomainNameNetBIOS}},
		{Domain: &admodel.DomainName{Name: "singlelabel", Format: admodel.DomainNameDNS}},
	} {
		if err := options.Validate(); err != nil {
			t.Fatalf("valid options: %v", err)
		}
	}
}

func TestDiscoveryRejectsInvalidSelectorsBeforeExecution(t *testing.T) {
	for _, options := range []admodel.DiscoveryOptions{
		{Domain: &admodel.DomainName{}},
		{Domain: &admodel.DomainName{Name: "ad.test", Format: 255}},
		{Services: admodel.ServiceGlobalCatalog | admodel.ServiceKDC},
		{Services: admodel.ServicePrimaryDC | admodel.ServiceGlobalCatalog},
		{Services: admodel.ServicePrimaryDC | admodel.ServiceKDC},
		{Services: 128},
		{MinimumVersion: 255},
		{SiteName: "site\x00suffix"},
		{SiteName: "bad\nsite"},
		{SiteName: "\xff"},
		{SiteName: strings.Repeat("x", 256)},
		{SiteName: "one", NextClosestSite: true},
		{Services: admodel.ServicePrimaryDC, NextClosestSite: true},
	} {
		_, err := admodel.DiscoverDomainController(context.Background(), options)
		if !errors.Is(err, admodel.ErrInvalidDiscovery) {
			t.Fatalf("invalid options reached native execution: %#v, %v", options, err)
		}
	}
	for _, name := range []string{"", "ad\x00.test", "\xff", "ad..test", ".ad.test", "ad test", "ldap://user:secret@ad.test", "ad.test:389", `AD\USER`} {
		options := admodel.DiscoveryOptions{Domain: &admodel.DomainName{Name: name}}
		if err := options.Validate(); !errors.Is(err, admodel.ErrInvalidDiscovery) {
			t.Fatalf("invalid domain returned %v", err)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("error exposed invalid input")
		}
	}
	for _, name := range []string{".AD", strings.Repeat("x", 16)} {
		if err := (admodel.DiscoveryOptions{Domain: &admodel.DomainName{Name: name, Format: admodel.DomainNameNetBIOS}}).Validate(); !errors.Is(
			err,
			admodel.ErrInvalidDiscovery,
		) {
			t.Fatalf("invalid NetBIOS domain returned %v", err)
		}
	}
}

func TestDiscoveryEndpointUsesControllerName(t *testing.T) {
	result := admodel.DiscoveredController{
		ControllerName:    `\\dc1.ad.sdk.test`,
		ControllerAddress: `\\10.77.23.10`,
	}
	endpoint, err := result.Endpoint()
	if err != nil || endpoint.Host != "dc1.ad.sdk.test" || endpoint.Port != 0 {
		t.Fatalf("endpoint: %#v, %v", endpoint, err)
	}
	for _, name := range []string{"", `\\dc1`, `\\10.77.23.10`, `\\dc1.ad.test:389`, `\\dc1.ad.test\other`, `ldap://user:secret@dc1.ad.test`} {
		if _, err := (admodel.DiscoveredController{ControllerName: name}).Endpoint(); !errors.Is(
			err,
			admodel.ErrInvalidNativeResult,
		) {
			t.Fatalf("invalid native hostname returned %v", err)
		}
	}
}

func TestDiscoveryCancellationAndCurrentModeArePortable(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("caller canceled discovery")
	cancel(cause)
	if _, err := admodel.DiscoverDomainController(
		ctx,
		admodel.DiscoveryOptions{},
	); !errors.Is(
		err,
		cause,
	) {
		t.Fatal(err)
	}
	if _, err := admodel.CurrentDomain(ctx, admodel.CurrentLoggedOnUser); !errors.Is(err, cause) {
		t.Fatal(err)
	}
	if _, err := admodel.CurrentDomain(
		context.Background(),
		0,
	); !errors.Is(
		err,
		admodel.ErrInvalidDiscovery,
	) {
		t.Fatal(err)
	}
}
