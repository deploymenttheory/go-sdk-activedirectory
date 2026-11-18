package engine

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"path/filepath"
	"testing"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type portableSASLForbiddenDialer struct{ calls int }

func (d *portableSASLForbiddenDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls++
	return nil, errors.New("unexpected network access")
}

func TestPortableSASLTLSCompatibilityRefusesBeforeCredentialAndNetworkAccess(t *testing.T) {
	for _, transport := range []admodel.Transport{admodel.TransportLDAPS, admodel.TransportStartTLS} {
		for _, layer := range []admodel.SASLProtection{admodel.SASLProtectionSign, admodel.SASLProtectionSeal} {
			for _, source := range []admodel.KerberosCredentialSource{admodel.KerberosKeytabFile, admodel.KerberosCredentialCacheFile} {
				cfg := admodel.Config{
					Backend: admodel.BackendPortable, Authentication: admodel.AuthenticationKerberos,
					Transport: transport, SASLProtection: layer, Timeout: time.Second,
					Endpoint: admodel.Endpoint{Host: "dc.ad.sdk.test"},
					Kerberos: &admodel.KerberosCredentials{Source: source, Username: "client", Realm: "AD.SDK.TEST", SPN: "ldap/dc.ad.sdk.test"},
				}
				if source == admodel.KerberosKeytabFile {
					cfg.Kerberos.KeytabPath = filepath.Join(t.TempDir(), "must-not-read.keytab")
				} else {
					cfg.Kerberos.CachePath = filepath.Join(t.TempDir(), "must-not-read.ccache")
				}
				if err := cfg.Validate(); !errors.Is(err, admodel.ErrInvalidConfig) {
					t.Fatal("public validation accepted an AD-incompatible compound traffic layer")
				}
				dialer := &portableSASLForbiddenDialer{}
				factoryCalls := 0
				factory := func(*krbclient.Client) (ldap.GSSAPIClient, func() error, error) {
					factoryCalls++
					return nil, nil, errors.New("unexpected credential mechanism construction")
				}
				session, err := internalDialPortableKerberosWithFactory(t.Context(), cfg, dialer, factory)
				if session != nil || !errors.Is(err, admodel.ErrInvalidConfig) || errors.Is(err, fs.ErrNotExist) ||
					admodel.Classify(err) != admodel.ClassInvalidRequest || dialer.calls != 0 || factoryCalls != 0 {
					t.Fatalf("AD compatibility policy accessed credentials/network or changed error identity: %v", err)
				}
			}
		}
	}
}

func TestPortableSASLPolicyMapsExplicitAndDefaultProtection(t *testing.T) {
	for _, transport := range []admodel.Transport{admodel.TransportLDAP, admodel.TransportLDAPS, admodel.TransportStartTLS} {
		for _, requested := range []admodel.SASLProtection{admodel.SASLProtectionDefault, admodel.SASLProtectionNone, admodel.SASLProtectionSign, admodel.SASLProtectionSeal} {
			cfg := admodel.Config{Transport: transport, Authentication: admodel.AuthenticationKerberos, SASLProtection: requested}
			actual, err := internalPortableSASLMode(cfg)
			if transport == admodel.TransportLDAP && requested == admodel.SASLProtectionNone ||
				transport != admodel.TransportLDAP && (requested == admodel.SASLProtectionSign || requested == admodel.SASLProtectionSeal) {
				if !errors.Is(err, admodel.ErrInvalidConfig) {
					t.Fatal("plaintext no-layer request did not fail closed")
				}
				continue
			}
			expected := ldap.SASLSecurityNone
			if requested == admodel.SASLProtectionSign {
				expected = ldap.SASLSecuritySign
			}
			if requested == admodel.SASLProtectionSeal || requested == admodel.SASLProtectionDefault && transport == admodel.TransportLDAP {
				expected = ldap.SASLSecuritySeal
			}
			if err != nil || actual != expected {
				t.Fatalf("transport=%d requested=%d mode=%d error=%v", transport, requested, actual, err)
			}
		}
	}
	for _, cfg := range []admodel.Config{
		{Transport: 255, Authentication: admodel.AuthenticationKerberos},
		{Authentication: admodel.AuthenticationSimple, SASLProtection: admodel.SASLProtectionSeal},
		{Authentication: admodel.AuthenticationKerberos, SASLProtection: 255},
	} {
		if _, err := internalPortableSASLMode(cfg); !errors.Is(err, admodel.ErrInvalidConfig) {
			t.Fatal("invalid SASL policy accepted")
		}
	}
}

func TestPortableObservedSASLMapsLibraryValuesWithoutCasts(t *testing.T) {
	for _, test := range []struct {
		vendor ldap.SASLSecurityMode
		sdk    admodel.SASLProtection
	}{{ldap.SASLSecurityNone, admodel.SASLProtectionNone}, {ldap.SASLSecuritySign, admodel.SASLProtectionSign}, {ldap.SASLSecuritySeal, admodel.SASLProtectionSeal}} {
		actual, err := internalPortableObservedSASL(test.vendor)
		if err != nil || actual != test.sdk {
			t.Fatal("observed SASL layer map changed its meaning")
		}
	}
	for _, invalid := range []ldap.SASLSecurityMode{1, 3, -1, 8} {
		if _, err := internalPortableObservedSASL(invalid); !errors.Is(err, admodel.ErrInvalidResult) {
			t.Fatal("unknown observed layer accepted")
		}
	}
}
