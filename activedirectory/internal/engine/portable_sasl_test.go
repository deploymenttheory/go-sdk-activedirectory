package engine

import (
	"errors"
	"testing"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableSASLPolicyMapsExplicitAndDefaultProtection(t *testing.T) {
	for _, transport := range []admodel.Transport{admodel.TransportLDAP, admodel.TransportLDAPS, admodel.TransportStartTLS} {
		for _, requested := range []admodel.SASLProtection{admodel.SASLProtectionDefault, admodel.SASLProtectionNone, admodel.SASLProtectionSign, admodel.SASLProtectionSeal} {
			cfg := admodel.Config{Transport: transport, Authentication: admodel.AuthenticationKerberos, SASLProtection: requested}
			actual, err := internalPortableSASLMode(cfg)
			if transport == admodel.TransportLDAP && requested == admodel.SASLProtectionNone {
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
