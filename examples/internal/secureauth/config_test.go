package secureauth

import (
	"flag"
	"strings"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
)

func parseOptions(t *testing.T, arguments ...string) *options {
	t.Helper()
	flags := flag.NewFlagSet("secure-example", flag.ContinueOnError)
	values := register(flags)
	if err := flags.Parse(arguments); err != nil {
		t.Fatal(err)
	}
	return values
}

func TestDefaultRequiresExplicitKerberosCredentials(t *testing.T) {
	values := parseOptions(t)
	if _, err := values.config(ad.Endpoint{Host: "dc1.example.test"}); err == nil {
		t.Fatal("default example accepted ambient authentication")
	}
	values = parseOptions(t, "-auth-user", "automation", "-auth-realm", "EXAMPLE.TEST", "-auth-keytab", "/run/secrets/automation.keytab")
	c, err := values.config(ad.Endpoint{Host: "dc1.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Backend != ad.BackendPortable || c.Authentication != ad.AuthenticationKerberos || c.Transport != ad.TransportLDAPS ||
		c.Kerberos.Source != ad.KerberosKeytabFile || c.Credentials != nil || c.Kerberos.SPN != "ldap/dc1.example.test" {
		t.Fatalf("default protection/identity was weakened: %+v", c)
	}
	other, err := values.config(ad.Endpoint{Host: "dc2.example.test", Port: 3269})
	if err != nil || other.Kerberos.SPN != "ldap/dc2.example.test" || other.Endpoint.Port != 3269 {
		t.Fatal("second endpoint reused the first service identity or lost its protected port", err)
	}
}

func TestProtectedProfilesAndCache(t *testing.T) {
	for _, profile := range []struct {
		name      string
		transport ad.Transport
		sasl      ad.SASLProtection
	}{
		{"ldaps", ad.TransportLDAPS, ad.SASLProtectionDefault},
		{"starttls", ad.TransportStartTLS, ad.SASLProtectionDefault},
		{"ldap-sign", ad.TransportLDAP, ad.SASLProtectionSign},
		{"ldap-seal", ad.TransportLDAP, ad.SASLProtectionSeal},
	} {
		t.Run(profile.name, func(t *testing.T) {
			values := parseOptions(t, "-auth-transport", profile.name, "-auth-source", "cache", "-auth-cache", "/run/secrets/client.ccache",
				"-auth-user", "automation", "-auth-realm", "EXAMPLE.TEST")
			c, err := values.config(ad.Endpoint{Host: "dc1.example.test"})
			if err != nil {
				t.Fatal(err)
			}
			if c.Transport != profile.transport || c.SASLProtection != profile.sasl || c.Kerberos.Source != ad.KerberosCredentialCacheFile {
				t.Fatal("profile did not require the selected protection and cache")
			}
		})
	}
}

func TestUnsafeOrAmbiguousAuthenticationRefused(t *testing.T) {
	for _, arguments := range [][]string{
		{"-auth-transport", "ldap"},
		{"-auth-transport", "none"},
		{"-auth-backend", "auto"},
		{"-auth-source", "password"},
		{"-auth-source", "simple"},
		{"-auth-source", "cache", "-auth-cache", "cache", "-auth-keytab", "keytab"},
		{"-auth-source", "keytab", "-auth-keytab", "keytab", "-auth-cache", "cache"},
		{"-auth-keytab", "keytab"}, // explicit principal and realm are still required
		{"-auth-backend", "native", "-auth-transport", "ldap-seal"},
		{"-auth-backend", "native", "-auth-cache", "cache"},
		{"-auth-backend", "native", "-auth-ca", "ca.pem"},
	} {
		t.Run(strings.Join(arguments, " "), func(t *testing.T) {
			if _, err := parseOptions(t, arguments...).config(ad.Endpoint{Host: "dc1.example.test"}); err == nil {
				t.Fatal("accepted an insecure, ambiguous or incomplete authentication request")
			}
		})
	}
}

func TestNativeRequiresExplicitChoiceAndVerifiedTLS(t *testing.T) {
	for _, transport := range []string{"ldaps", "starttls"} {
		c, err := parseOptions(t, "-auth-backend", "native", "-auth-transport", transport).config(ad.Endpoint{Host: "dc1.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		if c.Backend != ad.BackendNative || c.Authentication != ad.AuthenticationNegotiate || c.Transport == ad.TransportLDAP || c.Credentials != nil || c.Kerberos != nil {
			t.Fatal("native route lost explicit selection, TLS or current-identity semantics")
		}
	}
}
