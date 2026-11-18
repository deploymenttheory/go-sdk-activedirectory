// Package secureauth supplies the shared protected connection options used by
// the executable examples. It never reads passwords from arguments or ambient
// credentials for the portable backend.
package secureauth

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adclient "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
)

type options struct {
	backend   string
	transport string
	source    string
	username  string
	realm     string
	keytab    string
	cache     string
	caFile    string
}

func register(flags *flag.FlagSet) *options {
	var values options
	flags.StringVar(&values.backend, "auth-backend", "portable", "portable, or explicitly native for Windows-only APIs")
	flags.StringVar(&values.transport, "auth-transport", "ldaps", "ldaps, starttls, ldap-sign or ldap-seal; protection is required")
	flags.StringVar(&values.source, "auth-source", "keytab", "portable Kerberos credential source: keytab or cache")
	flags.StringVar(&values.username, "auth-user", "", "explicit Kerberos account name (no password)")
	flags.StringVar(&values.realm, "auth-realm", "", "explicit Kerberos realm")
	flags.StringVar(&values.keytab, "auth-keytab", "", "caller-owned Kerberos keytab path")
	flags.StringVar(&values.cache, "auth-cache", "", "caller-owned Kerberos FILE-cache path")
	flags.StringVar(&values.caFile, "auth-ca", "", "optional PEM CA file for portable verified TLS; otherwise system trust")
	return &values
}

var defaults = register(flag.CommandLine)

func (o options) config(endpoint ad.Endpoint) (ad.Config, error) {
	c := ad.Config{Endpoint: endpoint, Transport: ad.TransportLDAPS}
	switch o.transport {
	case "ldaps":
	case "starttls":
		c.Transport = ad.TransportStartTLS
	case "ldap-sign":
		c.Transport, c.SASLProtection = ad.TransportLDAP, ad.SASLProtectionSign
	case "ldap-seal":
		c.Transport, c.SASLProtection = ad.TransportLDAP, ad.SASLProtectionSeal
	default:
		return ad.Config{}, errors.New("auth-transport must select ldaps, starttls, ldap-sign or ldap-seal")
	}
	switch o.backend {
	case "portable":
		c.Backend, c.Authentication = ad.BackendPortable, ad.AuthenticationKerberos
		k := &ad.KerberosCredentials{Username: o.username, Realm: o.realm, SPN: "ldap/" + endpoint.Host}
		switch o.source {
		case "keytab":
			if o.keytab == "" || o.cache != "" {
				return ad.Config{}, errors.New("keytab authentication requires auth-keytab and no auth-cache")
			}
			k.Source, k.KeytabPath = ad.KerberosKeytabFile, o.keytab
		case "cache":
			if o.cache == "" || o.keytab != "" {
				return ad.Config{}, errors.New("cache authentication requires auth-cache and no auth-keytab")
			}
			k.Source, k.CachePath = ad.KerberosCredentialCacheFile, o.cache
		default:
			return ad.Config{}, errors.New("auth-source must be keytab or cache; password examples use bounded redirected stdin")
		}
		c.Kerberos = k
	case "native":
		if o.transport != "ldaps" && o.transport != "starttls" {
			return ad.Config{}, errors.New("native examples require verified ldaps or starttls")
		}
		if o.username != "" || o.realm != "" || o.keytab != "" || o.cache != "" || o.source != "keytab" || o.caFile != "" {
			return ad.Config{}, errors.New("native examples use the current Windows identity and system certificate trust; omit portable credential options")
		}
		c.Backend, c.Authentication = ad.BackendNative, ad.AuthenticationNegotiate
	default:
		return ad.Config{}, errors.New("auth-backend must be portable or explicitly native")
	}
	if o.caFile != "" {
		if c.Transport == ad.TransportLDAP {
			return ad.Config{}, errors.New("auth-ca applies only to verified TLS transports")
		}
		pem, err := os.ReadFile(o.caFile)
		if err != nil {
			return ad.Config{}, fmt.Errorf("read explicit example CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return ad.Config{}, errors.New("auth-ca has no PEM certificate")
		}
		c.TLS = &ad.TLSOptions{RootCAs: roots}
	}
	return c, c.Validate()
}

// Config selects explicit Kerberos credentials and required transport protection.
// The native option explicitly selects protected Windows integrated authentication.
func Config(endpoint ad.Endpoint) (ad.Config, error) {
	return defaults.config(endpoint)
}

// Dial opens an example session using the shared protected authentication flags.
func Dial(ctx context.Context, server string) (*ad.Client, error) {
	c, err := Config(ad.Endpoint{Host: server})
	if err != nil {
		return nil, err
	}
	return ad.Dial(ctx, c)
}

// GlobalCatalog opens the protected GC port appropriate to the selected transport.
func GlobalCatalog(ctx context.Context, server string) (*adclient.Client, error) {
	port := uint16(3268)
	if defaults.transport == "ldaps" {
		port = 3269
	}
	c, err := Config(ad.Endpoint{Host: server, Port: port})
	if err != nil {
		return nil, err
	}
	return adclient.Dial(ctx, c)
}
