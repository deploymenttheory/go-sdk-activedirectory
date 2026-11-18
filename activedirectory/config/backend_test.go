package config_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// An external consumer imports only public packages and can declare all inputs,
// handle precise backend errors, and consume protection without Win32 imports.
func TestPublicPortableConsumer(t *testing.T) {
	password := []byte("public-contract-test-only")
	options := config.Config{
		Backend: config.BackendPortable, Endpoint: config.Endpoint{Host: "dc.ad.sdk.test"},
		Transport: config.TransportStartTLS, Authentication: config.AuthenticationKerberos,
		Kerberos: &config.KerberosCredentials{
			Source: config.KerberosPassword, Username: "test-user", Realm: "AD.SDK.TEST",
			SPN: "ldap/dc.ad.sdk.test", Password: password,
		},
		TLS: &config.TLSOptions{RootCAs: x509.NewCertPool()},
	}
	if err := options.Validate(); err != nil {
		t.Fatal(err)
	}
	connection, err := client.Dial(t.Context(), options)
	var unavailable *shared.BackendUnavailableError
	if connection != nil || !errors.Is(err, ad.ErrBackendUnavailable) ||
		!errors.As(err, &unavailable) || errors.Is(err, ad.ErrUnsupportedDirectory) {
		t.Fatalf("public backend selection did not fail closed: %v", err)
	}
	if string(password) != "public-contract-test-only" {
		t.Fatal("SDK modified caller-owned password bytes")
	}
	var composed *ad.Client
	var protection shared.SessionProtection
	protection, err = composed.Protection(context.Background())
	if !errors.Is(err, ad.ErrClosed) || protection.Complete {
		t.Fatalf("public protection contract: %+v, %v", protection, err)
	}
}
