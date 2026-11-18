package acceptance

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func kerberosContractConfig(source config.KerberosCredentialSource) config.Config {
	k := &config.KerberosCredentials{
		Source: source, Username: "contract-user", Realm: "AD.SDK.TEST", SPN: "ldap/dc.ad.sdk.test",
	}
	switch source {
	case config.KerberosPassword:
		k.Password = []byte("contract-test-only")
	case config.KerberosKeytabFile:
		k.KeytabPath = "/caller-owned/absent.keytab"
	case config.KerberosCredentialCacheFile:
		k.CachePath = "/caller-owned/absent.ccache"
	}
	return config.Config{
		Backend: config.BackendPortable, Endpoint: config.Endpoint{Host: "dc.ad.sdk.test"},
		Authentication: config.AuthenticationKerberos, Kerberos: k,
		Transport: config.TransportLDAPS,
	}
}

func TestPublicKerberosContractValidatesSourcesWithoutFileAccess(t *testing.T) {
	for _, source := range []config.KerberosCredentialSource{config.KerberosPassword, config.KerberosKeytabFile, config.KerberosCredentialCacheFile} {
		options := kerberosContractConfig(source)
		if err := options.Validate(); err != nil {
			t.Fatalf("valid explicit source %d: %v", source, err)
		}
		// These files do not exist: syntax validation must neither open them nor
		// resolve an environment/default credential source.
		options.Transport = config.TransportLDAP
		options.SASLProtection = config.SASLProtectionSign
		if err := options.Validate(); err != nil {
			t.Fatalf("explicit SASL integrity contract: %v", err)
		}
	}
}

func TestKerberosContractRejectsAmbiguousOrDowngradedConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*config.Config){
		"missing source":     func(c *config.Config) { c.Kerberos.Source = 0 },
		"unknown source":     func(c *config.Config) { c.Kerberos.Source = 255 },
		"missing identity":   func(c *config.Config) { c.Kerberos.Username = "" },
		"ambiguous realm":    func(c *config.Config) { c.Kerberos.Username = "user@OTHER.TEST" },
		"missing realm":      func(c *config.Config) { c.Kerberos.Realm = "" },
		"missing SPN":        func(c *config.Config) { c.Kerberos.SPN = "" },
		"wrong SPN host":     func(c *config.Config) { c.Kerberos.SPN = "ldap/other.ad.sdk.test" },
		"wrong SPN service":  func(c *config.Config) { c.Kerberos.SPN = "cifs/dc.ad.sdk.test" },
		"missing password":   func(c *config.Config) { c.Kerberos.Password = nil },
		"two sources":        func(c *config.Config) { c.Kerberos.KeytabPath = "/must-not-open" },
		"two mechanisms":     func(c *config.Config) { c.Credentials = &config.Credentials{Username: "must-not-use"} },
		"ignored Kerberos":   func(c *config.Config) { c.Authentication = config.AuthenticationNegotiate },
		"IP endpoint":        func(c *config.Config) { c.Endpoint.Host = "192.0.2.1"; c.Kerberos.SPN = "ldap/192.0.2.1" },
		"unknown backend":    func(c *config.Config) { c.Backend = 255 },
		"unknown protection": func(c *config.Config) { c.SASLProtection = 255 },
		"plaintext no layer": func(c *config.Config) {
			c.Transport = config.TransportLDAP
			c.SASLProtection = config.SASLProtectionNone
		},
		"ignored TLS trust": func(c *config.Config) { c.Transport = config.TransportLDAP; c.TLS = &config.TLSOptions{} },
	} {
		t.Run(name, func(t *testing.T) {
			options := kerberosContractConfig(config.KerberosPassword)
			mutate(&options)
			err := options.Validate()
			if !errors.Is(err, config.ErrInvalidConfig) || ad.Classify(err) != ad.ClassInvalidRequest {
				t.Fatalf("unsafe configuration accepted or misclassified: %v", err)
			}
			if strings.Contains(err.Error(), "contract-test-only") || strings.Contains(err.Error(), "must-not") {
				t.Fatal("configuration error exposed credential input")
			}
		})
	}
	for _, source := range []config.KerberosCredentialSource{config.KerberosKeytabFile, config.KerberosCredentialCacheFile} {
		options := kerberosContractConfig(source)
		options.Kerberos.Password = []byte{}
		if !errors.Is(options.Validate(), config.ErrInvalidConfig) {
			t.Fatal("file source silently ignored an additional password")
		}
	}
}

func TestUnimplementedBackendCannotFallBackToNativeOrAnotherAuthentication(t *testing.T) {
	portable := kerberosContractConfig(config.KerberosPassword)
	nativeKerberos := portable
	nativeKerberos.Backend = config.BackendNative
	simple := config.Config{
		Backend: config.BackendPortable, Endpoint: config.Endpoint{Host: "must-not-resolve.ad.sdk.test"},
		Transport: config.TransportLDAPS, Authentication: config.AuthenticationSimple,
		Credentials: &config.Credentials{Username: "must-not-send", Password: []byte("contract-test-only")},
	}
	nativeCustomTrust := simple
	nativeCustomTrust.Backend, nativeCustomTrust.TLS = config.BackendNative, &config.TLSOptions{}
	portableNegotiate := config.Config{Backend: config.BackendPortable, Endpoint: config.Endpoint{Host: "must-not-resolve.ad.sdk.test"}}
	for _, options := range []config.Config{portable, nativeKerberos, nativeCustomTrust, portableNegotiate} {
		client, err := ad.Dial(t.Context(), options)
		var unavailable *config.BackendUnavailableError
		if client != nil || !errors.Is(err, config.ErrBackendUnavailable) || !errors.Is(err, ad.ErrUnsupported) ||
			!errors.As(err, &unavailable) || errors.Is(err, ad.ErrUnsupportedDirectory) || ad.Classify(err) != ad.ClassUnsupported {
			t.Fatalf("backend did not fail closed with a distinct cause: client=%v, err=%v", client, err)
		}
		if unavailable.Backend != options.Backend || unavailable.Authentication != options.Authentication {
			t.Fatalf("wrong selected backend/mechanism: %+v", unavailable)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ad.Dial(ctx, portable); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled Dial: %v", err)
	}
}

func TestPrivateTrustIsClonedBeforeBackendRetention(t *testing.T) {
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{Raw: []byte("first"), RawSubject: []byte("first-subject")})
	options := kerberosContractConfig(config.KerberosPassword)
	options.TLS = &config.TLSOptions{RootCAs: roots}
	normalized, err := admodel.InternalConfigNormalized(options)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.TLS == options.TLS || normalized.TLS.RootCAs == roots || !normalized.TLS.RootCAs.Equal(roots) {
		t.Fatal("backend retained caller-owned mutable trust inputs")
	}
	roots.AddCert(&x509.Certificate{Raw: []byte("second"), RawSubject: []byte("second-subject")})
	if normalized.TLS.RootCAs.Equal(roots) {
		t.Fatal("caller trust mutation altered the backend trust snapshot")
	}
}

func TestProtectionCancellationCannotLeaveCompleteObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	client := adengine.InternalNewClient(admodel.Config{Timeout: time.Second}, protectionContractSession{
		InternalTestSession: InternalTestSession{InternalFinish: func() error { return nil }},
		observe: func(context.Context) (shared.SessionProtection, error) {
			cancel()
			return shared.SessionProtection{CipherBits: 256, Complete: true}, nil
		},
	})
	t.Cleanup(func() { _ = client.Close() })
	result, err := client.Protection(ctx)
	if !errors.Is(err, context.Canceled) || result.Complete || result.CipherBits != 256 {
		t.Fatalf("cancelled observation became a guarantee: %+v, %v", result, err)
	}
}

func TestKerberosCredentialsRedactIdentityFilesAndSecret(t *testing.T) {
	options := kerberosContractConfig(config.KerberosPassword)
	k := options.Kerberos
	k.KeytabPath, k.CachePath = "/secret-keytab", "/secret-cache"
	encoded, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	text, err := encoding.TextMarshaler(*k).MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("test", "credentials", k)
	slog.New(slog.NewJSONHandler(&log, nil)).Info("test", "configuration", options)
	slog.New(slog.NewTextHandler(&log, nil)).Info("test", "configuration", options)
	for _, output := range []string{fmt.Sprint(k), fmt.Sprintf("%+v %#v", k, k), string(encoded), string(text), log.String(), fmt.Sprintf("%+v %#v", options, options)} {
		for _, secret := range []string{k.Username, k.Realm, k.SPN, string(k.Password), k.KeytabPath, k.CachePath} {
			if strings.Contains(output, secret) {
				t.Fatalf("ordinary logging exposed credentials: %s", output)
			}
		}
	}
}

type protectionContractSession struct {
	InternalTestSession
	observe func(context.Context) (shared.SessionProtection, error)
}

func (s protectionContractSession) InternalSessionProtection(ctx context.Context) (shared.SessionProtection, error) {
	return s.observe(ctx)
}

func TestProtectionObservationsPreserveMeasuredAndPartialFacts(t *testing.T) {
	for _, observationErr := range []error{nil, ad.ErrTLSNegotiation} {
		session := protectionContractSession{
			InternalTestSession: InternalTestSession{InternalFinish: func() error { return nil }},
			observe: func(ctx context.Context) (shared.SessionProtection, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("observation bypassed the bounded shared gate")
				}
				return shared.SessionProtection{Backend: config.BackendPortable, TLSVersion: 0x0304, CipherBits: 256, Complete: true}, observationErr
			},
		}
		options := kerberosContractConfig(config.KerberosPassword)
		options.Timeout = time.Second
		client := adengine.InternalNewClient(options, session)
		retained := adengine.InternalClientConfig(client)
		if retained.Credentials != nil || retained.Kerberos != nil || retained.TLS != nil {
			t.Fatal("client retained caller credential/trust inputs")
		}
		result, err := client.Protection(t.Context())
		if !errors.Is(err, observationErr) || result.TLSVersion != 0x0304 || result.CipherBits != 256 || result.Complete != (observationErr == nil) {
			t.Fatalf("observed facts lost or manufactured: %+v, %v", result, err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Protection(t.Context()); !errors.Is(err, ad.ErrClosed) {
			t.Fatalf("closed protection observer: %v", err)
		}
	}
}

func TestProtectionDoesNotInventGuaranteesFromConfiguration(t *testing.T) {
	options := kerberosContractConfig(config.KerberosPassword)
	options.Timeout = time.Second
	client := adengine.InternalNewClient(options, InternalTestSession{InternalFinish: func() error { return nil }})
	t.Cleanup(func() { _ = client.Close() })
	observed, err := client.Protection(t.Context())
	if !errors.Is(err, config.ErrBackendUnavailable) || observed.Complete || observed.TLSVerified || observed.ChannelBound {
		t.Fatalf("configuration became invented security evidence: %+v, %v", observed, err)
	}
	partialClient := adengine.InternalNewClient(options, protectionContractSession{
		InternalTestSession: InternalTestSession{InternalFinish: func() error { return nil }},
		observe: func(context.Context) (shared.SessionProtection, error) {
			return shared.SessionProtection{CipherBits: 128}, nil
		},
	})
	t.Cleanup(func() { _ = partialClient.Close() })
	partial, err := partialClient.Protection(t.Context())
	if !errors.Is(err, admodel.ErrIncompleteResult) || partial.Complete || partial.CipherBits != 128 {
		t.Fatalf("incomplete protection accepted: %+v, %v", partial, err)
	}
	var composed *ad.Client
	if _, err := composed.Protection(t.Context()); !errors.Is(err, ad.ErrClosed) {
		t.Fatalf("nil composed observer: %v", err)
	}
}
