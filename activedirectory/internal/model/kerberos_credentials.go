package model

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// KerberosCredentialSource selects exactly one caller-supplied credential source.
// There is no ambient cache, environment-variable or current-user fallback.
type KerberosCredentialSource uint8

const (
	KerberosPassword KerberosCredentialSource = iota + 1
	KerberosKeytabFile
	KerberosCredentialCacheFile
)

// KerberosCredentials supplies an explicit client identity, realm and LDAP
// service principal (ldap/<endpoint-FQDN>). Username is the client principal's
// name without its realm suffix. Password, KeytabPath and CachePath are mutually
// exclusive and selected by Source. File sources name ordinary caller-owned
// files; Validate performs no file access and proves neither validity nor expiry.
//
// Callers own input bytes and files and must not mutate them during Dial. Client
// never retains this structure; a backend may retain derived security-context
// keys until Close for SASL. Clearing caller bytes cannot erase compiler/runtime
// copies or third-party library allocations. The SDK never writes credentials to
// a cache, logs them, or silently changes sources after a failure.
type KerberosCredentials struct {
	Source     KerberosCredentialSource
	Username   string
	Realm      string
	SPN        string
	Password   []byte `json:"-"`
	KeytabPath string `json:"-"`
	CachePath  string `json:"-"`
}

func (KerberosCredentials) String() string   { return "KerberosCredentials{redacted}" }
func (KerberosCredentials) GoString() string { return "KerberosCredentials{redacted}" }

// Format redacts fields for every formatting verb, including numeric verbs.
func (KerberosCredentials) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("KerberosCredentials{redacted}"))
}

// MarshalJSON excludes identities, paths and secret material from serialization.
func (KerberosCredentials) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// MarshalText excludes identities, paths and secret material from serialization.
func (KerberosCredentials) MarshalText() ([]byte, error) {
	return []byte("KerberosCredentials{redacted}"), nil
}

// LogValue prevents structured logging from reflecting credential fields.
func (KerberosCredentials) LogValue() slog.Value {
	return slog.StringValue("KerberosCredentials{redacted}")
}

func InternalKerberosCredentialsValidate(k *KerberosCredentials, endpoint Endpoint) error {
	if k == nil || !InternalAuthText(k.Username) || strings.Contains(k.Username, "@") ||
		!InternalValidServerHost(k.Realm) || !strings.HasPrefix(k.SPN, "ldap/") ||
		!strings.EqualFold(strings.TrimPrefix(k.SPN, "ldap/"), strings.TrimSuffix(endpoint.Host, ".")) {
		return fmt.Errorf("%w: Kerberos requires an explicit username, realm and ldap/endpoint-FQDN service identity", ErrInvalidConfig)
	}
	if _, err := netip.ParseAddr(endpoint.Host); err == nil {
		return fmt.Errorf("%w: Kerberos requires a DNS endpoint", ErrInvalidConfig)
	}
	if _, err := netip.ParseAddr(k.Realm); err == nil {
		return fmt.Errorf("%w: Kerberos realm must be a DNS realm", ErrInvalidConfig)
	}
	switch k.Source {
	case KerberosPassword:
		if k.KeytabPath != "" || k.CachePath != "" || len(k.Password) == 0 {
			return fmt.Errorf("%w: Kerberos password source requires only a nonempty password", ErrInvalidConfig)
		}
		return InternalCredentialsValidate(&Credentials{Username: k.Username, Password: k.Password})
	case KerberosKeytabFile:
		if !InternalAuthText(k.KeytabPath) || k.CachePath != "" || k.Password != nil {
			return fmt.Errorf("%w: Kerberos keytab source requires only an explicit file path", ErrInvalidConfig)
		}
	case KerberosCredentialCacheFile:
		if !InternalAuthText(k.CachePath) || k.KeytabPath != "" || k.Password != nil {
			return fmt.Errorf("%w: Kerberos cache source requires only an explicit file path", ErrInvalidConfig)
		}
	default:
		return fmt.Errorf("%w: an explicit Kerberos credential source is required", ErrInvalidConfig)
	}
	return nil
}

func InternalAuthText(value string) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
