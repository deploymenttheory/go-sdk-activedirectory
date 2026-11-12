// Package activedirectory provides native Windows Active Directory operations.
// Configuration can be constructed and validated on any Go platform. Native
// execution requires Windows amd64 or arm64.
package activedirectory

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrInvalidConfig identifies a configuration rejected before native execution.
var ErrInvalidConfig = errors.New("invalid Active Directory configuration")

// Endpoint names exactly one LDAP server. Host is a fully qualified DNS name or
// an IP address, without a URL scheme, port, or brackets. Port defaults to 389,
// or 636 for TransportLDAPS.
// A DNS name is preferable for Kerberos authentication.
type Endpoint struct {
	Host string
	Port uint16
}

// Transport selects how the connection is protected before authentication.
type Transport uint8

const (
	// TransportLDAP uses signed and sealed Negotiate without TLS.
	TransportLDAP Transport = iota
	// TransportLDAPS performs TLS when connecting to the configured port.
	TransportLDAPS
	// TransportStartTLS upgrades LDAP to TLS before sending credentials.
	TransportStartTLS
)

// AuthenticationMethod selects the LDAP bind mechanism.
type AuthenticationMethod uint8

const (
	AuthenticationNegotiate AuthenticationMethod = iota
	// AuthenticationSimple requires TLS and explicit nonempty credentials.
	AuthenticationSimple
)

// Config configures an AD DS or AD LDS connection and its partition selection.
type Config struct {
	Endpoint       Endpoint
	Transport      Transport
	Authentication AuthenticationMethod

	// Partition names an explicit naming context. Empty selects the server's
	// default naming context when resolving a partition, if one is advertised.
	Partition string

	// Credentials selects an explicit identity. Nil uses the current Windows
	// identity with Negotiate. Simple uses Username as the LDAP bind name,
	// requires an empty Domain, and rejects empty Password. Client does not
	// retain this value.
	Credentials *Credentials `json:"-"`

	// Timeout limits individual native network waits and defaults to 30 seconds.
	// It is not a strict aggregate deadline for synchronous Negotiate: Windows
	// applies its bind timeout separately to each response round trip. Native
	// second-granularity waits round positive fractional seconds upward.
	// StartTLS has a native default wait of approximately 30 seconds and cannot
	// be interrupted by context cancellation. Certificate retrieval can add waits.
	Timeout time.Duration
}

// Validate checks configuration without loading Windows APIs or contacting a
// server. It does not prove reachability, authentication, or server capability.
func (c Config) Validate() error {
	_, err := c.normalized()
	return err
}

func (c Config) normalized() (Config, error) {
	if c.Transport > TransportStartTLS || c.Authentication > AuthenticationSimple {
		return Config{}, fmt.Errorf("%w: unknown transport or authentication method", ErrInvalidConfig)
	}
	if c.Authentication == AuthenticationSimple {
		if c.Transport == TransportLDAP {
			return Config{}, fmt.Errorf("%w: simple authentication requires TLS", ErrInvalidConfig)
		}
		if c.Credentials == nil || c.Credentials.Domain != "" || len(c.Credentials.Password) == 0 {
			return Config{}, fmt.Errorf("%w: simple authentication requires explicit credentials, an empty domain, and a nonempty password", ErrInvalidConfig)
		}
	}
	if err := c.Credentials.validate(); err != nil {
		return Config{}, err
	}
	if !utf8.ValidString(c.Partition) || strings.ContainsRune(c.Partition, 0) {
		return Config{}, fmt.Errorf("%w: partition must be valid UTF-8 without NUL", ErrInvalidConfig)
	}
	if !validServerHost(c.Endpoint.Host) {
		// Do not echo unvalidated input: it may be a URI containing credentials.
		return Config{}, fmt.Errorf("%w: endpoint host must name one fully qualified DNS server or IP address", ErrInvalidConfig)
	}
	if c.Endpoint.Port == 0 {
		c.Endpoint.Port = 389
		if c.Transport == TransportLDAPS {
			c.Endpoint.Port = 636
		}
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Timeout < 0 || c.Timeout > time.Duration(math.MaxInt32)*time.Second {
		return Config{}, fmt.Errorf("%w: timeout must fit a positive native signed 32-bit seconds value", ErrInvalidConfig)
	}
	return c, nil
}

func validServerHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	name := strings.TrimSuffix(host, ".")
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if ch != '-' && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
				return false
			}
		}
	}
	return true
}
