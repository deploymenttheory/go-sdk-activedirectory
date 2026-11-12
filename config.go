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
)

// ErrInvalidConfig identifies a configuration rejected before native execution.
var ErrInvalidConfig = errors.New("invalid Active Directory configuration")

// Endpoint names exactly one LDAP server. Host is a fully qualified DNS name or
// an IP address, without a URL scheme, port, or brackets. Port defaults to 389.
// A DNS name is preferable for Kerberos authentication.
type Endpoint struct {
	Host string
	Port uint16
}

// Config configures a connection using current or explicit Windows credentials.
type Config struct {
	Endpoint Endpoint

	// Credentials selects explicit Negotiate authentication. Nil uses the
	// current Windows identity. The returned Client does not retain this value.
	Credentials *Credentials `json:"-"`

	// Timeout limits individual native network waits and defaults to 30 seconds.
	// It is not a strict aggregate deadline for synchronous Negotiate: Windows
	// applies its bind timeout separately to each response round trip. Native
	// second-granularity waits round positive fractional seconds upward.
	Timeout time.Duration
}

// Validate checks configuration without loading Windows APIs or contacting a
// server. It does not prove reachability, authentication, or server capability.
func (c Config) Validate() error {
	_, err := c.normalized()
	return err
}

func (c Config) normalized() (Config, error) {
	if err := c.Credentials.validate(); err != nil {
		return Config{}, err
	}
	if !validServerHost(c.Endpoint.Host) {
		// Do not echo unvalidated input: it may be a URI containing credentials.
		return Config{}, fmt.Errorf("%w: endpoint host must name one fully qualified DNS server or IP address", ErrInvalidConfig)
	}
	if c.Endpoint.Port == 0 {
		c.Endpoint.Port = 389
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
