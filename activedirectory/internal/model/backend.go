package model

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
)

// Backend selects an implementation, not a host OS or server capability.
type Backend uint8

const (
	// BackendNative preserves the Windows WinLDAP/SSPI implementation.
	BackendNative Backend = iota
	// BackendPortable selects the portable LDAP implementation explicitly.
	BackendPortable
)

func (b Backend) String() string {
	switch b {
	case BackendNative:
		return "native"
	case BackendPortable:
		return "portable"
	default:
		return "unknown"
	}
}

func (a AuthenticationMethod) String() string {
	switch a {
	case AuthenticationNegotiate:
		return "negotiate"
	case AuthenticationSimple:
		return "simple"
	case AuthenticationKerberos:
		return "kerberos"
	default:
		return "unknown"
	}
}

// SASLProtection selects the protection of subsequent LDAP messages. A
// successful bind does not establish that the requested layer was negotiated.
type SASLProtection uint8

const (
	// SASLProtectionDefault preserves native behavior. Portable Kerberos requires
	// sealing without TLS and may use the verified TLS channel without a SASL layer.
	SASLProtectionDefault SASLProtection = iota
	SASLProtectionNone
	SASLProtectionSign
	SASLProtectionSeal
)

// TLSOptions supplies private certificate trust without weakening verification.
// RootCAs nil uses system roots. Callers must not mutate it during Dial; a backend
// must clone it before retention. TLS 1.2 or later and endpoint-name verification
// are mandatory. There is deliberately no insecure verification option.
type TLSOptions struct {
	RootCAs *x509.CertPool `json:"-"`
}

// ErrBackendUnavailable identifies an unavailable backend or host mechanism,
// separately from ErrUnsupportedDirectory on the connected server.
var ErrBackendUnavailable = errors.New("selected directory backend or authentication mechanism is unavailable")

// BackendUnavailableError identifies a refused implementation feature without
// exposing credentials, file paths or protocol diagnostics.
type BackendUnavailableError struct {
	Backend        Backend
	Authentication AuthenticationMethod
	Feature        string
}

func (e *BackendUnavailableError) Error() string {
	return fmt.Sprintf("%s backend cannot provide %s with %s authentication", e.Backend, e.Feature, e.Authentication)
}

func (e *BackendUnavailableError) Unwrap() error { return ErrBackendUnavailable }

// Is preserves the broad legacy unsupported match; callers should check the
// precise backend and directory sentinels before ErrUnsupported.
func (e *BackendUnavailableError) Is(target error) bool { return target == ErrUnsupported }

// SessionProtection contains measured connection facts, never credentials or
// tickets. Complete is false on partial/unavailable observations. Zero fields
// must not be interpreted as a security guarantee. TLS and SASL describe
// independent protection layers; authentication alone establishes neither.
type SessionProtection struct {
	Backend              Backend
	Authentication       AuthenticationMethod
	Transport            Transport
	TLSVerified          bool
	TLSVersion           uint16
	TLSCipherSuite       uint16
	CipherBits           uint32
	SASLProtection       SASLProtection
	MutualAuthentication bool
	ChannelBound         bool
	Delegated            bool
	Complete             bool
}

// InternalSessionProtectionObserver is optional: missing observations must be
// refused, never synthesized from Config or a successful bind.
type InternalSessionProtectionObserver interface {
	InternalSessionProtection(context.Context) (SessionProtection, error)
}
