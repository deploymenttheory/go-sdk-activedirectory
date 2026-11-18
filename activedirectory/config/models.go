// Package config provides the config SDK interface.
package config

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// AuthenticationMethod selects the LDAP bind mechanism.
type AuthenticationMethod = admodel.AuthenticationMethod

// AuthenticationNegotiate is the SDK's AuthenticationNegotiate.
const AuthenticationNegotiate = admodel.AuthenticationNegotiate

// AuthenticationSimple requires TLS and explicit nonempty credentials.
const AuthenticationSimple = admodel.AuthenticationSimple

// Config configures an AD DS or AD LDS connection and its partition selection.
type Config = admodel.Config

// Credentials supplies an explicit identity. Negotiate uses Username/Domain;
// Simple passes Username unchanged as the LDAP bind name and requires Domain to
// be empty. A nil Config.Credentials uses the current Windows identity only for
// Negotiate. Explicit authentication never falls back to the caller. Simple
// rejects empty passwords; Negotiate passes them to the authentication provider.
//
// Password is UTF-8 owned by the caller. Do not mutate any fields during Dial.
// The SDK creates temporary Unicode buffers, erases those buffers after bind,
// and does not retain Credentials in the returned Client. The caller remains
// responsible for clearing its own password bytes. No erasure guarantee applies
// to caller copies or storage maintained internally by Windows.
type Credentials = admodel.Credentials

// Endpoint names exactly one LDAP server. Host is a fully qualified DNS name or
// an IP address, without a URL scheme, port, or brackets. Port defaults to 389,
// or 636 for TransportLDAPS.
// A DNS name is preferable for Kerberos authentication.
type Endpoint = admodel.Endpoint

// ErrInvalidConfig is the SDK's ErrInvalidConfig.
var ErrInvalidConfig = admodel.ErrInvalidConfig

// Transport selects how the connection is protected before authentication.
type Transport = admodel.Transport

// TransportLDAP omits TLS and requires the selected authentication's SASL
// protection. Native Negotiate requests signing and sealing.
const TransportLDAP = admodel.TransportLDAP

// TransportLDAPS performs TLS when connecting to the configured port.
const TransportLDAPS = admodel.TransportLDAPS

// TransportStartTLS upgrades LDAP to TLS before sending credentials.
const TransportStartTLS = admodel.TransportStartTLS
