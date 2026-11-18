package activedirectory

import (
	"context"

	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// Backend selects exactly one implementation with no automatic fallback.
type Backend = config.Backend

const (
	BackendNative               = config.BackendNative
	BackendPortable             = config.BackendPortable
	AuthenticationKerberos      = config.AuthenticationKerberos
	KerberosPassword            = config.KerberosPassword
	KerberosKeytabFile          = config.KerberosKeytabFile
	KerberosCredentialCacheFile = config.KerberosCredentialCacheFile
	SASLProtectionDefault       = config.SASLProtectionDefault
	SASLProtectionNone          = config.SASLProtectionNone
	SASLProtectionSign          = config.SASLProtectionSign
	SASLProtectionSeal          = config.SASLProtectionSeal
)

type KerberosCredentialSource = config.KerberosCredentialSource

// KerberosCredentials contains one redacted, caller-owned credential source.
type KerberosCredentials = config.KerberosCredentials

// SASLProtection selects protection for subsequent LDAP messages.
type SASLProtection = config.SASLProtection

// TLSOptions supplies optional private roots with mandatory verification.
type TLSOptions = config.TLSOptions

// BackendUnavailableError identifies a selected implementation/host refusal.
type BackendUnavailableError = shared.BackendUnavailableError

var ErrBackendUnavailable = shared.ErrBackendUnavailable

// SessionProtection contains measured facts, not requested security settings.
type SessionProtection = shared.SessionProtection

// Protection observes the shared session's actual protection. An unavailable
// observer fails explicitly; partial values never establish a security guarantee.
func (c *Client) Protection(ctx context.Context) (SessionProtection, error) {
	if c == nil {
		return SessionProtection{}, ErrClosed
	}
	return c.directory.Protection(ctx)
}
