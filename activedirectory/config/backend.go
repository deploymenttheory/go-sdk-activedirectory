package config

import admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"

// Backend selects one implementation explicitly, with no automatic fallback.
type Backend = admodel.Backend

const (
	// BackendNative retains the Windows WinLDAP/SSPI implementation and is the default.
	BackendNative = admodel.BackendNative
	// BackendPortable selects portable LDAP; an unavailable implementation fails closed.
	BackendPortable = admodel.BackendPortable
	// AuthenticationKerberos requires Kerberos without NTLM or simple fallback.
	AuthenticationKerberos = admodel.AuthenticationKerberos
)

// KerberosCredentialSource selects one explicit password, keytab or file cache.
type KerberosCredentialSource = admodel.KerberosCredentialSource

const (
	KerberosPassword            = admodel.KerberosPassword
	KerberosKeytabFile          = admodel.KerberosKeytabFile
	KerberosCredentialCacheFile = admodel.KerberosCredentialCacheFile
)

// KerberosCredentials supplies caller-owned inputs and an explicit realm/SPN.
// Formatting and serialization redact identities, paths and credentials.
type KerberosCredentials = admodel.KerberosCredentials

// SASLProtection requests the protection of subsequent LDAP traffic, not just bind.
type SASLProtection = admodel.SASLProtection

const (
	SASLProtectionDefault = admodel.SASLProtectionDefault
	SASLProtectionNone    = admodel.SASLProtectionNone
	SASLProtectionSign    = admodel.SASLProtectionSign
	SASLProtectionSeal    = admodel.SASLProtectionSeal
)

// TLSOptions supplies optional private roots while retaining mandatory hostname,
// chain and TLS-version verification. There is no verification bypass.
type TLSOptions = admodel.TLSOptions

// BackendUnavailableError identifies an unavailable selected host mechanism.
type BackendUnavailableError = admodel.BackendUnavailableError

// ErrBackendUnavailable differs from a connected server's directory-type refusal.
var ErrBackendUnavailable = admodel.ErrBackendUnavailable
