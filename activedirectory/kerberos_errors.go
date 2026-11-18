package activedirectory

import "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"

// KerberosError preserves a protocol code without inventing an LDAP status.
type KerberosError = shared.KerberosError

var (
	ErrKerberosAuthentication = shared.ErrKerberosAuthentication
	ErrKerberosExpired        = shared.ErrKerberosExpired
)
