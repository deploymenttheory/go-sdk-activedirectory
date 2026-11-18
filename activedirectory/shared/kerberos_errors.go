package shared

import admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"

// KerberosError preserves a protocol code without inventing an LDAP status.
type KerberosError = admodel.KerberosError

var (
	ErrKerberosAuthentication = admodel.ErrKerberosAuthentication
	ErrKerberosExpired        = admodel.ErrKerberosExpired
)
