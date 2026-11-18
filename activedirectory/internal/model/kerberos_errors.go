package model

import (
	"errors"
	"fmt"
)

// ErrKerberosAuthentication identifies an unsuccessful explicit Kerberos
// authentication. It does not assert an LDAP status or authorize a retry.
var ErrKerberosAuthentication = errors.New("explicit Kerberos authentication failed")

// ErrKerberosExpired identifies a ticket/context outside its actual lifetime.
var ErrKerberosExpired = errors.New("kerberos ticket or context has expired or is not yet valid")

// KerberosError preserves a Kerberos protocol code separately from LDAP status.
// Code is zero when no valid KRB-ERROR was received. Diagnostics and credential
// identities are deliberately excluded from ordinary formatting.
type KerberosError struct {
	Code  int32
	cause error
}

// InternalKerberosError constructs an error without exposing library diagnostics.
func InternalKerberosError(code int32, cause error) *KerberosError {
	return &KerberosError{Code: code, cause: cause}
}

func (e *KerberosError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("explicit Kerberos authentication failed (Kerberos code %d)", e.Code)
	}
	return ErrKerberosAuthentication.Error()
}

func (e *KerberosError) GoString() string { return e.Error() }

func (e *KerberosError) Unwrap() []error { return []error{ErrKerberosAuthentication, e.cause} }
