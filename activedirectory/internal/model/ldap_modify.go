package model

import (
	"context"
	"errors"
)

// A deliberately internal primitive: feature workflows determine which
// directory attributes may be changed and how to validate their semantics.
type InternalLdapModifySession interface {
	InternalDirectorySession
	InternalLdapModify(context.Context, string, []InternalLdapModification) InternalLdapWriteAttempt
}

type InternalLdapModification struct {
	InternalOperation uint32 // LDAP add=0, delete=1, replace=2; never permissive modify.
	InternalAttribute string
	InternalValue     []byte // LDAP UTF-8 octets, or binary attribute data.
}

type InternalLdapWriteState uint8

const (
	InternalLdapWriteNotAttempted InternalLdapWriteState = iota
	InternalLdapWriteAccepted
	InternalLdapWriteRejected
	InternalLdapWriteUncertain
)

type InternalLdapWriteAttempt struct {
	State InternalLdapWriteState
	Err   error
}

var errLDAPWriteUncertain = errors.New(
	"LDAP write outcome is unknown; reconcile before another write",
)

// InternalLDAPWriteUncertainError returns the shared internal write-outcome sentinel.
func InternalLDAPWriteUncertainError() error { return errLDAPWriteUncertain }
