package activedirectory

import (
	"context"
	"errors"
)

// A deliberately internal primitive: feature workflows determine which
// directory attributes may be changed and how to validate their semantics.
type ldapModifySession interface {
	directorySession
	ldapModify(context.Context, string, []ldapModification) ldapWriteAttempt
}

type ldapModification struct {
	operation uint32 // LDAP add=0, delete=1, replace=2; never permissive modify.
	attribute string
	value     []byte // LDAP UTF-8 octets, or binary attribute data.
}

type ldapWriteState uint8

const (
	ldapWriteNotAttempted ldapWriteState = iota
	ldapWriteAccepted
	ldapWriteRejected
	ldapWriteUncertain
)

type ldapWriteAttempt struct {
	State ldapWriteState
	Err   error
}

var errLDAPWriteUncertain = errors.New("LDAP write outcome is unknown; reconcile before another write")
