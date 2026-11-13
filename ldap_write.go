package activedirectory

import "context"

// Feature workflows validate identity, schema and control capabilities before
// using this internal, single-attempt native write boundary.
type ldapWriteSession interface {
	directorySession
	ldapWrite(context.Context, ldapWriteRequest) ldapWriteAttempt
}

type ldapWriteOperation uint8

const (
	ldapWriteAdd ldapWriteOperation = iota
	ldapWriteModify
	ldapWriteDelete
	ldapWriteRename
)

type ldapWriteRequest struct {
	operation     ldapWriteOperation
	dn            string
	modifications []ldapAttributeModification
	newRDN        string
	newParent     string // Empty retains the current parent; typed topology moves set this explicitly.
	deleteOldRDN  bool
	controls      []ldapWriteControl
}

type ldapAttributeModification struct {
	operation uint32 // LDAP add=0, delete=1, replace=2.
	attribute string
	// Zero values clears the whole attribute only with LDAP delete. One empty
	// byte slice is an explicit zero-length value, including in legacy adapters.
	values [][]byte
}

type ldapWriteControl struct {
	oid      string
	critical bool
	value    []byte
}
