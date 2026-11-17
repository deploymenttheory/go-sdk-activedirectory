package model

import "context"

// Feature workflows validate identity, schema and control capabilities before
// using this internal, single-attempt native write boundary.
type InternalLdapWriteSession interface {
	InternalDirectorySession
	InternalLdapWrite(context.Context, InternalLdapWriteRequest) InternalLdapWriteAttempt
}

type InternalLdapWriteOperation uint8

const (
	InternalLdapWriteAdd InternalLdapWriteOperation = iota
	InternalLdapWriteModify
	InternalLdapWriteDelete
	InternalLdapWriteRename
)

type InternalLdapWriteRequest struct {
	InternalOperation     InternalLdapWriteOperation
	InternalDn            string
	InternalModifications []InternalLdapAttributeModification
	InternalNewRDN        string
	InternalNewParent     string // Empty retains the current parent; typed topology moves set this explicitly.
	InternalDeleteOldRDN  bool
	InternalControls      []InternalLdapWriteControl
}

type InternalLdapAttributeModification struct {
	InternalOperation uint32 // LDAP add=0, delete=1, replace=2.
	InternalAttribute string
	// Zero values clears the whole attribute only with LDAP delete. One empty
	// byte slice is an explicit zero-length value, including in legacy adapters.
	InternalValues [][]byte
}

type InternalLdapWriteControl struct {
	InternalOid      string
	InternalCritical bool
	InternalValue    []byte
}
