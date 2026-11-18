package model

import (
	"errors"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

// InternalEncodeDirectoryDACL edits only the DACL in an owned, bounded portable
// descriptor. Unloaded sections of a DACL-only LDAP read are never synthesized;
// nTSecurityDescriptor callers must keep the critical DACL-only write control.
func InternalEncodeDirectoryDACL(raw []byte, acl InternalDirectoryDACL, aces [][]byte) ([]byte, error) {
	descriptor, err := conditions.ParseDescriptor(raw)
	if err != nil {
		return nil, errors.Join(ErrInvalidResult, err)
	}
	current := descriptor.DACL()
	if !current.Present || current.Null {
		return nil, errDirectoryDACL
	}
	current.Revision, current.ACEs = acl.InternalRevision, aces
	edited, err := descriptor.WithDACL(current)
	if err != nil {
		return nil, errors.Join(ErrInvalidResult, err)
	}
	return edited.MarshalBinary()
}
