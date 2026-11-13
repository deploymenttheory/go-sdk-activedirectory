//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

// These valueless request controls are Go-owned and remain alive until native
// submission returns. They are never passed to a WinLDAP allocation-free API.
func (s *ldapSession) metadataBaseObject(ctx context.Context, base string, attributes, oids []string) (map[string][][]byte, error) {
	controls := make([]*ldap.LDAPControlW, len(oids)+1)
	for i, oid := range oids {
		if oid != metadataShowDeleted && oid != metadataShowDeactivated {
			return nil, ErrInvalidReplicationQuery
		}
		controls[i] = &ldap.LDAPControlW{Ldctl_oid: win32.UTF16Ptr(oid), Ldctl_iscritical: 1}
	}
	return s.baseObjectReadControls(ctx, base, attributes, controls, func(message *ldap.LDAPMessage) (map[string][][]byte, error) {
		return s.readMessageAttributes(message, func(entry *ldap.LDAPMessage) (map[string][][]byte, error) {
			return s.readAttributeProjection(entry, true, true)
		})
	})
}
