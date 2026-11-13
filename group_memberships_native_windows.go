//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func (s *ldapSession) groupMemberBaseObject(ctx context.Context, base string, attributes []string, ttl bool) (map[string][][]byte, error) {
	if !ttl {
		return s.rangedBaseObject(ctx, base, attributes)
	}
	controls := []*ldap.LDAPControlW{{Ldctl_oid: win32.UTF16Ptr(groupLinkTTL), Ldctl_iscritical: 1}, nil}
	return s.baseObjectReadControls(ctx, base, attributes, controls, func(message *ldap.LDAPMessage) (map[string][][]byte, error) {
		return s.readMessageAttributes(message, func(entry *ldap.LDAPMessage) (map[string][][]byte, error) {
			return s.readAttributeProjection(entry, true, true)
		})
	})
}
