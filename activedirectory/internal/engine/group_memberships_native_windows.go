//go:build windows && (amd64 || arm64)

package engine

import (
	"context"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (s *InternalLdapSession) InternalGroupMemberBaseObject(
	ctx context.Context,
	base string,
	attributes []string,
	ttl bool,
) (map[string][][]byte, error) {
	if !ttl {
		return s.InternalRangedBaseObject(ctx, base, attributes)
	}
	controls := []*ldap.LDAPControlW{
		{Ldctl_oid: win32.UTF16Ptr(admodel.InternalGroupLinkTTL), Ldctl_iscritical: 1},
		nil,
	}
	return s.InternalBaseObjectReadControls(
		ctx,
		base,
		attributes,
		controls,
		func(message *ldap.LDAPMessage) (map[string][][]byte, error) {
			return s.InternalReadMessageAttributes(
				message,
				func(entry *ldap.LDAPMessage) (map[string][][]byte, error) {
					return s.InternalReadAttributeProjection(entry, true, true)
				},
			)
		},
	)
}
