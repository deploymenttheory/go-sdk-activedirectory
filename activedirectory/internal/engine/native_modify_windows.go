//go:build windows && (amd64 || arm64)

package engine

import (
	"context"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalLdapModifyFunc func(*ldap.LDAP, string, **ldap.LDAPModW, **ldap.LDAPControlW, **ldap.LDAPControlW, *uint32) uint32

func (s *InternalLdapSession) InternalLdapModify(
	ctx context.Context,
	dn string,
	modifications []admodel.InternalLdapModification,
) admodel.InternalLdapWriteAttempt {
	return s.InternalLdapModifyWith(ctx, dn, modifications, ldap.Ldap_modify_extW)
}

func (s *InternalLdapSession) InternalLdapModifyWith(
	ctx context.Context,
	dn string,
	modifications []admodel.InternalLdapModification,
	modify InternalLdapModifyFunc,
) admodel.InternalLdapWriteAttempt {
	request := admodel.InternalLdapWriteRequest{
		InternalOperation: admodel.InternalLdapWriteModify,
		InternalDn:        dn,
		InternalModifications: make(
			[]admodel.InternalLdapAttributeModification,
			len(modifications),
		),
	}
	for i, modification := range modifications {
		// The legacy primitive always supplies exactly one berval. A nil value
		// remains a zero-length value; it never becomes a whole-attribute clear.
		request.InternalModifications[i] = admodel.InternalLdapAttributeModification{
			InternalOperation: modification.InternalOperation,
			InternalAttribute: modification.InternalAttribute,
			InternalValues:    [][]byte{modification.InternalValue},
		}
	}
	api := InternalSystemLDAPWriteAPI()
	api.InternalModify = modify
	// Existing feature workflows own validation of the legacy primitive.
	return s.InternalSubmitLDAPWrite(ctx, request, api)
}
