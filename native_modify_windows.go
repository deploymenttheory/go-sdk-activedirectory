//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

type ldapModifyFunc func(*ldap.LDAP, string, **ldap.LDAPModW, **ldap.LDAPControlW, **ldap.LDAPControlW, *uint32) uint32

func (s *ldapSession) ldapModify(ctx context.Context, dn string, modifications []ldapModification) ldapWriteAttempt {
	return s.ldapModifyWith(ctx, dn, modifications, ldap.Ldap_modify_extW)
}

func (s *ldapSession) ldapModifyWith(ctx context.Context, dn string, modifications []ldapModification, modify ldapModifyFunc) ldapWriteAttempt {
	request := ldapWriteRequest{operation: ldapWriteModify, dn: dn, modifications: make([]ldapAttributeModification, len(modifications))}
	for i, modification := range modifications {
		// The legacy primitive always supplies exactly one berval. A nil value
		// remains a zero-length value; it never becomes a whole-attribute clear.
		request.modifications[i] = ldapAttributeModification{operation: modification.operation, attribute: modification.attribute, values: [][]byte{modification.value}}
	}
	api := systemLDAPWriteAPI()
	api.modify = modify
	// Existing feature workflows own validation of the legacy primitive.
	return s.submitLDAPWrite(ctx, request, api)
}
