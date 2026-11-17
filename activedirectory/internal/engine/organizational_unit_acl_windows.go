//go:build windows && (amd64 || arm64)

package engine

import (
	"context"
	"errors"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (s *InternalLdapSession) InternalReadOUDACL(
	ctx context.Context,
	dn string,
) (admodel.Object, error) {
	return s.InternalReadDirectoryDACL(ctx, dn, nil)
}

func (s *InternalLdapSession) InternalReadDirectoryDACL(
	ctx context.Context,
	dn string,
	extra []string,
) (admodel.Object, error) {
	properties := admodel.InternalDirectoryDACLProperties(extra)
	control := ldap.LDAPControlW{
		Ldctl_oid: win32.UTF16Ptr(admodel.InternalOuSDFlagsControl),
		Ldctl_value: ldap.LDAP_BERVAL{
			Bv_len: uint32(len(admodel.InternalOuDACLControlValue)),
			Bv_val: foundation.PSTR(
				unsafe.Pointer(unsafe.SliceData(admodel.InternalOuDACLControlValue)),
			),
		},
		Ldctl_iscritical: 1,
	}
	attrs, err := s.InternalBaseObjectReadControls(
		ctx,
		dn,
		properties,
		[]*ldap.LDAPControlW{&control, nil},
		s.InternalReadMessage,
	)
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: attrs}
	actual := decoder.InternalText("distinguishedName")
	object := admodel.Object{Attributes: attrs, RequestedProperties: properties}
	if actual != nil {
		object.DistinguishedName = *actual
	}
	return object, errors.Join(err, errors.Join(decoder.InternalErrors...))
}

func (*InternalLdapSession) InternalEncodeDACL(raw []byte, aces [][]byte) ([]byte, error) {
	acl, err := admodel.InternalDecodeDirectoryDACL(raw)
	if err != nil {
		return nil, err
	}
	// Object ACEs require ACL_REVISION_DS, including when the old ACL had only
	// ordinary ACEs and therefore used ACL_REVISION.
	acl.InternalRevision = 4
	return admodel.InternalEncodeDirectoryDACL(raw, acl, aces)
}

func (s *InternalLdapSession) InternalEditOUDACL(
	raw []byte,
	mask uint32,
	protect bool,
) ([]byte, bool, error) {
	acl, err := admodel.InternalDecodeOUDACL(raw)
	if err != nil {
		return nil, false, err
	}
	aces, changed := admodel.InternalChangeOUACEs(acl, mask, protect)
	if !changed {
		return raw, false, nil
	}
	output, err := admodel.InternalEncodeDirectoryDACL(raw, acl, aces)
	return output, err == nil, err
}
