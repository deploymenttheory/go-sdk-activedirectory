//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
)

func (s *ldapSession) readOUDACL(ctx context.Context, dn string) (Object, error) {
	properties := []string{"distinguishedName", "objectGUID", "nTSecurityDescriptor", "sdRightsEffective", "instanceType", "isDeleted"}
	control := ldap.LDAPControlW{Ldctl_oid: win32.UTF16Ptr(ouSDFlagsControl), Ldctl_value: ldap.LDAP_BERVAL{Bv_len: uint32(len(ouDACLControlValue)), Bv_val: foundation.PSTR(unsafe.Pointer(unsafe.SliceData(ouDACLControlValue)))}, Ldctl_iscritical: 1}
	attrs, err := s.baseObjectReadControls(ctx, dn, properties, []*ldap.LDAPControlW{&control, nil}, s.readMessage)
	decoder := rootDSEDecoder{attributes: attrs}
	actual := decoder.text("distinguishedName")
	object := Object{Attributes: attrs, RequestedProperties: properties}
	if actual != nil {
		object.DistinguishedName = *actual
	}
	return object, errors.Join(err, errors.Join(decoder.errors...))
}

func (s *ldapSession) editOUDACL(raw []byte, mask uint32, protect bool) ([]byte, bool, error) {
	acl, err := decodeOUDACL(raw)
	if err != nil {
		return nil, false, err
	}
	aces, changed := changeOUACEs(acl, mask, protect)
	if !changed {
		return raw, false, nil
	}
	output, err := encodeDirectoryDACL(raw, acl, aces)
	return output, err == nil, err
}

// encodeDirectoryDACL rebuilds only the DACL while copying each supplied ACE as
// opaque bytes. Policies decide which ACEs to add/remove before this boundary.
func encodeDirectoryDACL(raw []byte, acl ouDACL, aces [][]byte) ([]byte, error) {
	for _, proc := range []*win32.Proc{security.Procs.IsValidSecurityDescriptor, security.Procs.InitializeAcl, security.Procs.AddAce, security.Procs.InitializeSecurityDescriptor, security.Procs.SetSecurityDescriptorDacl, security.Procs.SetSecurityDescriptorControl, security.Procs.MakeSelfRelativeSD} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	// decodeOUDACL bounded every referenced SID, ACL and ACE first.
	var pins runtime.Pinner
	defer pins.Unpin()
	pins.Pin(unsafe.SliceData(raw))
	if !security.IsValidSecurityDescriptor(security.PSECURITY_DESCRIPTOR(uintptr(unsafe.Pointer(unsafe.SliceData(raw))))) {
		return nil, ErrInvalidResult
	}
	runtime.KeepAlive(raw)
	length := 8
	for _, ace := range aces {
		length += len(ace)
	}
	if length > math.MaxUint16 {
		return nil, ErrIncompleteResult
	}
	buffer := make([]byte, length)
	pins.Pin(unsafe.SliceData(buffer))
	nativeACL := (*security.ACL)(unsafe.Pointer(unsafe.SliceData(buffer)))
	revision := security.ACE_REVISION(acl.revision)
	if err := security.InitializeAcl(nativeACL, uint32(length), revision); err != nil {
		return nil, fmt.Errorf("InitializeAcl: %w", err)
	}
	for _, ace := range aces {
		if err := security.AddAce(nativeACL, revision, math.MaxUint32, ace); err != nil {
			return nil, fmt.Errorf("AddAce: %w", err)
		}
	}
	var descriptor security.SECURITY_DESCRIPTOR
	pins.Pin(&descriptor)
	pointer := security.PSECURITY_DESCRIPTOR(uintptr(unsafe.Pointer(&descriptor)))
	if err := security.InitializeSecurityDescriptor(pointer, 1); err != nil {
		return nil, fmt.Errorf("InitializeSecurityDescriptor: %w", err)
	}
	if err := security.SetSecurityDescriptorDacl(pointer, true, nativeACL, acl.control&8 != 0); err != nil {
		return nil, fmt.Errorf("SetSecurityDescriptorDacl: %w", err)
	}
	const daclControl security.SECURITY_DESCRIPTOR_CONTROL = 0x1500
	if err := security.SetSecurityDescriptorControl(pointer, daclControl, security.SECURITY_DESCRIPTOR_CONTROL(acl.control)&daclControl); err != nil {
		return nil, fmt.Errorf("SetSecurityDescriptorControl: %w", err)
	}
	// Only the DACL is written, using the critical LDAP SD-flags control.
	// Owner, group and SACL are deliberately outside that update's scope.
	output := make([]byte, 20+length)
	pins.Pin(unsafe.SliceData(output))
	size := uint32(len(output))
	err := security.MakeSelfRelativeSD(pointer, security.PSECURITY_DESCRIPTOR(uintptr(unsafe.Pointer(unsafe.SliceData(output)))), &size)
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(buffer)
	runtime.KeepAlive(aces)
	if err != nil {
		return nil, fmt.Errorf("MakeSelfRelativeSD: %w", err)
	}
	if size > uint32(len(output)) {
		return nil, ErrInvalidResult
	}
	return output[:size], nil
}
