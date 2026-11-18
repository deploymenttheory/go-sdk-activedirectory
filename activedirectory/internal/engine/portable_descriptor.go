package engine

import (
	"context"
	"slices"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

// InternalReadDirectoryDACL reads the GUID/DN-bound object with the critical
// LDAP SD-flags control selecting only its DACL. Returned owner/group/SACL
// omission is an unloaded section, never evidence of directory absence.
func (s *InternalPortableSession) InternalReadDirectoryDACL(ctx context.Context, dn string, extra []string) (admodel.Object, error) {
	properties := admodel.InternalDirectoryDACLProperties(extra)
	controls := []admodel.InternalLdapWriteControl{{
		InternalOid: admodel.InternalDirectorySDFlagsControl, InternalCritical: true,
		InternalValue: slices.Clone(admodel.InternalDirectoryDACLControlValue),
	}}
	object, err := s.internalReadBaseObject(ctx, dn, properties, false, controls)
	object.RequestedProperties = properties
	object.SecurityDescriptorSections = 4
	return object, err
}

// InternalReadOUDACL uses the same explicit DACL-only read contract for OU workflows.
func (s *InternalPortableSession) InternalReadOUDACL(ctx context.Context, dn string) (admodel.Object, error) {
	return s.InternalReadDirectoryDACL(ctx, dn, nil)
}

// InternalEncodeDACL preserves all descriptor sections while replacing only the
// supplied DACL ACE sequence. It does not canonicalize or discard opaque ACEs.
func (*InternalPortableSession) InternalEncodeDACL(raw []byte, aces [][]byte) ([]byte, error) {
	acl, err := admodel.InternalDecodeDirectoryDACL(raw)
	if err != nil {
		return nil, err
	}
	return admodel.InternalEncodeDirectoryDACL(raw, acl, aces)
}

// InternalEditOUDACL changes only recognized explicit OU protection ACEs.
func (s *InternalPortableSession) InternalEditOUDACL(raw []byte, mask uint32, protect bool) ([]byte, bool, error) {
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

// InternalNewDirectoryDescriptor compiles complete directory attribute values
// through the portable codec, without a native helper or ambient SID resolution.
func (*InternalPortableSession) InternalNewDirectoryDescriptor(sddl string) ([]byte, error) {
	return conditions.DescriptorBytes(sddl)
}
