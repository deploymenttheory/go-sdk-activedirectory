package model

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

const (
	InternalOuObjectProtectionMask  uint32 = 0x10040
	InternalOuParentProtectionMask  uint32 = 2
	InternalDirectorySDFlagsControl        = "1.2.840.113556.1.4.801"
	InternalOuSDFlagsControl               = InternalDirectorySDFlagsControl
)

var (
	InternalDirectoryDACLControlValue = []byte{0x30, 3, 2, 1, 4}
	InternalOuDACLControlValue        = InternalDirectoryDACLControlValue
)

var errDirectoryDACL = errors.New("directory descriptor has no editable DACL")

type InternalDirectoryDACL struct {
	InternalControl  uint16
	InternalRevision byte
	InternalAces     [][]byte
}

type InternalOuDACL = InternalDirectoryDACL

func InternalDirectoryDACLProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"distinguishedName",
		"objectGUID",
		"nTSecurityDescriptor",
		"sdRightsEffective",
		"instanceType",
		"isDeleted",
	)
}

func InternalDecodeOUDACL(raw []byte) (InternalOuDACL, error) {
	acl, err := InternalDecodeDirectoryDACL(raw)
	if errors.Is(err, errDirectoryDACL) {
		err = errors.Join(ErrOUProtection, err)
	}
	return acl, err
}

// InternalDecodeDirectoryDACL shares the bounded portable descriptor codec.
// Retain opaque ACEs; an absent or NULL DACL is not an editable empty DACL.
func InternalDecodeDirectoryDACL(raw []byte) (InternalDirectoryDACL, error) {
	var result InternalDirectoryDACL
	descriptor, err := conditions.ParseDescriptor(raw)
	if err != nil {
		return result, errors.Join(ErrInvalidResult, err)
	}
	acl := descriptor.DACL()
	if !acl.Present || acl.Null {
		return result, errDirectoryDACL
	}
	result.InternalControl = descriptor.Control()
	result.InternalRevision, result.InternalAces = acl.Revision, acl.ACEs
	return result, nil
}

func InternalOuWorldACE(ace []byte) bool {
	return len(ace) == 20 && bytes.Equal(ace[8:], []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
}

// ouACLObjectScopedACE reports an allow/deny ACE that carries an explicit
// ObjectType, so it grants or denies rights on one property, property set or
// child class rather than on the object as a whole.
//
// Such an ACE cannot be the blanket rule this protection property is about: the
// reference writes and removes a plain non-object ACE, and reads the property
// back by looking for it. So an object-scoped ACE is skipped rather than
// treated as making the DACL unreadable.
//
// The ObjectType flag is required, not assumed from the ACE type. An object ACE
// without ACE_OBJECT_TYPE_PRESENT applies to every property, which makes it
// exactly as decisive as a plain ACE, so skipping that one would be a
// loosening. Callback ACEs are still refused: their applicability depends on a
// condition this package does not evaluate, so they are genuinely unknown.
func InternalOuACLObjectScopedACE(ace []byte) bool {
	if ace[0] != 5 && ace[0] != 6 {
		return false
	}
	if len(ace) < 12 {
		return false
	}
	const aceObjectTypePresent = 1
	return binary.LittleEndian.Uint32(ace[8:12])&aceObjectTypePresent != 0
}

// Match the reference's ordered ordinary ACE pattern. Unknown and callback
// rules before a decisive ordinary rule remain unknown, rather than being
// interpreted as effective access. Inherited rights are never edited.
//
// Object-scoped rules are skipped. A server returns a DACL in storage order
// rather than canonical order, and a newly created object's DACL commonly
// begins with the object ACEs its class's default descriptor supplies — so
// refusing to look past them left this property unreadable on ordinary objects.
// Note that a canonicalizing reader, such as .NET's CommonSecurityDescriptor,
// reorders plain ACEs to the front and hides this.
func InternalOuACLProtection(acl InternalOuDACL, mask uint32) *bool {
	for _, ace := range acl.InternalAces {
		if InternalOuACLObjectScopedACE(ace) {
			continue
		}
		if ace[0] != 0 && ace[0] != 1 {
			return nil
		}
		if len(ace) < 8 {
			return nil
		}
		rights := binary.LittleEndian.Uint32(ace[4:8])
		if ace[0] == 0 && rights&mask != 0 {
			value := false
			return &value
		}
		if ace[0] == 1 && ace[1]&0x0f == 0 && InternalOuWorldACE(ace) && rights&mask == mask {
			value := true
			return &value
		}
	}
	value := false
	return &value
}

func InternalChangeOUACEs(acl InternalOuDACL, mask uint32, protect bool) ([][]byte, bool) {
	if protect {
		if state := InternalOuACLProtection(acl, mask); state != nil && *state {
			return acl.InternalAces, false
		}
		ace := []byte{1, 0, 20, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(ace[4:8], mask)
		return append([][]byte{ace}, acl.InternalAces...), true
	}
	changed := false
	aces := make([][]byte, 0, len(acl.InternalAces))
	for _, ace := range acl.InternalAces {
		if ace[0] != 1 || ace[1] != 0 || !InternalOuWorldACE(ace) {
			aces = append(aces, ace)
			continue
		}
		rights := binary.LittleEndian.Uint32(ace[4:8])
		if rights&mask == 0 {
			aces = append(aces, ace)
			continue
		}
		changed = true
		if remaining := rights &^ mask; remaining != 0 {
			copy := slices.Clone(ace)
			binary.LittleEndian.PutUint32(copy[4:8], remaining)
			aces = append(aces, copy)
		}
	}
	return aces, changed
}
