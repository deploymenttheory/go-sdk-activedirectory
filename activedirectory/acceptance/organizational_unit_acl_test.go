package acceptance

import (
	"encoding/binary"
	"slices"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalOuTestACE(kind, flags byte, mask uint32) []byte {
	ace := []byte{kind, flags, 20, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	return ace
}

func InternalOuTestDescriptor(aces ...[]byte) []byte {
	length := 28
	for _, ace := range aces {
		length += len(ace)
	}
	raw := make([]byte, length)
	raw[0] = 1
	binary.LittleEndian.PutUint16(raw[2:4], 0x9404)
	binary.LittleEndian.PutUint32(raw[16:20], 20)
	raw[20] = 4
	binary.LittleEndian.PutUint16(raw[22:24], uint16(length-20))
	binary.LittleEndian.PutUint16(raw[24:26], uint16(len(aces)))
	at := 28
	for _, ace := range aces {
		copy(raw[at:], ace)
		at += len(ace)
	}
	return raw
}

func TestOUACLUnprotectPreservesInheritedUnknownAndOtherRights(t *testing.T) {
	combined := InternalOuTestACE(1, 0, admodel.InternalOuObjectProtectionMask|2)
	inherited := InternalOuTestACE(1, 0x10, admodel.InternalOuObjectProtectionMask)
	unknown := []byte{0x42, 0, 8, 0, 1, 2, 3, 4}
	allow := InternalOuTestACE(0, 0, 0x20000)
	raw := InternalOuTestDescriptor(combined, inherited, unknown, allow)
	acl, err := admodel.InternalDecodeOUDACL(raw)
	if err != nil {
		t.Fatal(err)
	}
	aces, changed := admodel.InternalChangeOUACEs(
		acl,
		admodel.InternalOuObjectProtectionMask,
		false,
	)
	if !changed || len(aces) != 4 || binary.LittleEndian.Uint32(aces[0][4:8]) != 2 {
		t.Fatal("unrelated deny rights changed", aces)
	}
	for i, want := range [][]byte{inherited, unknown, allow} {
		if !slices.Equal(aces[i+1], want) {
			t.Fatal("opaque/inherited rule changed", i)
		}
	}
	if !slices.Equal(raw, InternalOuTestDescriptor(combined, inherited, unknown, allow)) {
		t.Fatal("input was mutated")
	}
}

func TestOUACLProtectionPatternsAndIdempotence(t *testing.T) {
	allow := InternalOuTestACE(0, 0, 0x20000)
	acl, err := admodel.InternalDecodeOUDACL(InternalOuTestDescriptor(allow))
	if err != nil {
		t.Fatal(err)
	}
	aces, changed := admodel.InternalChangeOUACEs(acl, admodel.InternalOuObjectProtectionMask, true)
	if !changed || len(aces) != 2 || !slices.Equal(aces[1], allow) {
		t.Fatal(aces)
	}
	acl.InternalAces = aces
	state := admodel.InternalOuACLProtection(acl, admodel.InternalOuObjectProtectionMask)
	if state == nil || !*state {
		t.Fatal("new deny not observed")
	}
	if _, changed := admodel.InternalChangeOUACEs(
		acl,
		admodel.InternalOuObjectProtectionMask,
		true,
	); changed {
		t.Fatal("repeated enable changed ACL")
	}
	acl.InternalAces = [][]byte{InternalOuTestACE(1, 0, 0x10000), InternalOuTestACE(1, 0, 0x40)}
	if state := admodel.InternalOuACLProtection(
		acl,
		admodel.InternalOuObjectProtectionMask,
	); state == nil ||
		*state {
		t.Fatal("split deny rules became reference protection")
	}
}

func TestOUACLBoundsRejectTruncationAndNullDACL(t *testing.T) {
	raw := InternalOuTestDescriptor(InternalOuTestACE(1, 0, admodel.InternalOuObjectProtectionMask))
	for length := 0; length < len(raw); length++ {
		if _, err := admodel.InternalDecodeOUDACL(raw[:length]); err == nil {
			t.Fatal("accepted truncation", length)
		}
	}
	for _, offset := range []uint32{1, 19, 21, 0xffffffff} {
		bad := slices.Clone(raw)
		binary.LittleEndian.PutUint32(bad[16:20], offset)
		if _, err := admodel.InternalDecodeOUDACL(bad); err == nil {
			t.Fatal("accepted invalid offset", offset)
		}
	}
	null := slices.Clone(raw[:20])
	binary.LittleEndian.PutUint32(null[16:20], 0)
	if _, err := admodel.InternalDecodeOUDACL(null); err == nil {
		t.Fatal("NULL allow-all DACL accepted for editing")
	}
	for _, ace := range [][]byte{{1, 0, 4, 0}, {6, 0, 12, 0, 0, 0, 0, 0, 1, 0, 0, 0}} {
		if _, err := admodel.InternalDecodeOUDACL(InternalOuTestDescriptor(ace)); err == nil {
			t.Fatal("accepted known ACE with out-of-bounds SID", ace)
		}
	}
	badSID := InternalOuTestACE(1, 0, admodel.InternalOuObjectProtectionMask)
	badSID[9] = 15
	if _, err := admodel.InternalDecodeOUDACL(InternalOuTestDescriptor(badSID)); err == nil {
		t.Fatal("accepted SID extending beyond its ACE")
	}
}
