package activedirectory

import (
	"encoding/binary"
	"slices"
	"testing"
)

func ouTestACE(kind, flags byte, mask uint32) []byte {
	ace := []byte{kind, flags, 20, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	return ace
}
func ouTestDescriptor(aces ...[]byte) []byte {
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
	combined := ouTestACE(1, 0, ouObjectProtectionMask|2)
	inherited := ouTestACE(1, 0x10, ouObjectProtectionMask)
	unknown := []byte{0x42, 0, 8, 0, 1, 2, 3, 4}
	allow := ouTestACE(0, 0, 0x20000)
	raw := ouTestDescriptor(combined, inherited, unknown, allow)
	acl, err := decodeOUDACL(raw)
	if err != nil {
		t.Fatal(err)
	}
	aces, changed := changeOUACEs(acl, ouObjectProtectionMask, false)
	if !changed || len(aces) != 4 || binary.LittleEndian.Uint32(aces[0][4:8]) != 2 {
		t.Fatal("unrelated deny rights changed", aces)
	}
	for i, want := range [][]byte{inherited, unknown, allow} {
		if !slices.Equal(aces[i+1], want) {
			t.Fatal("opaque/inherited rule changed", i)
		}
	}
	if !slices.Equal(raw, ouTestDescriptor(combined, inherited, unknown, allow)) {
		t.Fatal("input was mutated")
	}
}
func TestOUACLProtectionPatternsAndIdempotence(t *testing.T) {
	allow := ouTestACE(0, 0, 0x20000)
	acl, err := decodeOUDACL(ouTestDescriptor(allow))
	if err != nil {
		t.Fatal(err)
	}
	aces, changed := changeOUACEs(acl, ouObjectProtectionMask, true)
	if !changed || len(aces) != 2 || !slices.Equal(aces[1], allow) {
		t.Fatal(aces)
	}
	acl.aces = aces
	state := ouACLProtection(acl, ouObjectProtectionMask)
	if state == nil || !*state {
		t.Fatal("new deny not observed")
	}
	if _, changed := changeOUACEs(acl, ouObjectProtectionMask, true); changed {
		t.Fatal("repeated enable changed ACL")
	}
	acl.aces = [][]byte{ouTestACE(1, 0, 0x10000), ouTestACE(1, 0, 0x40)}
	if state := ouACLProtection(acl, ouObjectProtectionMask); state == nil || *state {
		t.Fatal("split deny rules became reference protection")
	}
}
func TestOUACLBoundsRejectTruncationAndNullDACL(t *testing.T) {
	raw := ouTestDescriptor(ouTestACE(1, 0, ouObjectProtectionMask))
	for length := 0; length < len(raw); length++ {
		if _, err := decodeOUDACL(raw[:length]); err == nil {
			t.Fatal("accepted truncation", length)
		}
	}
	for _, offset := range []uint32{1, 19, 21, 0xffffffff} {
		bad := slices.Clone(raw)
		binary.LittleEndian.PutUint32(bad[16:20], offset)
		if _, err := decodeOUDACL(bad); err == nil {
			t.Fatal("accepted invalid offset", offset)
		}
	}
	null := slices.Clone(raw[:20])
	binary.LittleEndian.PutUint32(null[16:20], 0)
	if _, err := decodeOUDACL(null); err == nil {
		t.Fatal("NULL allow-all DACL accepted for editing")
	}
	for _, ace := range [][]byte{{1, 0, 4, 0}, {6, 0, 12, 0, 0, 0, 0, 0, 1, 0, 0, 0}} {
		if _, err := decodeOUDACL(ouTestDescriptor(ace)); err == nil {
			t.Fatal("accepted known ACE with out-of-bounds SID", ace)
		}
	}
	badSID := ouTestACE(1, 0, ouObjectProtectionMask)
	badSID[9] = 15
	if _, err := decodeOUDACL(ouTestDescriptor(badSID)); err == nil {
		t.Fatal("accepted SID extending beyond its ACE")
	}
}
