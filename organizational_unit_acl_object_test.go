package activedirectory

import (
	"encoding/binary"
	"slices"
	"testing"
)

// ouTestObjectACE builds an ACCESS_ALLOWED_OBJECT_ACE / ACCESS_DENIED_OBJECT_ACE
// in the shape a real directory returns. The live DACL of a newly created
// organizational unit begins with several of these, from its class's default
// security descriptor:
//
//	type=5 flags=0x00 size=44 rights=0x00000003
//
// Layout: 4-byte header, 4-byte access mask, 4-byte object flags, a 16-byte
// ObjectType when ACE_OBJECT_TYPE_PRESENT is set, a 16-byte
// InheritedObjectType when ACE_INHERITED_OBJECT_TYPE_PRESENT is set, then the
// SID. The SID here is S-1-5-32-544, which is 16 bytes, giving the 44-byte
// total the directory actually returns.
func ouTestObjectACE(kind, headerFlags byte, mask, objectFlags uint32) []byte {
	ace := []byte{kind, headerFlags, 0, 0}
	ace = append(ace, 0, 0, 0, 0) // access mask
	ace = append(ace, 0, 0, 0, 0) // object flags
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	binary.LittleEndian.PutUint32(ace[8:12], objectFlags)
	if objectFlags&1 != 0 {
		ace = append(ace, make([]byte, 16)...) // ObjectType
	}
	if objectFlags&2 != 0 {
		ace = append(ace, make([]byte, 16)...) // InheritedObjectType
	}
	// S-1-5-32-544, the shape the live ACEs carry.
	ace = append(ace, 1, 2, 0, 0, 0, 0, 0, 5, 20, 0, 0, 0, 32, 2, 0, 0)
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	return ace
}

// This is the regression for issue #146. A directory returns a DACL in storage
// order, not canonical order, and a newly created object's DACL begins with the
// object ACEs its class default descriptor supplies. Refusing to look past them
// made the protection property unreadable on an ordinary object, which made an
// organizational unit impossible to unprotect and therefore impossible to
// delete.
//
// The leading ACEs here are the ones measured live: allow, object-scoped,
// granting 0x3.
func TestOUProtectionReadsPastLeadingObjectACEs(t *testing.T) {
	leading := []([]byte){
		ouTestObjectACE(5, 0, 3, 1),
		ouTestObjectACE(5, 0, 3, 1),
		ouTestObjectACE(5, 0, 3, 1),
	}
	for _, test := range []struct {
		name  string
		tail  [][]byte
		mask  uint32
		want  *bool
		where string
	}{
		{
			name:  "an unprotected object reads false rather than unknown",
			tail:  [][]byte{ouTestACE(0, 0, 0x000F01FF)},
			mask:  ouObjectProtectionMask,
			want:  ouTestPointer(false),
			where: "the plain full-control allow after the object ACEs",
		},
		{
			name:  "a protected object still reads true",
			tail:  [][]byte{ouTestACE(1, 0, ouObjectProtectionMask), ouTestACE(0, 0, 0x000F01FF)},
			mask:  ouObjectProtectionMask,
			want:  ouTestPointer(true),
			where: "the world deny after the object ACEs",
		},
		{
			name:  "object ACEs alone fall through to the default",
			tail:  nil,
			mask:  ouObjectProtectionMask,
			want:  ouTestPointer(false),
			where: "no decisive ordinary rule at all",
		},
		{
			name:  "the parent mask reads the same way",
			tail:  [][]byte{ouTestACE(1, 0, ouParentProtectionMask)},
			mask:  ouParentProtectionMask,
			want:  ouTestPointer(true),
			where: "the world deny of delete-child",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := ouTestDescriptor(append(slices.Clone(leading), test.tail...)...)
			acl, err := decodeOUDACL(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := ouACLProtection(acl, test.mask)
			if got == nil {
				t.Fatalf("still unreadable; expected %v from %s", *test.want, test.where)
			}
			if *got != *test.want {
				t.Fatalf("got %v, want %v from %s", *got, *test.want, test.where)
			}
		})
	}
}

// Skipping is allowed only for an ACE that is genuinely scoped to one object
// type. An object ACE without ACE_OBJECT_TYPE_PRESENT applies to every
// property, so it is as decisive as a plain ACE and skipping it would be a
// loosening of what this package claims to have read.
func TestOUProtectionDoesNotSkipAnUnscopedObjectACE(t *testing.T) {
	unscoped := ouTestObjectACE(5, 0, ouObjectProtectionMask, 0)
	if ouACLObjectScopedACE(unscoped) {
		t.Fatal("an object ACE with no ObjectType was treated as scoped")
	}
	raw := ouTestDescriptor(unscoped, ouTestACE(0, 0, 0x000F01FF))
	acl, err := decodeOUDACL(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := ouACLProtection(acl, ouObjectProtectionMask); got != nil {
		t.Fatalf("got %v; an ACE applying to every property must leave the DACL unknown", *got)
	}

	// An InheritedObjectType alone does not scope the grant either: it limits
	// which children inherit the ACE, not what the ACE grants here.
	inheritOnly := ouTestObjectACE(5, 0, ouObjectProtectionMask, 2)
	if ouACLObjectScopedACE(inheritOnly) {
		t.Fatal("an ACE carrying only InheritedObjectType was treated as scoped")
	}
}

// Callback ACEs stay unknown. Their applicability depends on a condition this
// package does not evaluate, so an early one must still withhold a reading even
// when it carries an ObjectType.
func TestOUProtectionStillRefusesCallbackAndUnknownACEs(t *testing.T) {
	for _, test := range []struct {
		name string
		ace  []byte
	}{
		{"allowed callback object", ouTestObjectACE(11, 0, 3, 1)},
		{"denied callback object", ouTestObjectACE(12, 0, 3, 1)},
		{"allowed callback", ouTestACE(9, 0, 3)},
		{"an entirely unknown form", []byte{0x42, 0, 8, 0, 1, 2, 3, 4}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := ouTestDescriptor(test.ace, ouTestACE(0, 0, 0x000F01FF))
			acl, err := decodeOUDACL(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := ouACLProtection(acl, ouObjectProtectionMask); got != nil {
				t.Fatalf("got %v; %s must leave the DACL unknown", *got, test.name)
			}
		})
	}
}

// An audit-type object ACE belongs in a SACL, never a DACL. It is not skipped,
// because encountering one means the descriptor is not what this package
// expects and a reading should be withheld rather than guessed.
func TestOUProtectionRefusesAuditObjectACEs(t *testing.T) {
	for _, kind := range []byte{7, 8, 15, 16} {
		if ouACLObjectScopedACE(ouTestObjectACE(kind, 0, 3, 1)) {
			t.Errorf("ACE type %d was treated as a scoped access rule", kind)
		}
	}
}

// Skipping must not make the editor touch an object ACE. Unprotecting rewrites
// only the plain world deny, and every other rule has to survive byte for byte
// — including the ones now being read past.
func TestOUUnprotectLeavesObjectACEsByteIdentical(t *testing.T) {
	first := ouTestObjectACE(5, 0, 3, 1)
	second := ouTestObjectACE(6, 0, ouObjectProtectionMask, 1)
	deny := ouTestACE(1, 0, ouObjectProtectionMask)
	raw := ouTestDescriptor(first, deny, second)
	acl, err := decodeOUDACL(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	aces, changed := changeOUACEs(acl, ouObjectProtectionMask, false)
	if !changed {
		t.Fatal("the world deny was not removed")
	}
	if len(aces) != 2 {
		t.Fatalf("got %d ACEs, want the two object rules", len(aces))
	}
	for i, want := range [][]byte{first, second} {
		if !slices.Equal(aces[i], want) {
			t.Fatalf("object ACE %d changed:\n got %x\nwant %x", i, aces[i], want)
		}
	}
}

// Protecting must still prepend exactly one deny, and must now recognise an
// already-protected object whose deny sits behind object ACEs rather than
// adding a second one.
func TestOUProtectRecognisesProtectionBehindObjectACEs(t *testing.T) {
	leading := ouTestObjectACE(5, 0, 3, 1)
	deny := ouTestACE(1, 0, ouObjectProtectionMask)
	acl, err := decodeOUDACL(ouTestDescriptor(leading, deny))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	aces, changed := changeOUACEs(acl, ouObjectProtectionMask, true)
	if changed {
		t.Fatal("a second deny was added to an already-protected object")
	}
	if len(aces) != 2 {
		t.Fatalf("got %d ACEs, want the original two", len(aces))
	}

	unprotected, err := decodeOUDACL(ouTestDescriptor(leading, ouTestACE(0, 0, 0x000F01FF)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	aces, changed = changeOUACEs(unprotected, ouObjectProtectionMask, true)
	if !changed || len(aces) != 3 || aces[0][0] != 1 {
		t.Fatalf("protecting did not prepend one world deny: changed=%v aces=%d", changed, len(aces))
	}
}

func ouTestPointer(value bool) *bool { return &value }
