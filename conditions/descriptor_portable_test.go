package conditions_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

type nativeDescriptorCase struct {
	ID          string `json:"id"`
	InputSDDL   string `json:"input_sddl"`
	Binary      []byte `json:"binary_base64"`
	InputBinary []byte `json:"input_binary_base64"`
	Success     bool   `json:"success"`
	Valid       bool   `json:"native_binary_valid"`
}

func nativeDescriptorCorpus(t testing.TB, name string) []nativeDescriptorCase {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []nativeDescriptorCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for i := range corpus.Cases {
		if corpus.Cases[i].Binary == nil {
			corpus.Cases[i].Binary = corpus.Cases[i].InputBinary
		}
	}
	return corpus.Cases
}

func nativeDescriptorFixture(t testing.TB, id string) nativeDescriptorCase {
	t.Helper()
	for _, fixture := range nativeDescriptorCorpus(t, "sdk06-native-reference-initial.json") {
		if fixture.ID == id {
			return fixture
		}
	}
	t.Fatalf("native fixture %q is missing", id)
	return nativeDescriptorCase{}
}

func TestBinaryDescriptorRejectsMalformedBounds(t *testing.T) {
	fixture := nativeDescriptorFixture(t, "object-change-password")
	for length := range len(fixture.Binary) {
		if _, err := conditions.ParseDescriptor(fixture.Binary[:length]); !errors.Is(err, conditions.ErrInvalidDescriptor) {
			t.Fatalf("truncated descriptor length %d accepted: %v", length, err)
		}
	}
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"revision", func(raw []byte) { raw[0] = 2 }},
		{"absolute", func(raw []byte) { raw[3] &^= 0x80 }},
		{"owner-overflow", func(raw []byte) { binary.LittleEndian.PutUint32(raw[4:8], ^uint32(0)) }},
		{"owner-in-header", func(raw []byte) { binary.LittleEndian.PutUint32(raw[4:8], 4) }},
		{"sid-count", func(raw []byte) { raw[binary.LittleEndian.Uint32(raw[4:8])+1] = 16 }},
		{"acl-without-present", func(raw []byte) { raw[2] &^= 4 }},
		{"acl-size", func(raw []byte) { binary.LittleEndian.PutUint16(raw[22:24], 0xffff) }},
		{"acl-count", func(raw []byte) { binary.LittleEndian.PutUint16(raw[24:26], 0xffff) }},
		{"ace-zero-size", func(raw []byte) { binary.LittleEndian.PutUint16(raw[30:32], 0) }},
		{"ace-overflow", func(raw []byte) { binary.LittleEndian.PutUint16(raw[30:32], 0xfffc) }},
		{"object-guid-sid-overlap", func(raw []byte) { binary.LittleEndian.PutUint32(raw[36:40], 3) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.Clone(fixture.Binary)
			tc.edit(raw)
			if _, err := conditions.ParseDescriptor(raw); !errors.Is(err, conditions.ErrInvalidDescriptor) {
				t.Fatalf("malformed descriptor accepted: %v", err)
			}
		})
	}
	if _, err := conditions.ParseDescriptor(make([]byte, (16<<20)+1)); !errors.Is(err, conditions.ErrInvalidDescriptor) {
		t.Fatalf("oversized descriptor accepted: %v", err)
	}
}

func FuzzBinaryDescriptor(f *testing.F) {
	for _, name := range []string{"sdk06-native-reference-full.json", "sdk06-native-binary-controls.json"} {
		for _, fixture := range nativeDescriptorCorpus(f, name) {
			if fixture.Valid {
				f.Add(fixture.Binary)
			}
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		descriptor, err := conditions.ParseDescriptor(raw)
		if err != nil {
			if !errors.Is(err, conditions.ErrInvalidDescriptor) {
				t.Fatalf("unexpected parse error: %v", err)
			}
			return
		}
		actual, err := descriptor.MarshalBinary()
		if err != nil || !bytes.Equal(actual, raw) {
			t.Fatalf("accepted input was changed: %v", err)
		}
		_ = descriptor.DACL()
		_ = descriptor.SACL()
	})
}

func TestBinaryDescriptorNativeCorpusRoundTrip(t *testing.T) {
	fixtures := append(nativeDescriptorCorpus(t, "sdk06-native-reference-full.json"), nativeDescriptorCorpus(t, "sdk06-native-binary-controls.json")...)
	for _, fixture := range fixtures {
		if !fixture.Valid {
			continue
		}
		t.Run(fixture.ID, func(t *testing.T) {
			descriptor, err := conditions.ParseDescriptor(fixture.Binary)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := descriptor.MarshalBinary()
			if err != nil || !bytes.Equal(actual, fixture.Binary) {
				t.Fatalf("native-valid binary changed: %v", err)
			}
		})
	}
}

func TestBinaryDescriptorOwnsInputAndSnapshots(t *testing.T) {
	fixture := nativeDescriptorFixture(t, "object-change-password")
	original := bytes.Clone(fixture.Binary)
	descriptor, err := conditions.ParseDescriptor(fixture.Binary)
	if err != nil {
		t.Fatal(err)
	}
	clear(fixture.Binary)
	acl := descriptor.DACL()
	clear(acl.ACEs[0])
	first, err := descriptor.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	clear(first)
	actual, err := descriptor.MarshalBinary()
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatalf("caller mutation changed descriptor: %v", err)
	}
}

func TestBinaryDescriptorDistinguishesAbsentNullAndEmptyACLs(t *testing.T) {
	for _, tc := range []struct {
		id      string
		present bool
		null    bool
		sacl    bool
	}{
		{"owner-group-no-acls", false, false, false},
		{"empty-dacl", true, false, false},
		{"null-dacl", true, true, false},
		{"empty-sacl", true, false, true},
		{"null-sacl", true, true, true},
	} {
		t.Run(tc.id, func(t *testing.T) {
			descriptor, err := conditions.ParseDescriptor(nativeDescriptorFixture(t, tc.id).Binary)
			if err != nil {
				t.Fatal(err)
			}
			acl := descriptor.DACL()
			if tc.sacl {
				acl = descriptor.SACL()
			}
			if acl.Present != tc.present || acl.Null != tc.null || len(acl.ACEs) != 0 {
				t.Fatalf("ACL state was conflated: %+v", acl)
			}
		})
	}
}

func TestBinaryDescriptorDACLEditPreservesUnownedBytes(t *testing.T) {
	fixture := nativeDescriptorFixture(t, "reordered-components-trailing-padding")
	descriptor, err := conditions.ParseDescriptor(fixture.Binary)
	if err != nil {
		t.Fatal(err)
	}
	acl := descriptor.DACL()
	for _, id := range []string{"synthetic-unknown-ace-type", "conditional-nested", "object-inherited-two-guids"} {
		other, parseErr := conditions.ParseDescriptor(nativeDescriptorFixture(t, id).Binary)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		acl.ACEs = append(acl.ACEs, other.DACL().ACEs...)
	}
	edited, err := descriptor.WithDACL(acl)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := edited.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual[:16], fixture.Binary[:16]) || !bytes.Equal(actual[20:len(fixture.Binary)], fixture.Binary[20:]) {
		t.Fatal("DACL edit changed owner, group, SACL, control, or original opaque bytes")
	}
	retained := edited.DACL()
	if len(retained.ACEs) != len(acl.ACEs) {
		t.Fatal("DACL edit lost ACEs")
	}
	for i := range acl.ACEs {
		if !bytes.Equal(acl.ACEs[i], retained.ACEs[i]) {
			t.Fatalf("DACL edit changed ACE %d", i)
		}
	}
	original, _ := descriptor.MarshalBinary()
	if !bytes.Equal(original, fixture.Binary) {
		t.Fatal("DACL edit mutated the original descriptor")
	}
}

func TestBinaryDescriptorUnchangedACLEditRetainsLayoutAndCapacity(t *testing.T) {
	for _, name := range []string{"sdk06-native-reference-full.json", "sdk06-native-binary-controls.json"} {
		for _, fixture := range nativeDescriptorCorpus(t, name) {
			if !fixture.Valid {
				continue
			}
			t.Run(fixture.ID, func(t *testing.T) {
				descriptor, err := conditions.ParseDescriptor(fixture.Binary)
				if err != nil {
					t.Fatal(err)
				}
				edited, err := descriptor.WithDACL(descriptor.DACL())
				if err != nil {
					t.Fatal(err)
				}
				edited, err = edited.WithSACL(edited.SACL())
				if err != nil {
					t.Fatal(err)
				}
				actual, err := edited.MarshalBinary()
				if err != nil || !bytes.Equal(actual, fixture.Binary) {
					t.Fatalf("no-op edit changed layout, reserved fields, or ACL capacity: %v", err)
				}
			})
		}
	}
}

func TestNormalizeSDDLPreservesResourceAttributeACE(t *testing.T) {
	fixture := nativeDescriptorFixture(t, "resource-attribute")
	normalized, err := conditions.NormalizeSDDL(fixture.InputSDDL)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := conditions.DescriptorBytes(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, fixture.Binary) {
		t.Fatalf("normalization discarded SACL content: got %s, native %s", base64.StdEncoding.EncodeToString(actual), base64.StdEncoding.EncodeToString(fixture.Binary))
	}
}

func TestBinaryDescriptorRoundTripRetainsUnknownACEAndLayout(t *testing.T) {
	fixture := nativeDescriptorFixture(t, "synthetic-unknown-ace-type")
	descriptor, err := conditions.ParseDescriptor(fixture.Binary)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := descriptor.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, fixture.Binary) {
		t.Fatal("lossless roundtrip changed the opaque ACE or original layout")
	}
	acl := descriptor.DACL()
	if !acl.Present || acl.Null || len(acl.ACEs) != 1 || acl.ACEs[0][0] != 0x7f {
		t.Fatal("future ACE was dropped or assigned a different type")
	}
}
