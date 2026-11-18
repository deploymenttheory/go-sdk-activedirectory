package conditions_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func TestPortableSDDLTrusteesAndACLStates(t *testing.T) {
	for _, id := range []string{"owner-group-no-acls", "empty-dacl", "null-dacl", "empty-sacl", "null-sacl"} {
		t.Run(id, func(t *testing.T) {
			fixture := nativeDescriptorFixture(t, id)
			descriptor, err := conditions.ParseSDDL(fixture.InputSDDL)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := descriptor.MarshalBinary()
			if err != nil || !bytes.Equal(actual, fixture.Binary) {
				t.Fatalf("portable SDDL differs from independently generated native bytes: %v\ngot %x\nwant %x", err, actual, fixture.Binary)
			}
		})
	}
}

func TestPortableSDDLRequiresExplicitDomainAliasContext(t *testing.T) {
	input := "O:LAG:DAD:(A;;RP;;;DU)"
	if _, err := conditions.ParseSDDL(input); !errors.Is(err, conditions.ErrInvalidExpression) {
		t.Fatalf("domain-relative SDDL used ambient identity: %v", err)
	}
	descriptor, err := conditions.ParseSDDLWithOptions(input, conditions.SDDLOptions{DomainSID: "S-1-5-21-1-2-3", MachineSID: "S-1-5-21-4-5-6"})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := descriptor.SDDL()
	if err != nil || actual != "O:S-1-5-21-4-5-6-500G:S-1-5-21-1-2-3-512D:(A;;RP;;;S-1-5-21-1-2-3-513)" {
		t.Fatal(actual, err)
	}
}

func TestPortableSDDLRefusesToDiscardOpaqueBinaryMeaning(t *testing.T) {
	descriptor, err := conditions.ParseDescriptor(nativeDescriptorFixture(t, "synthetic-unknown-ace-type").Binary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := descriptor.SDDL(); !errors.Is(err, conditions.ErrUnrepresentableDescriptor) {
		t.Fatalf("opaque ACE formatted or silently discarded: %v", err)
	}
	for _, fixture := range nativeDescriptorCorpus(t, "sdk06-native-binary-controls.json") {
		if fixture.ID != "rm-control-present-42" {
			continue
		}
		descriptor, err = conditions.ParseDescriptor(fixture.Binary)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := descriptor.SDDL(); !errors.Is(err, conditions.ErrUnrepresentableDescriptor) {
			t.Fatalf("resource-manager control silently discarded: %v", err)
		}
	}
}

func TestPortableSDDLRejectsMalformedAndExcessiveInput(t *testing.T) {
	for _, input := range []string{
		"", "garbage", "O:", "O:SYG:BAO:WD", "D:NO_ACCESS_CONTROL(A;;GA;;;WD)",
		"D:(A;;RP;;;S-1-5-4294967296)", "D:(A;;RP;;;S-1-281474976710656-1)",
		"D:(A;;0x100000000;;;WD)", "D:(AU;SA;RP;;;WD)", "S:(A;;RP;;;WD)",
		`D:(XA;;RP;;;WD;(@User.Score === 7))`, `D:(XA;;RP;;;WD;(Exists @User.Score))`,
		`D:(XA;;RP;;;WD;(@User.Name == "unclosed))`, `D:(XA;;RP;;;WD;(@User.Bytes == #a#b#c##))`,
		`S:(RA;;;;;WD;("Unsigned",TU,0,-1))`, `S:(RA;;;;;WD;("Signed",TI,0,9223372036854775808))`,
		"D:(A;;RP;;;WD)\x00x", strings.Repeat("D", 65536),
		"D:(XA;;RP;;;WD;" + strings.Repeat("(", 70) + "@User.Enabled" + strings.Repeat(")", 70) + ")",
		"D:" + strings.Repeat("(A;;RP;;;WD)", 4000),
	} {
		if _, err := conditions.ParseSDDL(input); err == nil {
			t.Fatalf("invalid or excessive SDDL accepted: %.100s", input)
		}
	}
}

func FuzzSDDL(f *testing.F) {
	for _, name := range []string{"sdk06-native-reference-full.json", "sdk06-native-conditional-reference.json"} {
		for _, fixture := range nativeDescriptorCorpus(f, name) {
			if fixture.InputSDDL != "" {
				f.Add(fixture.InputSDDL)
			}
		}
	}
	f.Fuzz(func(t *testing.T, input string) {
		descriptor, err := conditions.ParseSDDL(input)
		if err != nil {
			return
		}
		text, err := descriptor.SDDL()
		if err != nil {
			t.Fatalf("accepted SDDL cannot be formatted: %v", err)
		}
		normalized, err := conditions.NormalizeSDDL(text)
		if err != nil || normalized != text {
			t.Fatalf("accepted SDDL normalization is unstable: %q: %v", text, err)
		}
	})
}

func TestPortableSDDLFormatsNativeCorpus(t *testing.T) {
	for _, name := range []string{"sdk06-native-reference-full.json", "sdk06-native-conditional-reference.json"} {
		for _, fixture := range nativeDescriptorCorpus(t, name) {
			if !fixture.Success {
				continue
			}
			t.Run(fixture.ID, func(t *testing.T) {
				descriptor, err := conditions.ParseDescriptor(fixture.Binary)
				if err != nil {
					t.Fatal(err)
				}
				text, err := descriptor.SDDL()
				if err != nil {
					t.Fatal(err)
				}
				roundTrip, err := conditions.ParseSDDL(text)
				if err != nil {
					t.Fatalf("formatted SDDL cannot be parsed: %s: %v", text, err)
				}
				actual, err := roundTrip.MarshalBinary()
				// Original storage order/padding may vary, so compare each ACL and
				// trustee through the independent native canonical representation.
				canonical, parseErr := conditions.ParseSDDL(fixture.CanonicalSDDL)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				expected, _ := canonical.MarshalBinary()
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatalf("formatted SDDL changed components: %s: %v\ngot %x\nwant %x", text, err, actual, expected)
				}
			})
		}
	}
}

func TestPortableSDDLResourceAttributeCanonicalEncoding(t *testing.T) {
	for _, fixture := range nativeDescriptorCorpus(t, "sdk06-native-conditional-reference.json") {
		if !fixture.Success || !strings.HasPrefix(fixture.InputSDDL, "S:") {
			continue
		}
		t.Run(fixture.ID, func(t *testing.T) {
			// The native canonical form resolves implementation quirks in its input
			// parser (negative unsigned values and octets containing '#').
			descriptor, err := conditions.ParseSDDL(fixture.CanonicalSDDL)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := descriptor.MarshalBinary()
			if err != nil || !bytes.Equal(actual, fixture.Binary) {
				t.Fatalf("portable resource claim differs from native: %v\ngot %x\nwant %x", err, actual, fixture.Binary)
			}
		})
	}
}

func TestPortableConditionNativeCorpusEncoding(t *testing.T) {
	for _, fixture := range nativeDescriptorCorpus(t, "sdk06-native-conditional-reference.json") {
		// This labelled native quirk accepts separators inside an octet literal,
		// outside MS-DTYP's documented # followed by pairs of hexadecimal digits.
		if !fixture.Success || !strings.HasPrefix(fixture.InputSDDL, "D:") || fixture.ID == "expression-75" {
			continue
		}
		t.Run(fixture.ID, func(t *testing.T) {
			descriptor, err := conditions.ParseSDDL(fixture.InputSDDL)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := descriptor.MarshalBinary()
			if err != nil || !bytes.Equal(actual, fixture.Binary) {
				t.Fatalf("conditional tokens differ from native: %v\ngot %x\nwant %x", err, actual, fixture.Binary)
			}
		})
	}
}

func TestPortableSDDLConditionalEncoding(t *testing.T) {
	for _, id := range []string{"conditional-string", "conditional-nested", "conditional-member-of", "conditional-object"} {
		t.Run(id, func(t *testing.T) {
			fixture := nativeDescriptorFixture(t, id)
			descriptor, err := conditions.ParseSDDL(fixture.InputSDDL)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := descriptor.MarshalBinary()
			if err != nil || !bytes.Equal(actual, fixture.Binary) {
				t.Fatalf("portable conditional encoding differs from native: %v\ngot %x\nwant %x", err, actual, fixture.Binary)
			}
		})
	}
}

func TestPortableSDDLPlainObjectAndControlEncoding(t *testing.T) {
	for _, id := range []string{"owner-group-dacl-sacl", "protected-auto-inherited-control", "object-change-password", "object-inherited-two-guids", "mandatory-label", "process-trust-label"} {
		t.Run(id, func(t *testing.T) {
			fixture := nativeDescriptorFixture(t, id)
			descriptor, err := conditions.ParseSDDL(fixture.InputSDDL)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := descriptor.MarshalBinary()
			if err != nil || !bytes.Equal(actual, fixture.Binary) {
				t.Fatalf("portable ACE differs from native bytes: %v\ngot %x\nwant %x", err, actual, fixture.Binary)
			}
		})
	}
}
