package conditions_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func TestCompileAcceptsCanonicalSixByteSIDAuthority(t *testing.T) {
	text, err := conditions.Compile(conditions.ACE{
		TrusteeSID: "S-1-0x010203040506-7", AccessMask: 0x100,
		Condition: conditions.Raw("@User.Score == 7"),
	})
	if err != nil {
		t.Fatal("canonical MS-DTYP trustee SID could not be compiled", err)
	}
	raw, err := conditions.DescriptorBytes(text)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := conditions.ParseDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	aces := descriptor.DACL().ACEs
	if len(aces) != 1 || len(aces[0]) < 20 || aces[0][0] != 9 {
		t.Fatal("compiled policy did not contain one conditional allow ACE")
	}
	// MS-DTYP SID: revision/count, six authority bytes, little-endian RID7.
	if !bytes.Equal(aces[0][8:20], []byte{1, 1, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0}) {
		t.Fatal("compiled trustee changed the six-byte SID authority")
	}
}

func TestPublicCompilerReturnsNoApproximationAndActionableDiagnostics(t *testing.T) {
	for _, text := range []string{
		"@User.Score ==", "@User.Score Matches 7", "@Other.Score == 7",
		"Member_of {SID(S-1-0x1000000000000-7)}", "@User.Score == 18446744073709551616",
	} {
		t.Run(text, func(t *testing.T) {
			compiled, err := conditions.Compile(conditions.ACE{
				TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: conditions.Raw(text),
			})
			if compiled != "" || !errors.Is(err, conditions.ErrInvalidExpression) || err.Error() == conditions.ErrInvalidExpression.Error() {
				t.Fatal("compiler returned approximate output or a nonactionable diagnostic", compiled, err)
			}
			sddl := "D:(XA;;CR;;;WD;(" + text + "))"
			normalized, normalizeErr := conditions.NormalizeSDDL(sddl)
			raw, binaryErr := conditions.DescriptorBytes(sddl)
			if normalized != "" || len(raw) != 0 || !errors.Is(normalizeErr, conditions.ErrInvalidExpression) ||
				!errors.Is(binaryErr, conditions.ErrInvalidExpression) {
				t.Fatal("conversion returned a partial policy for an invalid condition", normalizeErr, binaryErr)
			}
		})
	}
	for _, sddl := range []string{"D:(A;;GA;;;DA)", "D:(A;;GA;;;LA)"} {
		if output, err := conditions.NormalizeSDDL(sddl); output != "" || err == nil || !strings.Contains(err.Error(), "SID required") {
			t.Fatal("relative trustee silently used ambient identity context", output, err)
		}
	}
}

func TestTypedMembershipAcceptsCanonicalSixByteSIDAuthority(t *testing.T) {
	text, err := conditions.Compile(conditions.ACE{
		TrusteeSID: "S-1-1-0", AccessMask: 0x100,
		Condition: conditions.MemberOf(false, "S-1-0x010203040506-7"),
	})
	if err != nil {
		t.Fatal("canonical MS-DTYP membership SID could not be compiled", err)
	}
	raw, err := conditions.DescriptorBytes(text)
	if err != nil {
		t.Fatal(err)
	}
	// Conditional SID literal token0x51, length12, then the specified wire SID.
	if !bytes.Contains(raw, []byte{0x51, 12, 0, 0, 0, 1, 1, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0}) {
		t.Fatal("typed membership changed the six-byte SID authority")
	}
}
