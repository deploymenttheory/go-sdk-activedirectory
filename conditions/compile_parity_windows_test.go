//go:build windows && (amd64 || arm64)

package conditions

import (
	"bytes"
	"testing"
)

func TestPortableCanonicalSIDMatchesIndependentWindowsConversion(t *testing.T) {
	for _, fixture := range []struct {
		name string
		ace  ACE
		sddl string
	}{
		{
			"trustee",
			ACE{TrusteeSID: "S-1-0x010203040506-7", AccessMask: 0x100, Condition: Raw("@User.Score == 7")},
			"D:(XA;;CR;;;S-1-0x010203040506-7;(@User.Score == 7))",
		},
		{
			"membership",
			ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: MemberOf(false, "S-1-0x010203040506-7")},
			"D:(XA;;CR;;;WD;(Member_of {SID(S-1-0x010203040506-7)}))",
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			compiled, err := Compile(fixture.ace)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := DescriptorBytes(compiled)
			if err != nil {
				t.Fatal(err)
			}
			// Convert the independent literal through Advapi32 directly. Calling
			// nativeAPI.compile would share ACE.validate with the code under test.
			expected, err := systemNativeAPI().descriptorBytes(fixture.sddl)
			if err != nil {
				t.Fatal("independent Windows conversion failed", err)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("portable canonical SID differs from Windows: %x != %x", actual, expected)
			}
		})
	}
}
