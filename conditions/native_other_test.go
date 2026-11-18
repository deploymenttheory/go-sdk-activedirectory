//go:build !windows || (!amd64 && !arm64)

package conditions

import (
	"strings"
	"testing"
)

func TestPortableCompilerWithoutNativeRuntime(t *testing.T) {
	text, err := Compile(ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: Compare(Claim{User, "Department"}, Equal, Text("Finance"))})
	if err != nil || !strings.Contains(text, `(@USER.Department == "Finance")`) {
		t.Fatal(text, err)
	}
	raw, err := DescriptorBytes(text)
	if err != nil || len(raw) <= 28 {
		t.Fatal(raw, err)
	}
	normalized, err := NormalizeSDDL(text)
	if err != nil || text != normalized {
		t.Fatal(normalized, err)
	}
}
