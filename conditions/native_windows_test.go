//go:build windows && (amd64 || arm64)

package conditions

import (
	"strings"
	"testing"
)

func TestNativeCompileAndRoundTrip(t *testing.T) {
	cases := []Expression{
		Compare(Claim{User, "Department"}, Equal, Text("Finance")),
		All(Compare(Claim{User, "Title"}, Equal, Text("PM")), Any(Compare(Claim{User, "Division"}, Equal, Text("Finance")), Compare(Claim{User, "Division"}, Equal, Text("Sales")))),
		MemberOf(false, "S-1-5-32-544"), MemberOf(true, "S-1-1-0"),
		Compare(Claim{User, "Project"}, AnyOf, Reference(Claim{Resource, "Project"})),
		Raw(`(@User.NotAnActualDirectoryClaim == "syntactically-valid")`),
	}
	for _, expression := range cases {
		for _, deny := range []bool{false, true} {
			result, err := Compile(ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Deny: deny, Condition: expression})
			if err != nil {
				t.Fatal(err)
			}
			kind := "XA"
			if deny {
				kind = "XD"
			}
			if !strings.Contains(result, "("+kind+";") {
				t.Fatalf("wrong ACE type: %s", result)
			}
			normalized, err := NormalizeSDDL(result)
			if err != nil {
				t.Fatal(err)
			}
			if normalized != result {
				t.Fatalf("unstable roundtrip: %s -> %s", result, normalized)
			}
		}
	}
}

func TestNativeRejectsInvalidCondition(t *testing.T) {
	for _, condition := range []string{`(@User.Name == )`, `(Unclosed`, `(@User.Name === "x")`} {
		if _, err := Compile(ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: Raw(condition)}); err == nil {
			t.Fatalf("accepted %s", condition)
		}
	}
	if _, err := NormalizeSDDL("not SDDL"); err == nil {
		t.Fatal("accepted invalid SDDL")
	}
	if _, err := NormalizeSDDL("D:(A;;GA;;;WD)\x00garbage"); err == nil {
		t.Fatal("accepted NUL suffix")
	}
}

func TestNativePreservesDescriptorComponents(t *testing.T) {
	input := `O:SYG:BAD:PAI(A;;GA;;;SY)S:(AU;SA;GA;;;WD)`
	got, err := NormalizeSDDL(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"O:SY", "G:BA", "D:PAI", "S:(AU;SA;GA;;;WD)"} {
		if !strings.Contains(got, part) {
			t.Fatalf("lost %s from %s", part, got)
		}
	}
}

func TestNativeRepeatedCompilation(t *testing.T) {
	for n := 0; n < 100; n++ {
		if _, err := Compile(ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: Compare(Claim{User, "Name"}, Equal, Text("Cymru"))}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeLiteralBoundaries(t *testing.T) {
	for _, value := range []string{`C:\Finance`, "50%", `x); D:(A;;GA;;;WD)`, "Cymru £ 😀"} {
		result, err := Compile(ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: Compare(Claim{User, "Name"}, Equal, Text(value))})
		if err != nil {
			t.Fatalf("literal %q: %v", value, err)
		}
		if !strings.Contains(result, `"`+value+`"`) {
			t.Fatalf("literal changed: %q -> %s", value, result)
		}
	}
}
