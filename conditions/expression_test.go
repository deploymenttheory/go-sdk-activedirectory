package conditions

import (
	"errors"
	"strings"
	"testing"
)

func TestTypedExpression(t *testing.T) {
	e := All(
		Compare(Claim{User, "Department"}, Equal, Text("Finance")),
		Any(MemberOf(false, "S-1-5-32-544"), Compare(Claim{Device, "Managed"}, Equal, Integer(1))),
	)
	got, err := e.Render()
	if err != nil {
		t.Fatal(err)
	}
	want := `((@User.Department == "Finance") && ((Member_of {SID(S-1-5-32-544)}) || (@Device.Managed == 1)))`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestRejectUnsafeBuilderInputs(t *testing.T) {
	for _, e := range []Expression{
		{},
		Compare(Claim{Scope("Other"), "Name"}, Equal, Text("x")),
		Compare(Claim{User, `Name) || @User.Admin`}, Equal, Text("x")),
		Compare(Claim{User, "Name"}, Operator("== 1 ||"), Text("x")),
		Compare(Claim{User, "Name"}, Equal, Text(`x" || @User.Admin == "1`)),
		Compare(Claim{User, "Name"}, Equal, Text("x\x00y")),
		Compare(Claim{User, "Name"}, Equal, Value{}),
		All(), Any(Raw("valid")), Not(Expression{}), MemberOf(false),
		MemberOf(false, "S-1-1-0) || @User.Admin"), Raw("\x00"), Raw(strings.Repeat("a", 65536)),
	} {
		if _, err := e.Render(); !errors.Is(err, ErrInvalidExpression) {
			t.Fatalf("expected invalid expression, got %v", err)
		}
	}
}

func TestLiteralBoundaries(t *testing.T) {
	for _, value := range []string{"", `C:\Finance`, "50%", `x); D:(A;;GA;;;WD)`, "Cymru £ 😀"} {
		e := Compare(Claim{User, "Description"}, Equal, Text(value))
		got, err := e.Render()
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if !strings.Contains(got, `"`+value+`"`) {
			t.Fatalf("literal changed: %s", got)
		}
	}
}

func FuzzTextBoundary(f *testing.F) {
	for _, s := range []string{"Finance", `a"b`, "\x00", `x);D:(A;;GA;;;WD)`, "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		text, err := Compare(Claim{User, "Name"}, Equal, Text(value)).Render()
		if err == nil && strings.Count(text, `"`) != 2 {
			t.Fatalf("escaped literal boundary: %q", text)
		}
	})
}
