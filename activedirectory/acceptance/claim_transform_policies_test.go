package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// The digests below are the SHA-256 values recorded in
// docs/research/claims-transformation-evidence/server2025-shorthand-forms.json
// when the reference module wrote each form in an isolated lab. They pin the
// renderer to observed bytes: if the envelope or spacing drifts, these fail.
func TestClaimTransformRenderMatchesCapturedEvidence(t *testing.T) {
	const capturedClaimID = "ad://ext/sdke3106e771b"
	cases := []struct {
		InternalName string
		InternalSet  admodel.ClaimTransformRuleSet
		InternalSha  string
	}{
		{
			"AllowAll",
			admodel.ClaimTransformRuleSet{AllowAll: true},
			"1f54dcd65fbae24188ac62119c6581db6629920e446a871fb82fdabc863ef2ea",
		},
		{
			"DenyAll",
			admodel.ClaimTransformRuleSet{DenyAll: true},
			"caa7484df89b6d90ff8cc39b77d2b32178219935d10c3c7a50ec445828d59b61",
		},
		{
			"AllowAllExcept",
			admodel.ClaimTransformRuleSet{AllowAllExcept: []string{capturedClaimID}},
			"0ee3ee5a0ff33b0176b865c03e98e00002b402d6d15b4a48fa51aa2fbc6e3475",
		},
		{
			"DenyAllExcept",
			admodel.ClaimTransformRuleSet{DenyAllExcept: []string{capturedClaimID}},
			"38534268713eb97d4565a7027ea1b181c7f02baf5989872f3fa223a72e28c61c",
		},
	}
	for _, c := range cases {
		stored, ok, err := admodel.InternalClaimTransformRuleSetRender(c.InternalSet)
		if err != nil || !ok {
			t.Fatalf("%s: render failed: ok=%v err=%v", c.InternalName, ok, err)
		}
		sum := sha256.Sum256([]byte(stored))
		// The full digest recorded in the evidence file, compared in full.
		if got := hex.EncodeToString(sum[:]); got != c.InternalSha {
			t.Fatalf(
				"%s: digest %s, want %s\n  rendered %q",
				c.InternalName,
				got,
				c.InternalSha,
				stored,
			)
		}
		// The stored value must be the XML envelope, not bare rule text.
		if !strings.HasPrefix(stored, " <ClaimsTransformationPolicy>") ||
			!strings.HasSuffix(stored, "</ClaimsTransformationPolicy>") {
			t.Fatalf("%s: rendered value is not the observed envelope: %q", c.InternalName, stored)
		}
		if !strings.Contains(stored, "<![CDATA[") || !strings.Contains(stored, "]]>") {
			t.Fatalf("%s: rendered value lost its CDATA section: %q", c.InternalName, stored)
		}
	}
}

// The reference module's spacing is inconsistent between forms. Reproducing it
// exactly is the requirement, so these shapes are asserted directly.
func TestClaimTransformObservedSpacing(t *testing.T) {
	inner := func(t *testing.T, set admodel.ClaimTransformRuleSet) string {
		t.Helper()
		stored, ok, err := admodel.InternalClaimTransformRuleSetRender(set)
		if err != nil || !ok {
			t.Fatalf("render failed: %v", err)
		}
		value, err := admodel.InternalClaimTransformInner(stored)
		if err != nil {
			t.Fatalf("inner extraction failed: %v", err)
		}
		return value
	}
	if got, want := inner(
		t,
		admodel.ClaimTransformRuleSet{AllowAll: true},
	), "C1:[]=>Issue(claim=C1);"; got != want {
		t.Fatalf("AllowAll: %q want %q", got, want)
	}
	// DenyAll is expressed as a type that matches nothing, not an empty rule.
	if got, want := inner(
		t,
		admodel.ClaimTransformRuleSet{DenyAll: true},
	), `C1:[Type !~ "*"]=>Issue(claim=C1);`; got != want {
		t.Fatalf("DenyAll: %q want %q", got, want)
	}
	// A space precedes != here but no spaces surround == below.
	if got, want := inner(
		t,
		admodel.ClaimTransformRuleSet{AllowAllExcept: []string{"ad://ext/x"}},
	), `C1:[Type !="ad://ext/x"]=>Issue(claim=C1);`; got != want {
		t.Fatalf("AllowAllExcept: %q want %q", got, want)
	}
	if got, want := inner(
		t,
		admodel.ClaimTransformRuleSet{DenyAllExcept: []string{"ad://ext/x"}},
	), `C1:[Type=="ad://ext/x"]=>Issue(claim=C1);`; got != want {
		t.Fatalf("DenyAllExcept: %q want %q", got, want)
	}
}

func TestClaimTransformRuleSetRequiresExactlyOneForm(t *testing.T) {
	rule := "C1:[] => Issue(claim = C1);"
	// The zero value writes nothing rather than defaulting to allow or deny.
	if _, ok, err := admodel.InternalClaimTransformRuleSetRender(
		(admodel.ClaimTransformRuleSet{}),
	); ok ||
		err != nil {
		t.Fatalf("empty set must render nothing: ok=%v err=%v", ok, err)
	}
	for name, set := range map[string]admodel.ClaimTransformRuleSet{
		"allow and deny":  {AllowAll: true, DenyAll: true},
		"allow and rule":  {AllowAll: true, Rule: &rule},
		"except and deny": {DenyAll: true, DenyAllExcept: []string{"ad://ext/x"}},
		"both excepts":    {AllowAllExcept: []string{"ad://ext/x"}, DenyAllExcept: []string{"ad://ext/y"}},
	} {
		if _, _, err := admodel.InternalClaimTransformRuleSetRender(
			set,
		); !errors.Is(
			err,
			admodel.ErrClaimTransformPolicy,
		) {
			t.Fatalf("%s: expected ErrClaimTransformPolicy, got %v", name, err)
		}
	}
}

// Only the single-identifier shape was observed, so a multi-identifier request
// is refused rather than rendered with an invented separator.
func TestClaimTransformMultipleTypesRefused(t *testing.T) {
	for name, set := range map[string]admodel.ClaimTransformRuleSet{
		"allow": {AllowAllExcept: []string{"ad://ext/a", "ad://ext/b"}},
		"deny":  {DenyAllExcept: []string{"ad://ext/a", "ad://ext/b"}},
	} {
		_, _, err := admodel.InternalClaimTransformRuleSetRender(set)
		if !errors.Is(err, admodel.ErrClaimTransformRule) {
			t.Fatalf("%s: expected ErrClaimTransformRule, got %v", name, err)
		}
		if !strings.Contains(err.Error(), "qualified") {
			t.Fatalf("%s: the refusal must say it is unqualified: %v", name, err)
		}
	}
}

func TestClaimTransformExceptValidatesClaimID(t *testing.T) {
	// A malformed identifier must not reach the rendered rule.
	for _, id := range []string{"", "not-a-claim", "ad://ext/", `ad://ext/a"b`, "ad://ext/a b"} {
		if _, _, err := admodel.InternalClaimTransformRuleSetRender(
			(admodel.ClaimTransformRuleSet{DenyAllExcept: []string{id}}),
		); err == nil {
			t.Fatalf("accepted malformed claim ID %q", id)
		}
	}
}

func TestValidateClaimTransformRuleRejectsEnvelopeBreakout(t *testing.T) {
	// Explicit rule text is wrapped in CDATA, so anything able to close that
	// section or introduce another envelope is rejected before any write.
	for name, rule := range map[string]string{
		"closes cdata":    "C1:[]=>Issue(claim=C1);]]><Rules>",
		"opens cdata":     "<![CDATA[C1:[]=>Issue(claim=C1);",
		"nested envelope": "<ClaimsTransformationPolicy></ClaimsTransformationPolicy>",
		"nested rules":    "<Rules version=\"1\"></Rules>",
		"empty":           "",
		"control char":    "C1:[]=>Issue(claim=C1);\x00",
	} {
		if err := admodel.InternalValidateClaimTransformRule(
			rule,
		); !errors.Is(
			err,
			admodel.ErrClaimTransformRule,
		) {
			t.Fatalf("%s: expected ErrClaimTransformRule, got %v", name, err)
		}
	}
	if err := admodel.InternalValidateClaimTransformRule(
		"C1:[] => Issue(claim = C1);",
	); err != nil {
		t.Fatalf("a plain rule must be accepted: %v", err)
	}
}

func TestClaimTransformRuleWrappedVerbatim(t *testing.T) {
	// The caller's own spacing survives: the reference wrapped explicit text
	// without normalising it, and so must this.
	rule := "C1:[] => Issue(claim = C1);"
	stored, ok, err := admodel.InternalClaimTransformRuleSetRender(
		(admodel.ClaimTransformRuleSet{Rule: &rule}),
	)
	if err != nil || !ok {
		t.Fatalf("render failed: %v", err)
	}
	inner, err := admodel.InternalClaimTransformInner(stored)
	if err != nil {
		t.Fatal(err)
	}
	if inner != rule {
		t.Fatalf("explicit rule was rewritten: %q want %q", inner, rule)
	}
	// It must differ from the AllowAll expansion of the same intent, because
	// the stored bytes differ.
	allowAll, _, err := admodel.InternalClaimTransformRuleSetRender(
		(admodel.ClaimTransformRuleSet{AllowAll: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if stored == allowAll {
		t.Fatal("explicit rule text must not be normalised into the shorthand form")
	}
}

func TestClaimTransformInnerRejectsUnexpectedShape(t *testing.T) {
	// A stored value that is not the observed envelope is reported, never
	// reinterpreted as a rule.
	for name, stored := range map[string]string{
		"bare rule": "C1:[]=>Issue(claim=C1);",
		"no cdata":  " <ClaimsTransformationPolicy>     <Rules version=\"1\">rule</Rules></ClaimsTransformationPolicy>",
		"empty":     "",
	} {
		if _, err := admodel.InternalClaimTransformInner(
			stored,
		); !errors.Is(
			err,
			admodel.ErrClaimTransformPolicy,
		) {
			t.Fatalf("%s: expected ErrClaimTransformPolicy, got %v", name, err)
		}
	}
	inner, err := admodel.InternalClaimTransformInner(
		admodel.InternalClaimTransformEnvelopeFor("X"),
	)
	if err != nil || inner != "X" {
		t.Fatalf("round trip failed: %q %v", inner, err)
	}
}

func TestDecodeClaimTransformPolicyRetainsUnparsableStoredValue(t *testing.T) {
	object := admodel.Object{
		DistinguishedName: "CN=p,CN=Claims Transformation Policies,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example",
		Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte(admodel.InternalClaimTransformClass)},
			"objectguid":  {make([]byte, 16)},
			"name":        {[]byte("p")},
			"usnchanged":  {[]byte("7")},
			strings.ToLower(admodel.InternalClaimTransformRules): {[]byte("not an envelope")},
		},
	}
	value, err := admodel.InternalDecodeClaimTransformPolicy(object)
	if err == nil {
		t.Fatal("an unparsable stored value must be reported")
	}
	// The raw value still has to be visible even though it could not be parsed.
	if value.StoredRules == nil || *value.StoredRules != "not an envelope" {
		t.Fatalf("stored rules were dropped: %+v", value.StoredRules)
	}
	if value.Rule != nil {
		t.Fatalf("an unparsable value must not yield a rule: %q", *value.Rule)
	}
	if value.CompiledPresent {
		t.Fatal("compiled rules were absent and must not be reported present")
	}
}

func TestDecodeClaimTransformPolicyReportsCompiledPresence(t *testing.T) {
	object := admodel.Object{
		DistinguishedName: "CN=p,CN=Claims Transformation Policies,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example",
		Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte(admodel.InternalClaimTransformClass)},
			"objectguid":  {make([]byte, 16)},
			"name":        {[]byte("p")},
			"usnchanged":  {[]byte("7")},
			strings.ToLower(admodel.InternalClaimTransformRules): {
				[]byte(admodel.InternalClaimTransformEnvelopeFor("C1:[]=>Issue(claim=C1);")),
			},
			strings.ToLower(admodel.InternalClaimTransformCompiled): {{0x01, 0x02}},
		},
	}
	value, err := admodel.InternalDecodeClaimTransformPolicy(object)
	if err != nil {
		t.Fatal(err)
	}
	if value.Rule == nil || *value.Rule != "C1:[]=>Issue(claim=C1);" {
		t.Fatalf("rule not extracted: %+v", value.Rule)
	}
	if !value.CompiledPresent {
		t.Fatal("compiled rules were returned and must be reported present")
	}
}
