package activedirectory

import (
	"errors"
	"strings"
	"testing"
)

func claimText(value string) *string { return &value }

func TestValidateClaimID(t *testing.T) {
	for _, id := range []string{
		"ad://ext/Department",
		"ad://ext/Department:88ad1f2c",
		"AD://EXT/Department",
		"ad://ext/a:b/c",
	} {
		if err := validateClaimID(id); err != nil {
			t.Fatalf("rejected a conforming claim ID %q: %v", id, err)
		}
	}
	for name, id := range map[string]string{
		"empty":          "",
		"wrong prefix":   "urn://ext/Department",
		"prefix only":    "ad://ext/",
		"too short":      "ad://ext/",
		"embedded space": "ad://ext/Dep artment",
		"embedded pipe":  "ad://ext/Dep|artment",
		"control char":   "ad://ext/Dep\x01artment",
		"trailing slash": "ad://ext/Department/",
		"backslash":      "ad://ext/Dep\\artment",
		"question mark":  "ad://ext/Dep?artment",
		"quote":          "ad://ext/Dep\"artment",
		"angle bracket":  "ad://ext/Dep<artment",
		"too long":       "ad://ext/" + strings.Repeat("x", 64),
	} {
		if err := validateClaimID(id); !errors.Is(err, ErrClaimType) {
			t.Fatalf("%s: accepted %q (err=%v)", name, id, err)
		}
	}
}

func TestGenerateClaimIDConforms(t *testing.T) {
	for _, display := range []string{"Department", "Cost Centre", "a", "<<<>>>", "Ünïcødé", strings.Repeat("Long", 40)} {
		id, err := generateClaimID(display)
		if err != nil {
			t.Fatalf("%q: %v", display, err)
		}
		if err := validateClaimID(id); err != nil {
			t.Fatalf("generated a non-conforming ID %q from %q: %v", id, display, err)
		}
		if !strings.HasPrefix(id, "ad://ext/") {
			t.Fatalf("generated ID lacks the required prefix: %q", id)
		}
	}
	// Generated identifiers must not collide for the same display name.
	first, err := generateClaimID("Department")
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateClaimID("Department")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("generated the same ID twice: %q", first)
	}
}

func TestClaimValuesListPerValueType(t *testing.T) {
	for valueType, want := range map[ClaimValueType]string{
		ClaimInt64:       "IntegerList",
		ClaimUInt64:      "UnsignedIntegerList",
		ClaimString:      "StringList",
		ClaimFQBN:        "StringList",
		ClaimSID:         "StringList",
		ClaimOctetString: "StringList",
	} {
		if got := claimValuesList(valueType); got != want {
			t.Fatalf("value type %d: got %q want %q", valueType, got, want)
		}
	}
	// Boolean claims carry no suggested value list.
	if got := claimValuesList(ClaimBoolean); got != "" {
		t.Fatalf("boolean must have no list, got %q", got)
	}
}

func TestClaimValueTypeValidity(t *testing.T) {
	for _, valid := range []ClaimValueType{ClaimInt64, ClaimUInt64, ClaimString, ClaimFQBN, ClaimSID, ClaimBoolean, ClaimOctetString} {
		if !validClaimValueType(valid) {
			t.Fatalf("value type %d must be valid", valid)
		}
	}
	for _, invalid := range []ClaimValueType{0, -1, 7, 8, 15, 17, 1000} {
		if validClaimValueType(invalid) {
			t.Fatalf("value type %d must be invalid", invalid)
		}
	}
}

func TestEncodeClaimValuesRequiresExactlyOneTypedValue(t *testing.T) {
	number := int64(1)
	// A suggestion with no value, or with more than one, is ambiguous.
	for name, value := range map[string]ClaimSuggestedValue{
		"none": {},
		"both": {Text: claimText("a"), Integer: &number},
	} {
		if _, err := encodeClaimValues([]ClaimSuggestedValue{value}, ClaimString); !errors.Is(err, ErrClaimType) {
			t.Fatalf("%s: expected ErrClaimType, got %v", name, err)
		}
	}
}

func TestEncodeClaimValuesRoundTrip(t *testing.T) {
	number := int64(-42)
	unsigned := uint64(42)
	cases := map[ClaimValueType][]ClaimSuggestedValue{
		ClaimString: {{Text: claimText("engineering"), DisplayName: claimText("Engineering")}},
		ClaimInt64:  {{Integer: &number}},
		ClaimUInt64: {{Unsigned: &unsigned}},
	}
	for valueType, values := range cases {
		encoded, err := encodeClaimValues(values, valueType)
		if err != nil {
			t.Fatalf("value type %d: encode: %v", valueType, err)
		}
		parsed, err := parseClaimValues(encoded, &valueType)
		if err != nil {
			t.Fatalf("value type %d: parse: %v", valueType, err)
		}
		if len(parsed.Values) != len(values) {
			t.Fatalf("value type %d: round trip lost values: %+v", valueType, parsed.Values)
		}
		if parsed.RawXML != encoded {
			t.Fatalf("value type %d: raw XML was not retained verbatim", valueType)
		}
	}
}

func TestEncodeClaimValuesRejectsMistypedSuggestions(t *testing.T) {
	number := int64(1)
	// Text cannot stand in for an integer list, and an integer cannot stand
	// in for a string list: the value type is not coerced.
	if _, err := encodeClaimValues([]ClaimSuggestedValue{{Text: claimText("x")}}, ClaimInt64); err == nil {
		t.Fatal("text in an integer list must be rejected")
	}
	if _, err := encodeClaimValues([]ClaimSuggestedValue{{Integer: &number}}, ClaimString); err == nil {
		t.Fatal("an integer in a string list must be rejected")
	}
	// Boolean claims have no list to encode into.
	if _, err := encodeClaimValues([]ClaimSuggestedValue{{Text: claimText("x")}}, ClaimBoolean); err == nil {
		t.Fatal("boolean suggestions must be rejected")
	}
}

func TestParseClaimValuesRejectsOversizedAndMalformed(t *testing.T) {
	valueType := ClaimString
	if _, err := parseClaimValues(strings.Repeat("x", claimValuesMaxBytes+1), &valueType); err == nil {
		t.Fatal("an oversized value document must be rejected")
	}
	for name, raw := range map[string]string{
		"not xml":        "nonsense",
		"unclosed":       "<PossibleValues>",
		"wrong root":     "<Other xmlns=\"" + claimValuesNamespace + "\"></Other>",
		"empty document": "",
	} {
		if _, err := parseClaimValues(raw, &valueType); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestParseClaimValuesDisagreeingValueType(t *testing.T) {
	number := int64(7)
	encoded, err := encodeClaimValues([]ClaimSuggestedValue{{Integer: &number}}, ClaimInt64)
	if err != nil {
		t.Fatal(err)
	}
	// An integer list parsed as a string list is a disagreement, not a cast.
	mismatched := ClaimString
	if _, err := parseClaimValues(encoded, &mismatched); err == nil {
		t.Fatal("a disagreeing value type must be rejected")
	}
}

func TestClaimFoldKeyFoldsCaseConsistently(t *testing.T) {
	// Folding must be stable so suggested values cannot differ only by case.
	for _, pair := range [][2]string{{"Engineering", "engineering"}, {"ÄÖÜ", "äöü"}, {"K", "K"}} {
		if claimFoldKey(pair[0]) != claimFoldKey(pair[1]) {
			t.Fatalf("%q and %q must fold alike", pair[0], pair[1])
		}
	}
	if claimFoldKey("engineering") == claimFoldKey("finance") {
		t.Fatal("distinct values must not fold alike")
	}
}

func TestStrconvClaimBool(t *testing.T) {
	if strconvClaimBool(true) != "TRUE" || strconvClaimBool(false) != "FALSE" {
		t.Fatal("directory booleans must render as TRUE and FALSE")
	}
}

func TestClaimValueTypeText(t *testing.T) {
	if got := claimValueTypeText(ClaimOctetString); got != "16" {
		t.Fatalf("octet string rendered as %q", got)
	}
	if got := claimValueTypeText(ClaimInt64); got != "1" {
		t.Fatalf("int64 rendered as %q", got)
	}
}
