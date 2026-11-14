package activedirectory

import (
	"encoding/json"
	"errors"
	"testing"
)

// Identity holds a []byte for the GUID and SID forms, so it is not comparable
// with == and cannot be a map key. Comparison here is explicit over all three
// fields, so "round-trips" means every field was reconstructed rather than
// only the two that print.
func identityEqual(a, b Identity) bool {
	return a.form == b.form && a.value == b.value && string(a.binary) == string(b.binary)
}

// The prefixes are API, not an implementation detail: an identity written down
// by one build has to parse in the next. Pinning the exact strings makes a
// rename fail here rather than silently orphaning every stored identifier.
func TestIdentityFormNamesAreStable(t *testing.T) {
	for form, want := range map[IdentityForm]string{
		IdentityFormDN:          "dn",
		IdentityFormGUID:        "guid",
		IdentityFormSID:         "sid",
		IdentityFormAccountName: "sam",
	} {
		if got := form.String(); got != want {
			t.Errorf("form %d prints %q, want %q", form, got, want)
		}
	}
	if got := IdentityForm(0).String(); got != "invalid identity form" {
		t.Errorf("the zero form prints %q; it must not read as a usable form", got)
	}
	if got := IdentityForm(99).String(); got != "invalid identity form" {
		t.Errorf("an out-of-range form prints %q", got)
	}
}

// Every form must survive being written down and read back. The distinguished
// names here are the ones the lab identity qualification uses, plus a colon,
// because the encoding separates on a colon and a DN may legitimately hold one.
func TestIdentityTextRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func() (Identity, error)
		text  string
	}{
		{
			"distinguished name",
			func() (Identity, error) { return IdentityByDN("CN=sdk,OU=People,DC=ad,DC=sdk,DC=test") },
			"dn:CN=sdk,OU=People,DC=ad,DC=sdk,DC=test",
		},
		{
			"distinguished name with escaped comma and plus",
			func() (Identity, error) { return IdentityByDN(`CN=sdk\,esc\+name,DC=ad,DC=sdk,DC=test`) },
			`dn:CN=sdk\,esc\+name,DC=ad,DC=sdk,DC=test`,
		},
		{
			"distinguished name holding a colon",
			func() (Identity, error) { return IdentityByDN("CN=sdk:colon,DC=ad,DC=sdk,DC=test") },
			"dn:CN=sdk:colon,DC=ad,DC=sdk,DC=test",
		},
		{
			"distinguished name with non-ASCII and a supplementary-plane character",
			func() (Identity, error) { return IdentityByDN("CN=sdké\U0001f511,DC=ad,DC=sdk,DC=test") },
			"dn:CN=sdké\U0001f511,DC=ad,DC=sdk,DC=test",
		},
		{
			"GUID",
			func() (Identity, error) { return IdentityByGUID("6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11") },
			"guid:6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11",
		},
		{
			"SID",
			func() (Identity, error) { return IdentityBySID("S-1-5-21-1004336348-1177238915-682003330-512") },
			"sid:S-1-5-21-1004336348-1177238915-682003330-512",
		},
		{
			"account name",
			func() (Identity, error) { return IdentityByAccountName("sdkuser") },
			"sam:sdkuser",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			original, err := test.build()
			if err != nil {
				t.Fatalf("the fixture identity does not build: %v", err)
			}
			encoded, err := original.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText: %v", err)
			}
			if string(encoded) != test.text {
				t.Fatalf("encoded %q, want %q", encoded, test.text)
			}
			parsed, err := ParseIdentity(string(encoded))
			if err != nil {
				t.Fatalf("ParseIdentity(%q): %v", encoded, err)
			}
			// Every field, including the binary a GUID and a SID carry, so
			// "round-trips" means the identity is reconstructed rather than
			// merely re-printed.
			if !identityEqual(parsed, original) {
				t.Fatalf("round trip changed the identity:\n got %#v\nwant %#v", parsed, original)
			}
			if parsed.Form() != original.Form() {
				t.Errorf("form changed: got %s, want %s", parsed.Form(), original.Form())
			}
			if parsed.String() != original.String() {
				t.Errorf("value changed: got %q, want %q", parsed.String(), original.String())
			}
		})
	}
}

// A GUID and a SID carry bytes beside their text. The round trip has to
// reconstruct those bytes, not just an equal-looking string, because the bytes
// are what reaches the directory.
func TestIdentityTextReconstructsBinaryForms(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func() (Identity, error)
	}{
		{"GUID", func() (Identity, error) { return IdentityByGUID("6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11") }},
		{"SID", func() (Identity, error) {
			return IdentityBySID("S-1-5-21-1004336348-1177238915-682003330-512")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			original, err := test.build()
			if err != nil {
				t.Fatal(err)
			}
			if len(original.binary) == 0 {
				t.Fatal("the fixture carries no bytes, so this test proves nothing")
			}
			encoded, err := original.MarshalText()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseIdentity(string(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if string(parsed.binary) != string(original.binary) {
				t.Fatalf("bytes changed through the round trip:\n got %x\nwant %x",
					parsed.binary, original.binary)
			}
		})
	}
}

// The zero value is invalid, so it must be refused rather than encoded. An
// identity persisted as ":" would read back as something that names nothing.
func TestZeroIdentityCannotBeEncoded(t *testing.T) {
	var zero Identity
	if _, err := zero.MarshalText(); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("MarshalText on the zero identity returned %v, want ErrInvalidIdentity", err)
	}
	if got := Classify(func() error { _, err := zero.MarshalText(); return err }()); got != ClassInvalidRequest {
		t.Errorf("the refusal classifies as %s, want invalid-request", got)
	}
}

// Text that does not say which form it is must be refused, never guessed. That
// refusal is the whole reason the prefix exists.
func TestParseIdentityRefusesAmbiguousAndMalformedText(t *testing.T) {
	for _, test := range []struct {
		name string
		text string
	}{
		{"no prefix at all", "CN=sdk,DC=ad,DC=sdk,DC=test"},
		{"a bare GUID, which is not self-describing", "6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11"},
		{"empty", ""},
		{"unknown form", "upn:sdk@ad.sdk.test"},
		{"a form that is not a name", "1:CN=sdk,DC=test"},
		{"prefix only", "guid:"},
		{"a GUID that is not one", "guid:not-a-guid"},
		{"a SID that is not one", "sid:S-not-a-sid"},
		{"a DN that is not one", "dn:not a dn"},
		{"an account name with a domain qualifier", `sam:AD\sdkuser`},
		{"an account name that is a UPN", "sam:sdk@ad.sdk.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, err := ParseIdentity(test.text)
			if err == nil {
				t.Fatalf("ParseIdentity(%q) returned %#v, want a refusal", test.text, identity)
			}
			if !identityEqual(identity, Identity{}) {
				t.Errorf("a refused parse returned a non-zero identity: %#v", identity)
			}
			// Every refusal must classify the same way, so a caller handles
			// a bad stored identifier in one place.
			if got := Classify(err); got != ClassInvalidRequest {
				t.Errorf("%q classified as %s, want invalid-request (%v)", test.text, got, err)
			}
		})
	}
}

// UnmarshalText must leave the receiver untouched on a refusal rather than
// half-assign it, so a failed decode cannot quietly replace a good identity
// with a broken one.
func TestUnmarshalTextLeavesTheReceiverIntactOnFailure(t *testing.T) {
	good, err := IdentityByDN("CN=sdk,DC=ad,DC=sdk,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	subject := good
	if err := subject.UnmarshalText([]byte("guid:not-a-guid")); err == nil {
		t.Fatal("UnmarshalText accepted a malformed GUID")
	}
	if !identityEqual(subject, good) {
		t.Fatalf("the receiver changed on a failed decode:\n got %#v\nwant %#v", subject, good)
	}
	if err := subject.UnmarshalText([]byte("sam:sdkuser")); err != nil {
		t.Fatalf("UnmarshalText on valid text: %v", err)
	}
	if subject.Form() != IdentityFormAccountName || subject.String() != "sdkuser" {
		t.Fatalf("a successful decode produced %#v", subject)
	}
}

// Implementing the two text interfaces is what makes an Identity usable inside
// anything that persists state, because the struct's fields are unexported and
// would otherwise encode as an empty object.
func TestIdentityEncodesInsideJSON(t *testing.T) {
	type record struct {
		Resource string   `json:"resource"`
		ID       Identity `json:"id"`
	}
	original, err := IdentityByGUID("6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(record{Resource: "user", ID: original})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"resource":"user","id":"guid:6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11"}`
	if string(data) != want {
		t.Fatalf("encoded %s, want %s", data, want)
	}
	var decoded record
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !identityEqual(decoded.ID, original) {
		t.Fatalf("the identity did not survive JSON:\n got %#v\nwant %#v", decoded.ID, original)
	}
	// A stored identifier that has gone bad must fail the decode rather than
	// arrive as a zero identity that later reads as "not found".
	if err := json.Unmarshal([]byte(`{"id":"guid:not-a-guid"}`), &decoded); err == nil {
		t.Error("a malformed stored identity decoded without error")
	}
}

// String stays the diagnostic form. Pinning that keeps a future change from
// quietly making it the round-trippable one, which would make two encodings
// for the same thing and leave callers guessing which they were handed.
func TestStringRemainsTheValueWithoutTheForm(t *testing.T) {
	identity, err := IdentityByGUID("6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11")
	if err != nil {
		t.Fatal(err)
	}
	if got := identity.String(); got != "6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11" {
		t.Fatalf("String = %q, want the bare value", got)
	}
	if _, err := ParseIdentity(identity.String()); err == nil {
		t.Fatal("String produced text ParseIdentity accepted; the two forms must stay distinct")
	}
}
