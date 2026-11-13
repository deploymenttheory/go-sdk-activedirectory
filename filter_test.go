package activedirectory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestTypedFilterFormsAndLiteralValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		filter Filter
		want   string
	}{
		{"injection", FilterEqual("cn", FilterText(`*)(|(objectClass=*))`)), `(cn=\2a\29\28|\28objectClass=\2a\29\29)`},
		{"literal wildcard", FilterEqual("cn", FilterText("*")), `(cn=\2a)`},
		{"presence", FilterPresent("cn"), `(cn=*)`},
		{"UTF-8 and NUL", FilterEqual("cn", FilterText("Dŵr 😀\x00")), "(cn=Dŵr 😀\\00)"},
		{"empty text", FilterEqual("description", FilterText("")), "(description=)"},
		{"empty binary", FilterEqual("description", FilterBytes(nil)), "(description=)"},
		{"binary", FilterEqual("objectGUID", FilterBytes([]byte{0, 0xff, 0x80, '*', '\\'})), `(objectGUID=\00\ff\80\2a\5c)`},
		{"ge", FilterGreaterOrEqual("uSNChanged", FilterInteger(9007199254740993)), "(uSNChanged>=9007199254740993)"},
		{"le", FilterLessOrEqual("accountExpires", FilterInteger(-1)), "(accountExpires<=-1)"},
		{"approx", FilterApprox("cn", FilterText("a(b)")), `(cn~=a\28b\29)`},
		{"nested", FilterAnd(FilterEqual("objectClass", FilterText("user")), FilterOr(FilterPresent("mail"), FilterNot(FilterPresent("description")))), "(&(objectClass=user)(|(mail=*)(!(description=*))))"},
		{"substrings", FilterSubstrings("cn", SubstringFilter{Initial: FilterText("Al*"), Any: []FilterValue{FilterText("(middle)"), FilterBytes([]byte{0xff})}, Final: FilterText("終")}), `(cn=Al\2a*\28middle\29*\ff*終)`},
		{"prefix", FilterSubstrings("cn", SubstringFilter{Initial: FilterText("Al")}), "(cn=Al*)"},
		{"suffix", FilterSubstrings("cn", SubstringFilter{Final: FilterText("son")}), "(cn=*son)"},
		{"contains", FilterSubstrings("cn", SubstringFilter{Any: []FilterValue{FilterText("*")}}), `(cn=*\2a*)`},
		{"bit and", FilterBitAnd("userAccountControl", 2), "(userAccountControl:1.2.840.113556.1.4.803:=2)"},
		{"bit or", FilterBitOr("groupType", 2147483648), "(groupType:1.2.840.113556.1.4.804:=2147483648)"},
		{"in chain", FilterInChain("memberOf", `CN=Group\, One,DC=example,DC=test`), `(memberOf:1.2.840.113556.1.4.1941:=CN=Group\5c, One,DC=example,DC=test)`},
		{"DN with data", FilterExtensible(ExtensibleFilter{Attribute: "wellKnownObjects", Rule: MatchingRuleDNWithData, Value: FilterText("B:2:00:CN=X,DC=test")}), "(wellKnownObjects:1.2.840.113556.1.4.2253:=B:2:00:CN=X,DC=test)"},
		{"extensible DN", FilterExtensible(ExtensibleFilter{Rule: "2.5.13.2", DNAttributes: true, Value: FilterText("X")}), "(:dn:2.5.13.2:=X)"},
		{"default rule", FilterExtensible(ExtensibleFilter{Attribute: "cn", Value: FilterText("X")}), "(cn:=X)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.filter.LDAP()
			if err != nil || got != test.want {
				t.Fatalf("got %q err=%v want %q", got, err, test.want)
			}
		})
	}
}

func TestTypedFilterRejectsSyntaxInjectionAndIncompleteNodes(t *testing.T) {
	for _, attribute := range []string{"", "cn)(objectClass", "cn=", "cn:1.2.3", "cn\x00", "é", "1.02.3", "cn;range=0-*", "cn;"} {
		for _, filter := range []Filter{FilterPresent(attribute), FilterEqual(attribute, FilterText("safe")), FilterSubstrings(attribute, SubstringFilter{Initial: FilterText("a")}), FilterExtensible(ExtensibleFilter{Attribute: attribute, Value: FilterText("a")})} {
			if _, err := filter.LDAP(); !errors.Is(err, ErrInvalidFilter) {
				t.Fatalf("accepted invalid attribute: %q", attribute)
			}
		}
	}
	for _, filter := range []Filter{Filter{}, FilterAnd(), FilterOr(), FilterNot(Filter{}), FilterAnd(FilterPresent("cn"), Filter{}), FilterEqual("cn", FilterValue{}), FilterEqual("cn", FilterText(string([]byte{0xff}))), FilterSubstrings("cn", SubstringFilter{}), FilterSubstrings("cn", SubstringFilter{Initial: FilterText("")}), FilterSubstrings("cn", SubstringFilter{Any: []FilterValue{{}}}), FilterExtensible(ExtensibleFilter{Value: FilterText("x")}), FilterExtensible(ExtensibleFilter{Attribute: "cn", Rule: "1.2.3:=x)(cn", Value: FilterText("x")})} {
		if _, err := filter.LDAP(); !errors.Is(err, ErrInvalidFilter) {
			t.Fatalf("accepted invalid filter: %+v %v", filter, err)
		}
	}
	for _, attribute := range []string{"cn;lang-en", "1.2.840.113556.1.4.2", "objectGUID;binary"} {
		if _, err := FilterEqual(attribute, FilterText("x")).LDAP(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTypedFilterSnapshotsInputsAndBoundsComposition(t *testing.T) {
	input := []byte{1, 2, 3}
	value := FilterBytes(input)
	input[0] = 255
	filter := FilterEqual("objectGUID", value)
	got, err := filter.LDAP()
	if err != nil || got != `(objectGUID=\01\02\03)` {
		t.Fatalf("%q %v", got, err)
	}
	children := []Filter{filter}
	composed := FilterAnd(children...)
	children[0] = FilterPresent("cn")
	got, _ = composed.LDAP()
	if got != `(&(objectGUID=\01\02\03))` {
		t.Fatal(got)
	}
	deep := FilterPresent("cn")
	for i := 1; i < MaxFilterDepth; i++ {
		deep = FilterNot(deep)
	}
	if _, err = deep.LDAP(); err != nil {
		t.Fatal(err)
	}
	if _, err = FilterNot(deep).LDAP(); !errors.Is(err, ErrFilterLimit) {
		t.Fatal(err)
	}
	wide := FilterEqual("cn", FilterText(strings.Repeat("x", MaxFilterBytes/2)))
	if _, err = FilterOr(wide, wide).LDAP(); !errors.Is(err, ErrFilterLimit) {
		t.Fatal(err)
	}
	if _, err = FilterEqual("cn", FilterBytes(make([]byte, MaxFilterBytes/3+1))).LDAP(); !errors.Is(err, ErrFilterLimit) {
		t.Fatal(err)
	}
}

func TestTypedFilterSearchCompatibilityAndErrorPropagation(t *testing.T) {
	options := SearchOptions{TypedFilter: FilterEqual("cn", FilterText("*"))}
	normalized, err := options.normalized()
	if err != nil || normalized.Filter != `(cn=\2a)` {
		t.Fatalf("%+v %v", normalized, err)
	}
	if _, err = normalized.normalized(); err != nil {
		t.Fatalf("normalization not idempotent: %v", err)
	}
	if err = (SearchOptions{Filter: "(cn=*)", TypedFilter: FilterPresent("cn")}).Validate(); !errors.Is(err, ErrConflictingFilters) {
		t.Fatal(err)
	}
	for _, raw := range []string{"(cn=*)", "intentionally raw invalid grammar"} {
		got, err := (SearchOptions{Filter: raw}).normalized()
		if err != nil || got.Filter != raw {
			t.Fatalf("changed raw behavior: %+v %v", got, err)
		}
	}
	called := false
	nativeErr := &LDAPError{Operation: "fixture", Code: 18, Diagnostic: "private matching-rule diagnostic"}
	c := newClient(Config{Timeout: time.Second}, testSession{search: func(_ context.Context, got SearchOptions) (searchCursor, error) {
		called = true
		if got.Filter != `(cn=\2a)` {
			t.Fatal(got.Filter)
		}
		return nil, nativeErr
	}, finish: func() error { return nil }})
	defer c.Close()
	_, err = c.Search(context.Background(), SearchOptions{TypedFilter: FilterAnd()})
	if err == nil || called {
		t.Fatalf("invalid expression reached native search: %v", err)
	}
	_, err = c.Search(context.Background(), options)
	if !errors.Is(err, nativeErr) || !errors.Is(err, ErrIncompleteResult) || strings.Contains(err.Error(), "private matching-rule diagnostic") {
		t.Fatal(err)
	}
}

func TestDNAndFilterEscapingStayDistinct(t *testing.T) {
	for _, test := range []struct{ value, want string }{{" Alice ", `\ Alice\ `}, {"#name", `\#name`}, {"a,b+c\"d\\e<f>g;h=i", `a\,b\+c\"d\\e\<f\>g\;h\=i`}, {"*()", `*()`}, {"Dŵr😀\x00", `Dŵr😀\00`}} {
		got, err := EscapeDNValue(test.value)
		if err != nil || got != test.want {
			t.Fatalf("got=%q want=%q err=%v", got, test.want, err)
		}
	}
	rdn, err := EscapeDNValue("Group, *")
	if err != nil {
		t.Fatal(err)
	}
	got, err := FilterEqual("memberOf", FilterText("CN="+rdn+",DC=test")).LDAP()
	if err != nil || got != `(memberOf=CN=Group\5c, \2a,DC=test)` {
		t.Fatalf("%q %v", got, err)
	}
	if _, err = EscapeDNValue(string([]byte{255})); !errors.Is(err, ErrInvalidDNValue) {
		t.Fatal(err)
	}
}

func TestTypedFilterNativeExtensibleValidationAndPortableOutput(t *testing.T) {
	filter := FilterNot(FilterOr(FilterInChain("memberOf", `CN=Group\, One,DC=test`), FilterPresent("cn")))
	portable, err := filter.LDAP()
	if err != nil || portable != `(!(|(memberOf:1.2.840.113556.1.4.1941:=CN=Group\5c, One,DC=test)(cn=*)))` {
		t.Fatalf("portable=%q error=%v", portable, err)
	}
	normalized, err := (SearchOptions{TypedFilter: filter}).normalized()
	if err != nil || normalized.Filter != `(!(|(memberOf:1.2.840.113556.1.4.1941:=CN=Group\, One,DC=test)(cn=*)))` {
		t.Fatalf("native=%q error=%v", normalized.Filter, err)
	}
	raw, err := (SearchOptions{Filter: portable}).normalized()
	if err != nil || raw.Filter != portable {
		t.Fatalf("raw filter was reinterpreted: %+v %v", raw, err)
	}
	for _, value := range []FilterValue{FilterText("a(b)c"), FilterText("a\x00b"), FilterBytes([]byte{255}), FilterText(`trailing\`)} {
		invalid := FilterExtensible(ExtensibleFilter{Attribute: "cn", Rule: "2.5.13.2", Value: value})
		for _, wrapped := range []Filter{invalid, FilterAnd(invalid), FilterOr(FilterPresent("cn"), invalid), FilterNot(invalid)} {
			if _, err := wrapped.LDAP(); err != nil {
				t.Fatalf("valid portable filter rejected: %v", err)
			}
			if err := (SearchOptions{TypedFilter: wrapped}).Validate(); !errors.Is(err, ErrUnsupportedFilterValue) {
				t.Fatalf("native restriction lost through composition: %v", err)
			}
		}
	}
}

// Independently decode assertion escapes and reject any unescaped structural
// character. This oracle checks that user octets survive without creating nodes.
func decodeFilterTestLiteral(encoded string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '\\' {
			if i+2 >= len(encoded) {
				return nil, ErrInvalidFilter
			}
			b, err := hex.DecodeString(encoded[i+1 : i+3])
			if err != nil {
				return nil, err
			}
			out = append(out, b[0])
			i += 2
			continue
		}
		if strings.ContainsRune("\x00()*", rune(encoded[i])) {
			return nil, ErrInvalidFilter
		}
		out = append(out, encoded[i])
	}
	return out, nil
}

func FuzzFilterLiteralEscaping(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("*)(|(objectClass=*))"), []byte("Dŵr😀"), {0, 255, 128, '\\', '*'}, []byte(`\2a`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > 4096 {
			t.Skip()
		}
		for _, typed := range []FilterValue{FilterText(string(value)), FilterBytes(value)} {
			got, err := FilterEqual("cn", typed).LDAP()
			if !typed.binary && !utf8.Valid(value) {
				if !errors.Is(err, ErrInvalidFilter) {
					t.Fatal(err)
				}
				continue
			}
			if err != nil || !strings.HasPrefix(got, "(cn=") || !strings.HasSuffix(got, ")") {
				t.Fatalf("%q %v", got, err)
			}
			decoded, err := decodeFilterTestLiteral(got[4 : len(got)-1])
			if err != nil || !bytes.Equal(decoded, value) {
				t.Fatalf("assertion changed or injected syntax: %x %v", decoded, err)
			}
		}
	})
}

func FuzzFilterComposition(f *testing.F) {
	f.Add([]byte("a*()"), uint8(4))
	f.Add([]byte{0, 255, 92}, uint8(7))
	f.Fuzz(func(t *testing.T, value []byte, depth uint8) {
		if len(value) > 1024 {
			t.Skip()
		}
		leaf := FilterEqual("cn", FilterBytes(value))
		filter := leaf
		for i := uint8(0); i < depth%16; i++ {
			if i%2 == 0 {
				filter = FilterAnd(filter, FilterNot(leaf))
			} else {
				filter = FilterOr(filter, leaf)
			}
		}
		encoded, err := filter.LDAP()
		if err != nil {
			t.Fatal(err)
		}
		leaves := 0
		var parse func() error
		parse = func() error {
			if len(encoded) == 0 || encoded[0] != '(' {
				return ErrInvalidFilter
			}
			encoded = encoded[1:]
			if len(encoded) > 0 && strings.ContainsRune("&|!", rune(encoded[0])) {
				op := encoded[0]
				encoded = encoded[1:]
				count := 0
				for strings.HasPrefix(encoded, "(") {
					if err := parse(); err != nil {
						return err
					}
					count++
				}
				if count == 0 || (op == '!' && count != 1) {
					return ErrInvalidFilter
				}
			} else {
				if !strings.HasPrefix(encoded, "cn=") {
					return ErrInvalidFilter
				}
				end := strings.IndexByte(encoded, ')')
				if end < 0 {
					return ErrInvalidFilter
				}
				got, err := decodeFilterTestLiteral(encoded[3:end])
				if err != nil || !bytes.Equal(got, value) {
					return ErrInvalidFilter
				}
				leaves++
				encoded = encoded[end:]
			}
			if len(encoded) == 0 || encoded[0] != ')' {
				return ErrInvalidFilter
			}
			encoded = encoded[1:]
			return nil
		}
		if err := parse(); err != nil || encoded != "" || leaves != int(depth%16)+1 {
			t.Fatalf("composition changed grammar/value: leaves=%d rest=%q err=%v", leaves, encoded, err)
		}
	})
}
