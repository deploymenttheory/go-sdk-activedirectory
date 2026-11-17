package acceptance

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestTypedFilterFormsAndLiteralValues(t *testing.T) {
	for _, test := range []struct {
		InternalName   string
		InternalFilter admodel.Filter
		InternalWant   string
	}{
		{"injection", admodel.FilterEqual("cn", admodel.FilterText(`*)(|(objectClass=*))`)), `(cn=\2a\29\28|\28objectClass=\2a\29\29)`},
		{"literal wildcard", admodel.FilterEqual("cn", admodel.FilterText("*")), `(cn=\2a)`},
		{"presence", admodel.FilterPresent("cn"), `(cn=*)`},
		{"UTF-8 and NUL", admodel.FilterEqual("cn", admodel.FilterText("Dŵr 😀\x00")), "(cn=Dŵr 😀\\00)"},
		{"empty text", admodel.FilterEqual("description", admodel.FilterText("")), "(description=)"},
		{"empty binary", admodel.FilterEqual("description", admodel.FilterBytes(nil)), "(description=)"},
		{"binary", admodel.FilterEqual("objectGUID", admodel.FilterBytes([]byte{0, 0xff, 0x80, '*', '\\'})), `(objectGUID=\00\ff\80\2a\5c)`},
		{"ge", admodel.FilterGreaterOrEqual("uSNChanged", admodel.FilterInteger(9007199254740993)), "(uSNChanged>=9007199254740993)"},
		{"le", admodel.FilterLessOrEqual("accountExpires", admodel.FilterInteger(-1)), "(accountExpires<=-1)"},
		{"approx", admodel.FilterApprox("cn", admodel.FilterText("a(b)")), `(cn~=a\28b\29)`},
		{"nested", admodel.FilterAnd(admodel.FilterEqual("objectClass", admodel.FilterText("user")), admodel.FilterOr(admodel.FilterPresent("mail"), admodel.FilterNot(admodel.FilterPresent("description")))), "(&(objectClass=user)(|(mail=*)(!(description=*))))"},
		{"substrings", admodel.FilterSubstrings("cn", admodel.SubstringFilter{Initial: admodel.FilterText("Al*"), Any: []admodel.FilterValue{admodel.FilterText("(middle)"), admodel.FilterBytes([]byte{0xff})}, Final: admodel.FilterText("終")}), `(cn=Al\2a*\28middle\29*\ff*終)`},
		{"prefix", admodel.FilterSubstrings("cn", admodel.SubstringFilter{Initial: admodel.FilterText("Al")}), "(cn=Al*)"},
		{"suffix", admodel.FilterSubstrings("cn", admodel.SubstringFilter{Final: admodel.FilterText("son")}), "(cn=*son)"},
		{"contains", admodel.FilterSubstrings("cn", admodel.SubstringFilter{Any: []admodel.FilterValue{admodel.FilterText("*")}}), `(cn=*\2a*)`},
		{"bit and", admodel.FilterBitAnd("userAccountControl", 2), "(userAccountControl:1.2.840.113556.1.4.803:=2)"},
		{"bit or", admodel.FilterBitOr("groupType", 2147483648), "(groupType:1.2.840.113556.1.4.804:=2147483648)"},
		{"in chain", admodel.FilterInChain("memberOf", `CN=Group\, One,DC=example,DC=test`), `(memberOf:1.2.840.113556.1.4.1941:=CN=Group\5c, One,DC=example,DC=test)`},
		{"DN with data", admodel.FilterExtensible(admodel.ExtensibleFilter{Attribute: "wellKnownObjects", Rule: admodel.MatchingRuleDNWithData, Value: admodel.FilterText("B:2:00:CN=X,DC=test")}), "(wellKnownObjects:1.2.840.113556.1.4.2253:=B:2:00:CN=X,DC=test)"},
		{"extensible DN", admodel.FilterExtensible(admodel.ExtensibleFilter{Rule: "2.5.13.2", DNAttributes: true, Value: admodel.FilterText("X")}), "(:dn:2.5.13.2:=X)"},
		{"default rule", admodel.FilterExtensible(admodel.ExtensibleFilter{Attribute: "cn", Value: admodel.FilterText("X")}), "(cn:=X)"},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			got, err := test.InternalFilter.LDAP()
			if err != nil || got != test.InternalWant {
				t.Fatalf("got %q err=%v want %q", got, err, test.InternalWant)
			}
		})
	}
}

func TestTypedFilterRejectsSyntaxInjectionAndIncompleteNodes(t *testing.T) {
	for _, attribute := range []string{"", "cn)(objectClass", "cn=", "cn:1.2.3", "cn\x00", "é", "1.02.3", "cn;range=0-*", "cn;"} {
		for _, filter := range []admodel.Filter{admodel.FilterPresent(attribute), admodel.FilterEqual(attribute, admodel.FilterText("safe")), admodel.FilterSubstrings(attribute, admodel.SubstringFilter{Initial: admodel.FilterText("a")}), admodel.FilterExtensible(admodel.ExtensibleFilter{Attribute: attribute, Value: admodel.FilterText("a")})} {
			if _, err := filter.LDAP(); !errors.Is(err, admodel.ErrInvalidFilter) {
				t.Fatalf("accepted invalid attribute: %q", attribute)
			}
		}
	}
	for _, filter := range []admodel.Filter{{}, admodel.FilterAnd(), admodel.FilterOr(), admodel.FilterNot(admodel.Filter{}), admodel.FilterAnd(admodel.FilterPresent("cn"), admodel.Filter{}), admodel.FilterEqual("cn", admodel.FilterValue{}), admodel.FilterEqual("cn", admodel.FilterText(string([]byte{0xff}))), admodel.FilterSubstrings("cn", admodel.SubstringFilter{}), admodel.FilterSubstrings("cn", admodel.SubstringFilter{Initial: admodel.FilterText("")}), admodel.FilterSubstrings("cn", admodel.SubstringFilter{Any: []admodel.FilterValue{{}}}), admodel.FilterExtensible(admodel.ExtensibleFilter{Value: admodel.FilterText("x")}), admodel.FilterExtensible(admodel.ExtensibleFilter{Attribute: "cn", Rule: "1.2.3:=x)(cn", Value: admodel.FilterText("x")})} {
		if _, err := filter.LDAP(); !errors.Is(err, admodel.ErrInvalidFilter) {
			t.Fatalf("accepted invalid filter: %+v %v", filter, err)
		}
	}
	for _, attribute := range []string{"cn;lang-en", "1.2.840.113556.1.4.2", "objectGUID;binary"} {
		if _, err := admodel.FilterEqual(attribute, admodel.FilterText("x")).LDAP(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTypedFilterSnapshotsInputsAndBoundsComposition(t *testing.T) {
	input := []byte{1, 2, 3}
	value := admodel.FilterBytes(input)
	input[0] = 255
	filter := admodel.FilterEqual("objectGUID", value)
	got, err := filter.LDAP()
	if err != nil || got != `(objectGUID=\01\02\03)` {
		t.Fatalf("%q %v", got, err)
	}
	children := []admodel.Filter{filter}
	composed := admodel.FilterAnd(children...)
	children[0] = admodel.FilterPresent("cn")
	got, _ = composed.LDAP()
	if got != `(&(objectGUID=\01\02\03))` {
		t.Fatal(got)
	}
	deep := admodel.FilterPresent("cn")
	for i := 1; i < admodel.MaxFilterDepth; i++ {
		deep = admodel.FilterNot(deep)
	}
	if _, err = deep.LDAP(); err != nil {
		t.Fatal(err)
	}
	if _, err = admodel.FilterNot(deep).LDAP(); !errors.Is(err, admodel.ErrFilterLimit) {
		t.Fatal(err)
	}
	wide := admodel.FilterEqual(
		"cn",
		admodel.FilterText(strings.Repeat("x", admodel.MaxFilterBytes/2)),
	)
	if _, err = admodel.FilterOr(wide, wide).LDAP(); !errors.Is(err, admodel.ErrFilterLimit) {
		t.Fatal(err)
	}
	if _, err = admodel.FilterEqual("cn", admodel.FilterBytes(make([]byte, admodel.MaxFilterBytes/3+1))).
		LDAP(); !errors.Is(
		err,
		admodel.ErrFilterLimit,
	) {
		t.Fatal(err)
	}
}

func TestTypedFilterSearchCompatibilityAndErrorPropagation(t *testing.T) {
	options := admodel.SearchOptions{
		TypedFilter: admodel.FilterEqual("cn", admodel.FilterText("*")),
	}
	normalized, err := admodel.InternalSearchOptionsNormalized(options)
	if err != nil || normalized.Filter != `(cn=\2a)` {
		t.Fatalf("%+v %v", normalized, err)
	}
	if _, err = admodel.InternalSearchOptionsNormalized(normalized); err != nil {
		t.Fatalf("normalization not idempotent: %v", err)
	}
	if err = (admodel.SearchOptions{Filter: "(cn=*)", TypedFilter: admodel.FilterPresent("cn")}).Validate(); !errors.Is(
		err,
		admodel.ErrConflictingFilters,
	) {
		t.Fatal(err)
	}
	for _, raw := range []string{"(cn=*)", "intentionally raw invalid grammar"} {
		got, err := admodel.InternalSearchOptionsNormalized((admodel.SearchOptions{Filter: raw}))
		if err != nil || got.Filter != raw {
			t.Fatalf("changed raw behavior: %+v %v", got, err)
		}
	}
	called := false
	nativeErr := &admodel.LDAPError{
		Operation:  "fixture",
		Code:       18,
		Diagnostic: "private matching-rule diagnostic",
	}
	c := adengine.InternalNewClient(
		admodel.Config{Timeout: time.Second},
		InternalTestSession{
			InternalSearch: func(_ context.Context, got admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				called = true
				if got.Filter != `(cn=\2a)` {
					t.Fatal(got.Filter)
				}
				return nil, nativeErr
			},
			InternalFinish: func() error { return nil },
		},
	)
	defer c.Close()
	_, err = c.Search(context.Background(), admodel.SearchOptions{TypedFilter: admodel.FilterAnd()})
	if err == nil || called {
		t.Fatalf("invalid expression reached native search: %v", err)
	}
	_, err = c.Search(context.Background(), options)
	if !errors.Is(err, nativeErr) || !errors.Is(err, admodel.ErrIncompleteResult) ||
		strings.Contains(err.Error(), "private matching-rule diagnostic") {
		t.Fatal(err)
	}
}

func TestDNAndFilterEscapingStayDistinct(t *testing.T) {
	for _, test := range []struct{ InternalValue, InternalWant string }{{" Alice ", `\ Alice\ `}, {"#name", `\#name`}, {"a,b+c\"d\\e<f>g;h=i", `a\,b\+c\"d\\e\<f\>g\;h\=i`}, {"*()", `*()`}, {"Dŵr😀\x00", `Dŵr😀\00`}} {
		got, err := admodel.EscapeDNValue(test.InternalValue)
		if err != nil || got != test.InternalWant {
			t.Fatalf("got=%q want=%q err=%v", got, test.InternalWant, err)
		}
	}
	rdn, err := admodel.EscapeDNValue("Group, *")
	if err != nil {
		t.Fatal(err)
	}
	got, err := admodel.FilterEqual("memberOf", admodel.FilterText("CN="+rdn+",DC=test")).LDAP()
	if err != nil || got != `(memberOf=CN=Group\5c, \2a,DC=test)` {
		t.Fatalf("%q %v", got, err)
	}
	if _, err = admodel.EscapeDNValue(
		string([]byte{255}),
	); !errors.Is(
		err,
		admodel.ErrInvalidDNValue,
	) {
		t.Fatal(err)
	}
}

func TestTypedFilterNativeExtensibleValidationAndPortableOutput(t *testing.T) {
	filter := admodel.FilterNot(
		admodel.FilterOr(
			admodel.FilterInChain("memberOf", `CN=Group\, One,DC=test`),
			admodel.FilterPresent("cn"),
		),
	)
	portable, err := filter.LDAP()
	if err != nil ||
		portable != `(!(|(memberOf:1.2.840.113556.1.4.1941:=CN=Group\5c, One,DC=test)(cn=*)))` {
		t.Fatalf("portable=%q error=%v", portable, err)
	}
	normalized, err := admodel.InternalSearchOptionsNormalized(
		(admodel.SearchOptions{TypedFilter: filter}),
	)
	if err != nil ||
		normalized.Filter != `(!(|(memberOf:1.2.840.113556.1.4.1941:=CN=Group\, One,DC=test)(cn=*)))` {
		t.Fatalf("native=%q error=%v", normalized.Filter, err)
	}
	raw, err := admodel.InternalSearchOptionsNormalized((admodel.SearchOptions{Filter: portable}))
	if err != nil || raw.Filter != portable {
		t.Fatalf("raw filter was reinterpreted: %+v %v", raw, err)
	}
	for _, value := range []admodel.FilterValue{admodel.FilterText("a(b)c"), admodel.FilterText("a\x00b"), admodel.FilterBytes([]byte{255}), admodel.FilterText(`trailing\`)} {
		invalid := admodel.FilterExtensible(
			admodel.ExtensibleFilter{Attribute: "cn", Rule: "2.5.13.2", Value: value},
		)
		for _, wrapped := range []admodel.Filter{invalid, admodel.FilterAnd(invalid), admodel.FilterOr(admodel.FilterPresent("cn"), invalid), admodel.FilterNot(invalid)} {
			if _, err := wrapped.LDAP(); err != nil {
				t.Fatalf("valid portable filter rejected: %v", err)
			}
			if err := (admodel.SearchOptions{TypedFilter: wrapped}).Validate(); !errors.Is(
				err,
				admodel.ErrUnsupportedFilterValue,
			) {
				t.Fatalf("native restriction lost through composition: %v", err)
			}
		}
	}
}

// Independently decode assertion escapes and reject any unescaped structural
// character. This oracle checks that user octets survive without creating nodes.
func InternalDecodeFilterTestLiteral(encoded string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '\\' {
			if i+2 >= len(encoded) {
				return nil, admodel.ErrInvalidFilter
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
			return nil, admodel.ErrInvalidFilter
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
		for _, typed := range []admodel.FilterValue{admodel.FilterText(string(value)), admodel.FilterBytes(value)} {
			got, err := admodel.FilterEqual("cn", typed).LDAP()
			if !admodel.InternalFilterValueBinary(typed) && !utf8.Valid(value) {
				if !errors.Is(err, admodel.ErrInvalidFilter) {
					t.Fatal(err)
				}
				continue
			}
			if err != nil || !strings.HasPrefix(got, "(cn=") || !strings.HasSuffix(got, ")") {
				t.Fatalf("%q %v", got, err)
			}
			decoded, err := InternalDecodeFilterTestLiteral(got[4 : len(got)-1])
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
		leaf := admodel.FilterEqual("cn", admodel.FilterBytes(value))
		filter := leaf
		for i := uint8(0); i < depth%16; i++ {
			if i%2 == 0 {
				filter = admodel.FilterAnd(filter, admodel.FilterNot(leaf))
			} else {
				filter = admodel.FilterOr(filter, leaf)
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
				return admodel.ErrInvalidFilter
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
					return admodel.ErrInvalidFilter
				}
			} else {
				if !strings.HasPrefix(encoded, "cn=") {
					return admodel.ErrInvalidFilter
				}
				end := strings.IndexByte(encoded, ')')
				if end < 0 {
					return admodel.ErrInvalidFilter
				}
				got, err := InternalDecodeFilterTestLiteral(encoded[3:end])
				if err != nil || !bytes.Equal(got, value) {
					return admodel.ErrInvalidFilter
				}
				leaves++
				encoded = encoded[end:]
			}
			if len(encoded) == 0 || encoded[0] != ')' {
				return admodel.ErrInvalidFilter
			}
			encoded = encoded[1:]
			return nil
		}
		if err := parse(); err != nil || encoded != "" || leaves != int(depth%16)+1 {
			t.Fatalf(
				"composition changed grammar/value: leaves=%d rest=%q err=%v",
				leaves,
				encoded,
				err,
			)
		}
	})
}
