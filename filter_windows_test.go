//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
)

// These are actual WinLDAP string-to-BER tests against the existing loopback
// responder. Expected ASN.1 is assembled independently of the typed encoder.
func TestTypedFilterNativeBERAndOwnership(t *testing.T) {
	guid, _ := hex.DecodeString("33221100554477668899aabbccddeeff")
	sid, _ := hex.DecodeString("0105000000000005150000006f000000de0000004d010000e9030000")
	assertion := func(tag byte, attribute string, value []byte) []byte {
		return searchBER(tag, searchBER(4, []byte(attribute)), searchBER(4, value))
	}
	for _, test := range []struct {
		name   string
		filter Filter
		want   []byte
	}{
		{"injection", FilterEqual("cn", FilterText(`*)(|(objectClass=*))`)), assertion(0xa3, "cn", []byte(`*)(|(objectClass=*))`))},
		{"unicode-nul", FilterEqual("cn", FilterText("Dŵr😀\x00")), assertion(0xa3, "cn", []byte("Dŵr😀\x00"))},
		{"guid", FilterEqual("objectGUID", FilterBytes(guid)), assertion(0xa3, "objectGUID", guid)},
		{"sid", FilterEqual("objectSid", FilterBytes(sid)), assertion(0xa3, "objectSid", sid)},
		{"presence", FilterPresent("description"), searchBER(0x87, []byte("description"))},
		{"literal-wildcard", FilterEqual("cn", FilterText("*")), assertion(0xa3, "cn", []byte("*"))},
		{"greater-or-equal", FilterGreaterOrEqual("uSNChanged", FilterInteger(9007199254740993)), assertion(0xa5, "uSNChanged", []byte("9007199254740993"))},
		{"less-or-equal", FilterLessOrEqual("uSNChanged", FilterInteger(42)), assertion(0xa6, "uSNChanged", []byte("42"))},
		{"approx", FilterApprox("cn", FilterText("A")), assertion(0xa8, "cn", []byte("A"))},
		{"substrings", FilterSubstrings("cn", SubstringFilter{Initial: FilterText("A*"), Any: []FilterValue{FilterText("(B)")}, Final: FilterText("終")}), searchBER(0xa4, searchBER(4, []byte("cn")), searchBER(0x30, searchBER(0x80, []byte("A*")), searchBER(0x81, []byte("(B)")), searchBER(0x82, []byte("終"))))},
		{"nested", FilterAnd(FilterPresent("cn"), FilterOr(FilterEqual("objectGUID", FilterBytes(guid)), FilterNot(FilterPresent("mail")))), searchBER(0xa0, searchBER(0x87, []byte("cn")), searchBER(0xa1, assertion(0xa3, "objectGUID", guid), searchBER(0xa2, searchBER(0x87, []byte("mail")))))},
		{"bit-and", FilterBitAnd("userAccountControl", 2), searchBER(0xa9, searchBER(0x81, []byte(MatchingRuleBitAnd)), searchBER(0x82, []byte("userAccountControl")), searchBER(0x83, []byte("2")))},
		{"bit-or", FilterBitOr("groupType", 2147483648), searchBER(0xa9, searchBER(0x81, []byte(MatchingRuleBitOr)), searchBER(0x82, []byte("groupType")), searchBER(0x83, []byte("2147483648")))},
		{"in-chain", FilterInChain("memberOf", `CN=Group\, One,DC=test`), searchBER(0xa9, searchBER(0x81, []byte(MatchingRuleInChain)), searchBER(0x82, []byte("memberOf")), searchBER(0x83, []byte(`CN=Group\, One,DC=test`)))},
		{"in-chain-unicode-wildcard", FilterInChain("memberOf", `CN=Dŵr*\, One,DC=test`), searchBER(0xa9, searchBER(0x81, []byte(MatchingRuleInChain)), searchBER(0x82, []byte("memberOf")), searchBER(0x83, []byte(`CN=Dŵr*\, One,DC=test`)))},
		{"extensible-literal-hex", FilterExtensible(ExtensibleFilter{Attribute: "cn", Rule: "2.5.13.2", Value: FilterText(`a\29`)}), searchBER(0xa9, searchBER(0x81, []byte("2.5.13.2")), searchBER(0x82, []byte("cn")), searchBER(0x83, []byte(`a\29`)))},
		{"dn-with-data", FilterExtensible(ExtensibleFilter{Attribute: "wellKnownObjects", Rule: MatchingRuleDNWithData, Value: FilterText("B:2:00:DC=test")}), searchBER(0xa9, searchBER(0x81, []byte(MatchingRuleDNWithData)), searchBER(0x82, []byte("wellKnownObjects")), searchBER(0x83, []byte("B:2:00:DC=test")))},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSearchWireFixture(t, []searchWirePage{{emptyCookie: true}})
			var counts searchNativeCounts
			c := searchWireClient(t, f, countedSearchAPI(&counts))
			result, err := c.Search(context.Background(), SearchOptions{Base: "DC=example", TypedFilter: test.filter})
			if err != nil || !result.Complete {
				t.Fatalf("native typed search: %+v %v", result, err)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			filters := append([][]byte(nil), f.filters...)
			f.mu.Unlock()
			if len(filters) != 1 || !bytes.Equal(normalizeFilterBER(t, filters[0]), normalizeFilterBER(t, test.want)) {
				t.Fatalf("WinLDAP BER=%x want=%x", filters, test.want)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("native owners leaked: %+v", counts)
			}
		})
	}
}

// BER permits long-form lengths and an explicit DEFAULT FALSE boolean.
// Normalize those representational differences while retaining every value byte.
func normalizeFilterBER(t *testing.T, encoded []byte) []byte {
	t.Helper()
	var normalized []byte
	for len(encoded) > 0 {
		tag := encoded[0]
		value, rest, err := takeSearchBER(encoded, tag)
		if err != nil {
			t.Fatal(err)
		}
		if tag == 0x84 && len(value) == 1 && value[0] == 0 {
			encoded = rest
			continue
		}
		if tag&0x20 != 0 {
			value = normalizeFilterBER(t, value)
		}
		normalized = append(normalized, searchBER(tag, value)...)
		encoded = rest
	}
	return normalized
}

func TestTypedFilterNativeExtensibleRejectsUnsafeValuesBeforeIO(t *testing.T) {
	f := newSearchWireFixture(t, []searchWirePage{{emptyCookie: true}})
	var counts searchNativeCounts
	c := searchWireClient(t, f, countedSearchAPI(&counts))
	for _, value := range []FilterValue{FilterText(`*)(|(objectClass=*))`), FilterText("a(b)c"), FilterText("a\x00b"), FilterBytes([]byte{0xff}), FilterText(`trailing\`)} {
		filter := FilterAnd(FilterPresent("objectClass"), FilterExtensible(ExtensibleFilter{Attribute: "memberOf", Rule: MatchingRuleInChain, Value: value}))
		if _, err := filter.LDAP(); err != nil {
			t.Fatalf("portable RFC filter unavailable: %v", err)
		}
		if _, err := c.Search(context.Background(), SearchOptions{Base: "DC=example", TypedFilter: filter}); !errors.Is(err, ErrUnsupportedFilterValue) {
			t.Fatalf("unsafe native assertion accepted: %v", err)
		}
	}
	// A valid following search proves rejected input neither used nor retired
	// the native session. The responder must see exactly this one request.
	if _, err := c.Search(context.Background(), SearchOptions{Base: "DC=example", TypedFilter: FilterPresent("cn")}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	count := len(f.filters)
	f.mu.Unlock()
	if count != 1 || counts != (searchNativeCounts{}) {
		t.Fatalf("requests=%d owners=%+v", count, counts)
	}
}

func TestTypedFilterNativeErrorsPreservePartialResults(t *testing.T) {
	for _, code := range []byte{18, 50, 12} {
		t.Run(string(rune('A'+code)), func(t *testing.T) {
			f := newSearchWireFixture(t, []searchWirePage{{count: 1, code: code, emptyCookie: true}})
			var counts searchNativeCounts
			c := searchWireClient(t, f, countedSearchAPI(&counts))
			result, err := c.Search(context.Background(), SearchOptions{Base: "DC=example", TypedFilter: FilterBitAnd("userAccountControl", 2)})
			var native *LDAPError
			if !errors.As(err, &native) || native.Code != uint32(code) || native.Diagnostic != "private test diagnostic" || result.Complete || len(result.Objects) != 1 {
				t.Fatalf("result=%+v error=%v native=%+v", result, err, native)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("native owners leaked: %+v", counts)
			}
		})
	}
}

func TestTypedFilterNativeEmptyAssertionErrorAndOwnership(t *testing.T) {
	// RFC 4515 permits this empty assertion. Preserve the actual WinLDAP
	// parser error, without silently changing it to a presence/absence test.
	f := newSearchWireFixture(t, nil)
	var counts searchNativeCounts
	c := searchWireClient(t, f, countedSearchAPI(&counts))
	result, err := c.Search(context.Background(), SearchOptions{Base: "DC=example", TypedFilter: FilterEqual("description", FilterBytes(nil))})
	var native *LDAPError
	if !errors.As(err, &native) || native.Code != 87 || result.Complete || len(result.Objects) != 0 {
		t.Fatalf("result=%+v error=%v native=%+v", result, err, native)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	count := len(f.filters)
	f.mu.Unlock()
	if count != 0 || counts != (searchNativeCounts{}) {
		t.Fatalf("requests=%d owners=%+v", count, counts)
	}
}
