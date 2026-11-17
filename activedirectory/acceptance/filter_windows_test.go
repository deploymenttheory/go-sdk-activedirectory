//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// These are actual WinLDAP string-to-BER tests against the existing loopback
// responder. Expected ASN.1 is assembled independently of the typed encoder.
func TestTypedFilterNativeBERAndOwnership(t *testing.T) {
	guid, _ := hex.DecodeString("33221100554477668899aabbccddeeff")
	sid, _ := hex.DecodeString("0105000000000005150000006f000000de0000004d010000e9030000")
	assertion := func(tag byte, attribute string, value []byte) []byte {
		return InternalSearchBER(
			tag,
			InternalSearchBER(4, []byte(attribute)),
			InternalSearchBER(4, value),
		)
	}
	for _, test := range []struct {
		InternalName   string
		InternalFilter admodel.Filter
		InternalWant   []byte
	}{
		{"injection", admodel.FilterEqual("cn", admodel.FilterText(`*)(|(objectClass=*))`)), assertion(0xa3, "cn", []byte(`*)(|(objectClass=*))`))},
		{"unicode-nul", admodel.FilterEqual("cn", admodel.FilterText("Dŵr😀\x00")), assertion(0xa3, "cn", []byte("Dŵr😀\x00"))},
		{"guid", admodel.FilterEqual("objectGUID", admodel.FilterBytes(guid)), assertion(0xa3, "objectGUID", guid)},
		{"sid", admodel.FilterEqual("objectSid", admodel.FilterBytes(sid)), assertion(0xa3, "objectSid", sid)},
		{"presence", admodel.FilterPresent("description"), InternalSearchBER(0x87, []byte("description"))},
		{"literal-wildcard", admodel.FilterEqual("cn", admodel.FilterText("*")), assertion(0xa3, "cn", []byte("*"))},
		{"greater-or-equal", admodel.FilterGreaterOrEqual("uSNChanged", admodel.FilterInteger(9007199254740993)), assertion(0xa5, "uSNChanged", []byte("9007199254740993"))},
		{"less-or-equal", admodel.FilterLessOrEqual("uSNChanged", admodel.FilterInteger(42)), assertion(0xa6, "uSNChanged", []byte("42"))},
		{"approx", admodel.FilterApprox("cn", admodel.FilterText("A")), assertion(0xa8, "cn", []byte("A"))},
		{"substrings", admodel.FilterSubstrings("cn", admodel.SubstringFilter{Initial: admodel.FilterText("A*"), Any: []admodel.FilterValue{admodel.FilterText("(B)")}, Final: admodel.FilterText("終")}), InternalSearchBER(0xa4, InternalSearchBER(4, []byte("cn")), InternalSearchBER(0x30, InternalSearchBER(0x80, []byte("A*")), InternalSearchBER(0x81, []byte("(B)")), InternalSearchBER(0x82, []byte("終"))))},
		{"nested", admodel.FilterAnd(admodel.FilterPresent("cn"), admodel.FilterOr(admodel.FilterEqual("objectGUID", admodel.FilterBytes(guid)), admodel.FilterNot(admodel.FilterPresent("mail")))), InternalSearchBER(0xa0, InternalSearchBER(0x87, []byte("cn")), InternalSearchBER(0xa1, assertion(0xa3, "objectGUID", guid), InternalSearchBER(0xa2, InternalSearchBER(0x87, []byte("mail")))))},
		{"bit-and", admodel.FilterBitAnd("userAccountControl", 2), InternalSearchBER(0xa9, InternalSearchBER(0x81, []byte(admodel.MatchingRuleBitAnd)), InternalSearchBER(0x82, []byte("userAccountControl")), InternalSearchBER(0x83, []byte("2")))},
		{"bit-or", admodel.FilterBitOr("groupType", 2147483648), InternalSearchBER(0xa9, InternalSearchBER(0x81, []byte(admodel.MatchingRuleBitOr)), InternalSearchBER(0x82, []byte("groupType")), InternalSearchBER(0x83, []byte("2147483648")))},
		{"in-chain", admodel.FilterInChain("memberOf", `CN=Group\, One,DC=test`), InternalSearchBER(0xa9, InternalSearchBER(0x81, []byte(admodel.MatchingRuleInChain)), InternalSearchBER(0x82, []byte("memberOf")), InternalSearchBER(0x83, []byte(`CN=Group\, One,DC=test`)))},
		{"in-chain-unicode-wildcard", admodel.FilterInChain("memberOf", `CN=Dŵr*\, One,DC=test`), InternalSearchBER(0xa9, InternalSearchBER(0x81, []byte(admodel.MatchingRuleInChain)), InternalSearchBER(0x82, []byte("memberOf")), InternalSearchBER(0x83, []byte(`CN=Dŵr*\, One,DC=test`)))},
		{"extensible-literal-hex", admodel.FilterExtensible(admodel.ExtensibleFilter{Attribute: "cn", Rule: "2.5.13.2", Value: admodel.FilterText(`a\29`)}), InternalSearchBER(0xa9, InternalSearchBER(0x81, []byte("2.5.13.2")), InternalSearchBER(0x82, []byte("cn")), InternalSearchBER(0x83, []byte(`a\29`)))},
		{"dn-with-data", admodel.FilterExtensible(admodel.ExtensibleFilter{Attribute: "wellKnownObjects", Rule: admodel.MatchingRuleDNWithData, Value: admodel.FilterText("B:2:00:DC=test")}), InternalSearchBER(0xa9, InternalSearchBER(0x81, []byte(admodel.MatchingRuleDNWithData)), InternalSearchBER(0x82, []byte("wellKnownObjects")), InternalSearchBER(0x83, []byte("B:2:00:DC=test")))},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			f := InternalNewSearchWireFixture(
				t,
				[]InternalSearchWirePage{{InternalEmptyCookie: true}},
			)
			var counts InternalSearchNativeCounts
			c := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
			result, err := c.Search(
				context.Background(),
				admodel.SearchOptions{Base: "DC=example", TypedFilter: test.InternalFilter},
			)
			if err != nil || !result.Complete {
				t.Fatalf("native typed search: %+v %v", result, err)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			f.InternalMu.Lock()
			filters := append([][]byte(nil), f.InternalFilters...)
			f.InternalMu.Unlock()
			if len(filters) != 1 ||
				!bytes.Equal(
					InternalNormalizeFilterBER(t, filters[0]),
					InternalNormalizeFilterBER(t, test.InternalWant),
				) {
				t.Fatalf("WinLDAP BER=%x want=%x", filters, test.InternalWant)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("native owners leaked: %+v", counts)
			}
		})
	}
}

// BER permits long-form lengths and an explicit DEFAULT FALSE boolean.
// Normalize those representational differences while retaining every value byte.
func InternalNormalizeFilterBER(t *testing.T, encoded []byte) []byte {
	t.Helper()
	var normalized []byte
	for len(encoded) > 0 {
		tag := encoded[0]
		value, rest, err := InternalTakeSearchBER(encoded, tag)
		if err != nil {
			t.Fatal(err)
		}
		if tag == 0x84 && len(value) == 1 && value[0] == 0 {
			encoded = rest
			continue
		}
		if tag&0x20 != 0 {
			value = InternalNormalizeFilterBER(t, value)
		}
		normalized = append(normalized, InternalSearchBER(tag, value)...)
		encoded = rest
	}
	return normalized
}

func TestTypedFilterNativeExtensibleRejectsUnsafeValuesBeforeIO(t *testing.T) {
	f := InternalNewSearchWireFixture(t, []InternalSearchWirePage{{InternalEmptyCookie: true}})
	var counts InternalSearchNativeCounts
	c := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
	for _, value := range []admodel.FilterValue{admodel.FilterText(`*)(|(objectClass=*))`), admodel.FilterText("a(b)c"), admodel.FilterText("a\x00b"), admodel.FilterBytes([]byte{0xff}), admodel.FilterText(`trailing\`)} {
		filter := admodel.FilterAnd(
			admodel.FilterPresent("objectClass"),
			admodel.FilterExtensible(
				admodel.ExtensibleFilter{
					Attribute: "memberOf",
					Rule:      admodel.MatchingRuleInChain,
					Value:     value,
				},
			),
		)
		if _, err := filter.LDAP(); err != nil {
			t.Fatalf("portable RFC filter unavailable: %v", err)
		}
		if _, err := c.Search(
			context.Background(),
			admodel.SearchOptions{Base: "DC=example", TypedFilter: filter},
		); !errors.Is(
			err,
			admodel.ErrUnsupportedFilterValue,
		) {
			t.Fatalf("unsafe native assertion accepted: %v", err)
		}
	}
	// A valid following search proves rejected input neither used nor retired
	// the native session. The responder must see exactly this one request.
	if _, err := c.Search(
		context.Background(),
		admodel.SearchOptions{Base: "DC=example", TypedFilter: admodel.FilterPresent("cn")},
	); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	f.InternalMu.Lock()
	count := len(f.InternalFilters)
	f.InternalMu.Unlock()
	if count != 1 || counts != (InternalSearchNativeCounts{}) {
		t.Fatalf("requests=%d owners=%+v", count, counts)
	}
}

func TestTypedFilterNativeErrorsPreservePartialResults(t *testing.T) {
	for _, code := range []byte{18, 50, 12} {
		t.Run(string(rune('A'+code)), func(t *testing.T) {
			f := InternalNewSearchWireFixture(
				t,
				[]InternalSearchWirePage{
					{InternalCount: 1, InternalCode: code, InternalEmptyCookie: true},
				},
			)
			var counts InternalSearchNativeCounts
			c := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
			result, err := c.Search(
				context.Background(),
				admodel.SearchOptions{
					Base:        "DC=example",
					TypedFilter: admodel.FilterBitAnd("userAccountControl", 2),
				},
			)
			var native *admodel.LDAPError
			if !errors.As(err, &native) || native.Code != uint32(code) ||
				native.Diagnostic != "private test diagnostic" ||
				result.Complete ||
				len(result.Objects) != 1 {
				t.Fatalf("result=%+v error=%v native=%+v", result, err, native)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("native owners leaked: %+v", counts)
			}
		})
	}
}

func TestTypedFilterNativeEmptyAssertionErrorAndOwnership(t *testing.T) {
	// RFC 4515 permits this empty assertion. Preserve the actual WinLDAP
	// parser error, without silently changing it to a presence/absence test.
	f := InternalNewSearchWireFixture(t, nil)
	var counts InternalSearchNativeCounts
	c := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
	result, err := c.Search(
		context.Background(),
		admodel.SearchOptions{
			Base:        "DC=example",
			TypedFilter: admodel.FilterEqual("description", admodel.FilterBytes(nil)),
		},
	)
	var native *admodel.LDAPError
	if !errors.As(err, &native) || native.Code != 87 || result.Complete ||
		len(result.Objects) != 0 {
		t.Fatalf("result=%+v error=%v native=%+v", result, err, native)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	f.InternalMu.Lock()
	count := len(f.InternalFilters)
	f.InternalMu.Unlock()
	if count != 0 || counts != (InternalSearchNativeCounts{}) {
		t.Fatalf("requests=%d owners=%+v", count, counts)
	}
}
