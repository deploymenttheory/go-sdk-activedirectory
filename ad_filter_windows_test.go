//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestADFilterNativeBERAndOwnership(t *testing.T) {
	guid, _ := hex.DecodeString("33221100554477668899aabbccddeeff")
	sid, _ := hex.DecodeString("0105000000000005150000006f000000de0000004d010000e9030000")
	assertion := func(tag byte, attribute string, value []byte) []byte {
		return searchBER(tag, searchBER(4, []byte(attribute)), searchBER(4, value))
	}
	extensible := func(attribute, rule, value string) []byte {
		return searchBER(0xa9, searchBER(0x81, []byte(rule)), searchBER(0x82, []byte(attribute)), searchBER(0x83, []byte(value)))
	}
	for _, test := range []struct {
		expression string
		options    ADFilterOptions
		want       []byte
	}{
		{`cn -eq $value`, ADFilterOptions{Variables: map[string]any{"value": `*)(|(objectClass=*))`}}, assertion(0xa3, "cn", []byte(`*)(|(objectClass=*))`))},
		{`cn -eq 'Dŵr😀\00'`, ADFilterOptions{}, assertion(0xa3, "cn", []byte("Dŵr😀\x00"))},
		{`ObjectGUID -eq '00112233-4455-6677-8899-aabbccddeeff'`, ADFilterOptions{}, assertion(0xa3, "objectGUID", guid)},
		{`SID -eq 'S-1-5-21-111-222-333-1001'`, ADFilterOptions{Profile: ADFilterUser}, assertion(0xa3, "objectSid", sid)},
		{`LastLogonDate -gt $date`, ADFilterOptions{Profile: ADFilterUser, Variables: map[string]any{"date": time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}}, searchBER(0xa0, searchBER(0xa2, assertion(0xa6, "lastLogonTimestamp", []byte("134117966450000000"))), searchBER(0x87, []byte("lastLogonTimestamp")))},
		{`Enabled -eq $true`, ADFilterOptions{Profile: ADFilterUser}, searchBER(0xa2, extensible("userAccountControl", string(MatchingRuleBitAnd), "2"))},
		{`cn -like 'A\2a*\28B\29'`, ADFilterOptions{}, searchBER(0xa4, searchBER(4, []byte("cn")), searchBER(0x30, searchBER(0x80, []byte("A*")), searchBER(0x82, []byte("(B)"))))},
		{`memberOf -recursivematch 'CN=Group\5c, One,DC=test'`, ADFilterOptions{}, extensible("memberOf", string(MatchingRuleInChain), `CN=Group\, One,DC=test`)},
		{`cn -notlike '*' -or uSNChanged -ge 9007199254740993`, ADFilterOptions{}, searchBER(0xa1, searchBER(0xa2, searchBER(0x87, []byte("cn"))), assertion(0xa5, "uSNChanged", []byte("9007199254740993")))},
	} {
		t.Run(test.expression, func(t *testing.T) {
			filter, err := ParseADFilter(test.expression, test.options)
			if err != nil {
				t.Fatal(err)
			}
			f := newSearchWireFixture(t, []searchWirePage{{emptyCookie: true}})
			var counts searchNativeCounts
			c := searchWireClient(t, f, countedSearchAPI(&counts))
			result, err := c.Search(context.Background(), SearchOptions{Base: "DC=example", TypedFilter: filter})
			if err != nil || !result.Complete {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			wire := append([][]byte(nil), f.filters...)
			f.mu.Unlock()
			if len(wire) != 1 || !bytes.Equal(normalizeFilterBER(t, wire[0]), normalizeFilterBER(t, test.want)) {
				t.Fatalf("BER=%x want=%x", wire, test.want)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("owners=%+v", counts)
			}
		})
	}
}

func TestADFilterNativePartialPermissionError(t *testing.T) {
	filter, err := ParseADFilter(`Enabled -eq $true`, ADFilterOptions{Profile: ADFilterUser})
	if err != nil {
		t.Fatal(err)
	}
	f := newSearchWireFixture(t, []searchWirePage{{count: 1, code: 50, emptyCookie: true}})
	var counts searchNativeCounts
	c := searchWireClient(t, f, countedSearchAPI(&counts))
	result, err := c.Search(context.Background(), SearchOptions{Base: "DC=example", TypedFilter: filter})
	var native *LDAPError
	if !errors.As(err, &native) || native.Code != 50 || native.Diagnostic != "private test diagnostic" || result.Complete || len(result.Objects) != 1 {
		t.Fatalf("result=%+v native=%+v err=%v", result, native, err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if counts != (searchNativeCounts{}) {
		t.Fatalf("owners=%+v", counts)
	}
}
