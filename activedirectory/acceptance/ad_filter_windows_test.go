//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestADFilterNativeBERAndOwnership(t *testing.T) {
	guid, _ := hex.DecodeString("33221100554477668899aabbccddeeff")
	sid, _ := hex.DecodeString("0105000000000005150000006f000000de0000004d010000e9030000")
	assertion := func(tag byte, attribute string, value []byte) []byte {
		return InternalSearchBER(
			tag,
			InternalSearchBER(4, []byte(attribute)),
			InternalSearchBER(4, value),
		)
	}
	extensible := func(attribute, rule, value string) []byte {
		return InternalSearchBER(
			0xa9,
			InternalSearchBER(0x81, []byte(rule)),
			InternalSearchBER(0x82, []byte(attribute)),
			InternalSearchBER(0x83, []byte(value)),
		)
	}
	for _, test := range []struct {
		InternalExpression string
		InternalOptions    admodel.ADFilterOptions
		InternalWant       []byte
	}{
		{`cn -eq $value`, admodel.ADFilterOptions{Variables: map[string]any{"value": `*)(|(objectClass=*))`}}, assertion(0xa3, "cn", []byte(`*)(|(objectClass=*))`))},
		{`cn -eq 'Dŵr😀\00'`, admodel.ADFilterOptions{}, assertion(0xa3, "cn", []byte("Dŵr😀\x00"))},
		{`ObjectGUID -eq '00112233-4455-6677-8899-aabbccddeeff'`, admodel.ADFilterOptions{}, assertion(0xa3, "objectGUID", guid)},
		{`SID -eq 'S-1-5-21-111-222-333-1001'`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser}, assertion(0xa3, "objectSid", sid)},
		{`LastLogonDate -gt $date`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser, Variables: map[string]any{"date": time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}}, InternalSearchBER(0xa0, InternalSearchBER(0xa2, assertion(0xa6, "lastLogonTimestamp", []byte("134117966450000000"))), InternalSearchBER(0x87, []byte("lastLogonTimestamp")))},
		{`Enabled -eq $true`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser}, InternalSearchBER(0xa2, extensible("userAccountControl", string(admodel.MatchingRuleBitAnd), "2"))},
		{`cn -like 'A\2a*\28B\29'`, admodel.ADFilterOptions{}, InternalSearchBER(0xa4, InternalSearchBER(4, []byte("cn")), InternalSearchBER(0x30, InternalSearchBER(0x80, []byte("A*")), InternalSearchBER(0x82, []byte("(B)"))))},
		{`memberOf -recursivematch 'CN=Group\5c, One,DC=test'`, admodel.ADFilterOptions{}, extensible("memberOf", string(admodel.MatchingRuleInChain), `CN=Group\, One,DC=test`)},
		{`cn -notlike '*' -or uSNChanged -ge 9007199254740993`, admodel.ADFilterOptions{}, InternalSearchBER(0xa1, InternalSearchBER(0xa2, InternalSearchBER(0x87, []byte("cn"))), assertion(0xa5, "uSNChanged", []byte("9007199254740993")))},
	} {
		t.Run(test.InternalExpression, func(t *testing.T) {
			filter, err := admodel.ParseADFilter(test.InternalExpression, test.InternalOptions)
			if err != nil {
				t.Fatal(err)
			}
			f := InternalNewSearchWireFixture(
				t,
				[]InternalSearchWirePage{{InternalEmptyCookie: true}},
			)
			var counts InternalSearchNativeCounts
			c := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
			result, err := c.Search(
				context.Background(),
				admodel.SearchOptions{Base: "DC=example", TypedFilter: filter},
			)
			if err != nil || !result.Complete {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			f.InternalMu.Lock()
			wire := append([][]byte(nil), f.InternalFilters...)
			f.InternalMu.Unlock()
			if len(wire) != 1 ||
				!bytes.Equal(
					InternalNormalizeFilterBER(t, wire[0]),
					InternalNormalizeFilterBER(t, test.InternalWant),
				) {
				t.Fatalf("BER=%x want=%x", wire, test.InternalWant)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("owners=%+v", counts)
			}
		})
	}
}

func TestADFilterNativePartialPermissionError(t *testing.T) {
	filter, err := admodel.ParseADFilter(
		`Enabled -eq $true`,
		admodel.ADFilterOptions{Profile: admodel.ADFilterUser},
	)
	if err != nil {
		t.Fatal(err)
	}
	f := InternalNewSearchWireFixture(
		t,
		[]InternalSearchWirePage{{InternalCount: 1, InternalCode: 50, InternalEmptyCookie: true}},
	)
	var counts InternalSearchNativeCounts
	c := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
	result, err := c.Search(
		context.Background(),
		admodel.SearchOptions{Base: "DC=example", TypedFilter: filter},
	)
	var native *admodel.LDAPError
	if !errors.As(err, &native) || native.Code != 50 ||
		native.Diagnostic != "private test diagnostic" ||
		result.Complete ||
		len(result.Objects) != 1 {
		t.Fatalf("result=%+v native=%+v err=%v", result, native, err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if counts != (InternalSearchNativeCounts{}) {
		t.Fatalf("owners=%+v", counts)
	}
}
