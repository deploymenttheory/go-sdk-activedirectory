package activedirectory

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestADFilterOperatorsPrecedenceAndLiterals(t *testing.T) {
	for _, test := range []struct{ expression, want string }{
		{`*`, `(objectClass=*)`}, {`{ ObjectClass -like '*' }`, `(objectClass=*)`},
		{`CN -like '*bob*'`, `(cn=*bob*)`}, {`badPwdCount -ge 5`, `(badPwdCount>=5)`},
		{`badPwdCount -gt 5`, `(&(!(badPwdCount<=5))(badPwdCount=*))`},
		{`badPwdCount -lt -5`, `(&(!(badPwdCount>=-5))(badPwdCount=*))`},
		{`cn -ne 'bob'`, `(&(!(cn=bob))(cn=*))`},
		{`cn -notlike 'bob*'`, `(&(!(cn=bob*))(cn=*))`},
		{`cn -notlike '***'`, `(!(cn=*))`},
		{`-not cn -like '*'`, `(!(cn=*))`},
		{`cn -eq 'a' -or sn -eq 'b' -and mail -eq 'c'`, `(|(cn=a)(&(sn=b)(mail=c)))`},
		{`(cn -eq 'a' -or sn -eq 'b') -and mail -eq 'c'`, `(&(|(cn=a)(sn=b))(mail=c))`},
		{`-not cn -eq 'a' -and sn -eq 'b'`, `(&(!(cn=a))(sn=b))`},
		{`CN -EQ 'A*()/'`, `(cn=A\2a\28\29/)`},
		{`cn -eq 'a''b'`, `(cn=a'b)`},
		{"cn -eq \"a`\"b\"", `(cn=a"b)`},
		{"cn -eq \"a`nb\"", "(cn=a`nb)"},
		{`cn -eq '$literal'`, `(cn=$literal)`},
		{`cn -eq 'a\00\5cb'`, `(cn=a\00\5cb)`},
		{`cn -like 'a\2a**b?c[d]*終'`, `(cn=a\2a*b?c[d]*終)`},
		{`cn -approx 'Dŵr😀'`, `(cn~=Dŵr😀)`},
		{`groupType -band 0x80000000`, `(groupType:1.2.840.113556.1.4.803:=2147483648)`},
		{`groupType -bor 3`, `(groupType:1.2.840.113556.1.4.804:=3)`},
		{`memberOf -RecursiveMatch 'CN=Group\5c, One,DC=test'`, `(memberOf:1.2.840.113556.1.4.1941:=CN=Group\5c, One,DC=test)`},
		{`uSNChanged -eq 9007199254740993`, `(uSNChanged=9007199254740993)`},
		{`n -eq +001`, `(n=1)`},
		{`objectGUID -like '*'`, `(objectGUID=*)`},
	} {
		t.Run(test.expression, func(t *testing.T) {
			filter, err := ParseADFilter(test.expression, ADFilterOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := filter.LDAP()
			if err != nil || got != test.want {
				t.Fatalf("got=%q want=%q err=%v", got, test.want, err)
			}
		})
	}
}

func TestADFilterTypedVariablesProfilesAndSchema(t *testing.T) {
	guid, _ := ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	sid, _ := ParseSID("S-1-5-21-111-222-333-1001")
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 123400000, time.FixedZone("offset", 3600))
	ticks, _ := FileTimeFromTime(stamp)
	for _, test := range []struct {
		expression string
		options    ADFilterOptions
		want       Filter
	}{
		{`cn -eq $VALUE`, ADFilterOptions{Variables: map[string]any{"value": `*)(|(objectClass=*))`}}, FilterEqual("cn", FilterText(`*)(|(objectClass=*))`))},
		{`cn -eq ${value}`, ADFilterOptions{Variables: map[string]any{"value": `\2a`}}, FilterEqual("cn", FilterText(`\2a`))},
		{`cn -like $pattern`, ADFilterOptions{Variables: map[string]any{"pattern": "A*(literal)"}}, FilterSubstrings("cn", SubstringFilter{Initial: FilterText("A"), Final: FilterText("(literal)")})},
		{`ObjectGUID -eq '00112233-4455-6677-8899-aabbccddeeff'`, ADFilterOptions{}, FilterEqual("objectGUID", FilterBytes(guid.Bytes()))},
		{`ObjectGUID -eq $guid`, ADFilterOptions{Variables: map[string]any{"guid": guid}}, FilterEqual("objectGUID", FilterBytes(guid.Bytes()))},
		{`SID -eq 'S-1-5-21-111-222-333-1001'`, ADFilterOptions{Profile: ADFilterUser}, FilterEqual("objectSid", FilterBytes(sid.Bytes()))},
		{`SID -eq $sid`, ADFilterOptions{Profile: ADFilterUser, Variables: map[string]any{"sid": sid}}, FilterEqual("objectSid", FilterBytes(sid.Bytes()))},
		{`LastLogonDate -ge $date`, ADFilterOptions{Profile: ADFilterUser, Variables: map[string]any{"date": stamp}}, FilterGreaterOrEqual("lastLogonTimestamp", FilterText(ticks.LDAPString()))},
		{`Created -le $date`, ADFilterOptions{Variables: map[string]any{"date": stamp}}, FilterLessOrEqual("createTimeStamp", FilterText("20260102020405.123400000Z"))},
		{`customDate -eq $date`, ADFilterOptions{Variables: map[string]any{"date": stamp}, Properties: map[string]ADFilterProperty{"customDate": {Attribute: "extensionAttribute1", Syntax: ADFilterFileTime}}}, FilterEqual("extensionAttribute1", FilterText(ticks.LDAPString()))},
		{`Enabled -eq $true`, ADFilterOptions{Profile: ADFilterUser}, FilterNot(FilterBitAnd("userAccountControl", 2))},
		{`Enabled -ne 'False'`, ADFilterOptions{Profile: ADFilterComputer}, FilterNot(FilterBitAnd("userAccountControl", 2))},
		{`PasswordNeverExpires -eq $true`, ADFilterOptions{Profile: ADFilterUser}, FilterBitAnd("userAccountControl", 65536)},
		{`Deleted -eq $false`, ADFilterOptions{}, FilterEqual("isDeleted", FilterText("FALSE"))},
		{`EmailAddress -like '*' -and Surname -eq 'smith'`, ADFilterOptions{Profile: ADFilterUser}, FilterAnd(FilterPresent("mail"), FilterEqual("sn", FilterText("smith")))},
		{`SamAccountName -eq 'HOST$'`, ADFilterOptions{Profile: ADFilterComputer}, FilterEqual("sAMAccountName", FilterText("HOST$"))},
		{`SamAccountName -like 'HOST*'`, ADFilterOptions{Profile: ADFilterComputer}, FilterSubstrings("sAMAccountName", SubstringFilter{Initial: FilterText("HOST")})},
		{`GroupScope -eq 'Universal'`, ADFilterOptions{Profile: ADFilterGroup}, FilterBitAnd("groupType", 8)},
		{`GroupCategory -eq 'Security'`, ADFilterOptions{Profile: ADFilterGroup}, FilterExtensible(ExtensibleFilter{Attribute: "groupType", Rule: MatchingRuleBitAnd, Value: FilterInteger(-2147483648)})},
		{`unknown -eq $bytes`, ADFilterOptions{Variables: map[string]any{"bytes": []byte{0, 255, 42}}}, FilterEqual("unknown", FilterBytes([]byte{0, 255, 42}))},
	} {
		t.Run(test.expression, func(t *testing.T) {
			got, err := ParseADFilter(test.expression, test.options)
			if err != nil {
				t.Fatal(err)
			}
			actual, _ := got.LDAP()
			want, _ := test.want.LDAP()
			if actual != want {
				t.Fatalf("got=%q want=%q", actual, want)
			}
		})
	}
}

func TestADFilterRejectsExecutableAndAmbiguousInputs(t *testing.T) {
	for _, expression := range []string{"", `Get-ADUser`, `cn -eq bob`, `cn -eq (Get-Content 'x')`, `cn -eq $x.ToString()`, `cn -eq $env:secret`, `cn -eq $(Get-Content 'x')`, `cn -eq $x[0]`, `cn -eq @('a','b')`, `cn -eq [guid]'00112233-4455-6677-8899-aabbccddeeff'`, `cn -eq 'a'; Get-ADUser`, `cn -eq 'a' | Get-ADUser`, `cn -match 'x'`, `cn -eq 'unterminated`, `cn -eq 'bad\escape'`, `cn -eq 'a' -and`, `cn -eq 1.5`, `cn -eq 1e3`, `cn -eq 18446744073709551616`} {
		_, err := ParseADFilter(expression, ADFilterOptions{Variables: map[string]any{"x": "safe"}})
		var located *ADFilterError
		if !errors.As(err, &located) || located.Offset < 0 || located.Offset > len(expression) || located.Line < 1 || located.Column < 1 {
			t.Fatalf("expression=%q error=%v", expression, err)
		}
	}
	for _, test := range []struct {
		expression string
		options    ADFilterOptions
		cause      error
	}{
		{`cn -eq $missing`, ADFilterOptions{}, ErrADFilterVariable},
		{`cn -eq $null`, ADFilterOptions{}, ErrADFilterVariable},
		{`cn -eq $value`, ADFilterOptions{Variables: map[string]any{"value": nil}}, ErrADFilterVariable},
		{`cn -eq $value`, ADFilterOptions{Variables: map[string]any{"value": []string{"a", "b"}}}, ErrADFilterConversion},
		{`cn -eq $value`, ADFilterOptions{Variables: map[string]any{"value": math.Inf(1)}}, ErrValuePrecision},
		{`unknownDate -eq $date`, ADFilterOptions{Variables: map[string]any{"date": time.Now()}}, ErrADFilterConversion},
		{`LastLogonDate -eq $date`, ADFilterOptions{Profile: ADFilterUser, Variables: map[string]any{"date": time.Unix(1, 1)}}, ErrValuePrecision},
		{`Enabled -like '*'`, ADFilterOptions{Profile: ADFilterUser}, ErrADFilterConversion},
		{`ProtectedFromAccidentalDeletion -eq $true`, ADFilterOptions{}, ErrADFilterProperty},
		{`LockedOut -eq $true`, ADFilterOptions{Profile: ADFilterUser}, ErrADFilterProperty},
		{`SamAccountName -eq 'HOST'`, ADFilterOptions{Profile: ADFilterComputer}, ErrADFilterProperty},
		{`memberOf -recursivematch 'CN=Group(x),DC=test'`, ADFilterOptions{}, ErrUnsupportedFilterValue},
		{`cn -eq $value`, ADFilterOptions{Variables: map[string]any{"value": "x", "VALUE": "y"}}, ErrADFilterVariable},
		{`cn -eq 'x'`, ADFilterOptions{Variables: map[string]any{"true": false}}, ErrADFilterVariable},
		{`cn -eq 'x'`, ADFilterOptions{Properties: map[string]ADFilterProperty{"cn": {Attribute: "cn)(objectClass"}}}, ErrADFilterProperty},
	} {
		_, err := ParseADFilter(test.expression, test.options)
		if !errors.Is(err, test.cause) {
			t.Fatalf("expression=%q err=%v want=%v", test.expression, err, test.cause)
		}
	}
	_, err := ParseADFilter("cn -eq 'Dŵr' -and\n mail -eq $missing", ADFilterOptions{})
	var located *ADFilterError
	if !errors.As(err, &located) || located.Line != 2 || located.Column != 11 || strings.Contains(err.Error(), "Dŵr") {
		t.Fatalf("location/privacy: %+v", err)
	}
	_, err = ParseADFilter(strings.Repeat("(", MaxFilterDepth)+`cn -eq 'x'`+strings.Repeat(")", MaxFilterDepth), ADFilterOptions{})
	if !errors.Is(err, ErrFilterLimit) {
		t.Fatal(err)
	}
}

func FuzzADFilterParser(f *testing.F) {
	for _, seed := range []string{`cn -eq 'bob'`, `-not cn -like '*'`, `(cn -eq 'a' -or sn -eq 'b') -and Enabled -eq $true`, `cn -eq $v`, `cn -eq 'a\00b'`, `cn -eq $(bad)`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expression string) {
		if len(expression) > 8192 {
			t.Skip()
		}
		filter, err := ParseADFilter(expression, ADFilterOptions{Profile: ADFilterUser, Variables: map[string]any{"v": "literal"}})
		if err != nil {
			var located *ADFilterError
			if !errors.As(err, &located) || located.Offset < 0 || located.Offset > len(expression) {
				t.Fatalf("unlocated error: %v", err)
			}
			return
		}
		encoded, err := filter.LDAP()
		if err != nil || len(encoded) > MaxFilterBytes {
			t.Fatalf("invalid successful filter: %v", err)
		}
		if err = (SearchOptions{TypedFilter: filter}).Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzADFilterVariableIsData(f *testing.F) {
	f.Add([]byte(`*)(|(objectClass=*))`))
	f.Add([]byte{0, 255, 42, 92})
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > 4096 {
			t.Skip()
		}
		filter, err := ParseADFilter(`unknown -eq $value`, ADFilterOptions{Variables: map[string]any{"value": value}})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := filter.LDAP()
		if !strings.HasPrefix(encoded, "(unknown=") || !strings.HasSuffix(encoded, ")") {
			t.Fatal(encoded)
		}
		got, err := decodeFilterTestLiteral(encoded[9 : len(encoded)-1])
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("value changed/injected nodes: %x %v", got, err)
		}
	})
}
