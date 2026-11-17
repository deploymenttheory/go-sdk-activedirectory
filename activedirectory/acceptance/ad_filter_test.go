package acceptance

import (
	"bytes"
	"errors"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestADFilterStopsExpansionAtOutputBudget(t *testing.T) {
	value := strings.Repeat("a", 65536)
	// A final missing binding distinguishes an incremental budget from a
	// size check that happens only after materializing the whole group.
	expression := strings.Repeat("cn -eq $v -or ", 200) + "cn -eq $missing"
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := admodel.ParseADFilter(
		expression,
		admodel.ADFilterOptions{Variables: map[string]any{"v": value}},
	)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, admodel.ErrFilterLimit) {
		t.Fatalf("expected output budget before later binding: %v", err)
	}
	// The old compiler allocated about 142 MiB for this bounded input. Leave
	// room for allocator/runtime variation while detecting full expansion.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 32<<20 {
		t.Fatalf("expanded siblings beyond the output budget: %d bytes", allocated)
	}
	// The same budget must cross nested groups, not restart per child.
	nested := strings.Repeat("(cn -eq $v -and sn -eq $v) -or ", 100) + "cn -eq $missing"
	if _, err := admodel.ParseADFilter(
		nested,
		admodel.ADFilterOptions{Variables: map[string]any{"v": value}},
	); !errors.Is(
		err,
		admodel.ErrFilterLimit,
	) {
		t.Fatalf("nested output budget was not shared: %v", err)
	}
}

func TestADFilterGeneralizedTimeChecksUTCYear(t *testing.T) {
	for _, test := range []struct {
		InternalName  string
		InternalValue time.Time
		InternalWant  string
	}{
		{"UTC year 10000", time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("minus", -3600)), ""},
		{"UTC year zero", time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("plus", 3600)), ""},
		{"local year 10000 UTC valid", time.Date(10000, 1, 1, 0, 30, 0, 0, time.FixedZone("plus", 3600)), "99991231233000.000000000Z"},
		{"local year zero UTC valid", time.Date(0, 12, 31, 23, 30, 0, 0, time.FixedZone("minus", -3600)), "00010101003000.000000000Z"},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			filter, err := admodel.ParseADFilter(
				`Created -eq $date`,
				admodel.ADFilterOptions{Variables: map[string]any{"date": test.InternalValue}},
			)
			if test.InternalWant == "" {
				if !errors.Is(err, admodel.ErrValueRange) {
					t.Fatalf("accepted UTC year outside the range: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := filter.LDAP()
			if want := "(createTimeStamp=" + test.InternalWant + ")"; got != want {
				t.Fatalf("got=%q want=%q", got, want)
			}
		})
	}
}

func TestADFilterOperatorsPrecedenceAndLiterals(t *testing.T) {
	for _, test := range []struct{ InternalExpression, InternalWant string }{
		{`*`, `(objectClass=*)`},
		{`{ ObjectClass -like '*' }`, `(objectClass=*)`},
		{`CN -like '*bob*'`, `(cn=*bob*)`},
		{`badPwdCount -ge 5`, `(badPwdCount>=5)`},
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
		t.Run(test.InternalExpression, func(t *testing.T) {
			filter, err := admodel.ParseADFilter(test.InternalExpression, admodel.ADFilterOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := filter.LDAP()
			if err != nil || got != test.InternalWant {
				t.Fatalf("got=%q want=%q err=%v", got, test.InternalWant, err)
			}
		})
	}
}

func TestADFilterTypedVariablesProfilesAndSchema(t *testing.T) {
	guid, _ := admodel.ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	sid, _ := admodel.ParseSID("S-1-5-21-111-222-333-1001")
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 123400000, time.FixedZone("offset", 3600))
	ticks, _ := admodel.FileTimeFromTime(stamp)
	for _, test := range []struct {
		InternalExpression string
		InternalOptions    admodel.ADFilterOptions
		InternalWant       admodel.Filter
	}{
		{`cn -eq $VALUE`, admodel.ADFilterOptions{Variables: map[string]any{"value": `*)(|(objectClass=*))`}}, admodel.FilterEqual("cn", admodel.FilterText(`*)(|(objectClass=*))`))},
		{`cn -eq ${value}`, admodel.ADFilterOptions{Variables: map[string]any{"value": `\2a`}}, admodel.FilterEqual("cn", admodel.FilterText(`\2a`))},
		{`cn -like $pattern`, admodel.ADFilterOptions{Variables: map[string]any{"pattern": "A*(literal)"}}, admodel.FilterSubstrings("cn", admodel.SubstringFilter{Initial: admodel.FilterText("A"), Final: admodel.FilterText("(literal)")})},
		{`ObjectGUID -eq '00112233-4455-6677-8899-aabbccddeeff'`, admodel.ADFilterOptions{}, admodel.FilterEqual("objectGUID", admodel.FilterBytes(guid.Bytes()))},
		{`ObjectGUID -eq $guid`, admodel.ADFilterOptions{Variables: map[string]any{"guid": guid}}, admodel.FilterEqual("objectGUID", admodel.FilterBytes(guid.Bytes()))},
		{`SID -eq 'S-1-5-21-111-222-333-1001'`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser}, admodel.FilterEqual("objectSid", admodel.FilterBytes(sid.Bytes()))},
		{`SID -eq $sid`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser, Variables: map[string]any{"sid": sid}}, admodel.FilterEqual("objectSid", admodel.FilterBytes(sid.Bytes()))},
		{`LastLogonDate -ge $date`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser, Variables: map[string]any{"date": stamp}}, admodel.FilterGreaterOrEqual("lastLogonTimestamp", admodel.FilterText(ticks.LDAPString()))},
		{`Created -le $date`, admodel.ADFilterOptions{Variables: map[string]any{"date": stamp}}, admodel.FilterLessOrEqual("createTimeStamp", admodel.FilterText("20260102020405.123400000Z"))},
		{`customDate -eq $date`, admodel.ADFilterOptions{Variables: map[string]any{"date": stamp}, Properties: map[string]admodel.ADFilterProperty{"customDate": {Attribute: "extensionAttribute1", Syntax: admodel.ADFilterFileTime}}}, admodel.FilterEqual("extensionAttribute1", admodel.FilterText(ticks.LDAPString()))},
		{`Enabled -eq $true`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser}, admodel.FilterNot(admodel.FilterBitAnd("userAccountControl", 2))},
		{`Enabled -ne 'False'`, admodel.ADFilterOptions{Profile: admodel.ADFilterComputer}, admodel.FilterNot(admodel.FilterBitAnd("userAccountControl", 2))},
		{`PasswordNeverExpires -eq $true`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser}, admodel.FilterBitAnd("userAccountControl", 65536)},
		{`Deleted -eq $false`, admodel.ADFilterOptions{}, admodel.FilterEqual("isDeleted", admodel.FilterText("FALSE"))},
		{`EmailAddress -like '*' -and Surname -eq 'smith'`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser}, admodel.FilterAnd(admodel.FilterPresent("mail"), admodel.FilterEqual("sn", admodel.FilterText("smith")))},
		{`SamAccountName -eq 'HOST$'`, admodel.ADFilterOptions{Profile: admodel.ADFilterComputer}, admodel.FilterEqual("sAMAccountName", admodel.FilterText("HOST$"))},
		{`SamAccountName -like 'HOST*'`, admodel.ADFilterOptions{Profile: admodel.ADFilterComputer}, admodel.FilterSubstrings("sAMAccountName", admodel.SubstringFilter{Initial: admodel.FilterText("HOST")})},
		{`GroupScope -eq 'Universal'`, admodel.ADFilterOptions{Profile: admodel.ADFilterGroup}, admodel.FilterBitAnd("groupType", 8)},
		{`GroupCategory -eq 'Security'`, admodel.ADFilterOptions{Profile: admodel.ADFilterGroup}, admodel.FilterExtensible(admodel.ExtensibleFilter{Attribute: "groupType", Rule: admodel.MatchingRuleBitAnd, Value: admodel.FilterInteger(-2147483648)})},
		{`unknown -eq $bytes`, admodel.ADFilterOptions{Variables: map[string]any{"bytes": []byte{0, 255, 42}}}, admodel.FilterEqual("unknown", admodel.FilterBytes([]byte{0, 255, 42}))},
	} {
		t.Run(test.InternalExpression, func(t *testing.T) {
			got, err := admodel.ParseADFilter(test.InternalExpression, test.InternalOptions)
			if err != nil {
				t.Fatal(err)
			}
			actual, _ := got.LDAP()
			want, _ := test.InternalWant.LDAP()
			if actual != want {
				t.Fatalf("got=%q want=%q", actual, want)
			}
		})
	}
}

func TestADFilterRejectsExecutableAndAmbiguousInputs(t *testing.T) {
	for _, expression := range []string{"", `Get-ADUser`, `cn -eq bob`, `cn -eq (Get-Content 'x')`, `cn -eq $x.ToString()`, `cn -eq $env:secret`, `cn -eq $(Get-Content 'x')`, `cn -eq $x[0]`, `cn -eq @('a','b')`, `cn -eq [guid]'00112233-4455-6677-8899-aabbccddeeff'`, `cn -eq 'a'; Get-ADUser`, `cn -eq 'a' | Get-ADUser`, `cn -match 'x'`, `cn -eq 'unterminated`, `cn -eq 'bad\escape'`, `cn -eq 'a' -and`, `cn -eq 1.5`, `cn -eq 1e3`, `cn -eq 18446744073709551616`} {
		_, err := admodel.ParseADFilter(
			expression,
			admodel.ADFilterOptions{Variables: map[string]any{"x": "safe"}},
		)
		var located *admodel.ADFilterError
		if !errors.As(err, &located) || located.Offset < 0 || located.Offset > len(expression) ||
			located.Line < 1 ||
			located.Column < 1 {
			t.Fatalf("expression=%q error=%v", expression, err)
		}
	}
	for _, test := range []struct {
		InternalExpression string
		InternalOptions    admodel.ADFilterOptions
		InternalCause      error
	}{
		{`cn -eq $missing`, admodel.ADFilterOptions{}, admodel.ErrADFilterVariable},
		{`cn -eq $null`, admodel.ADFilterOptions{}, admodel.ErrADFilterVariable},
		{`cn -eq $value`, admodel.ADFilterOptions{Variables: map[string]any{"value": nil}}, admodel.ErrADFilterVariable},
		{`cn -eq $value`, admodel.ADFilterOptions{Variables: map[string]any{"value": []string{"a", "b"}}}, admodel.ErrADFilterConversion},
		{`cn -eq $value`, admodel.ADFilterOptions{Variables: map[string]any{"value": math.Inf(1)}}, admodel.ErrValuePrecision},
		{`unknownDate -eq $date`, admodel.ADFilterOptions{Variables: map[string]any{"date": time.Now()}}, admodel.ErrADFilterConversion},
		{`LastLogonDate -eq $date`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser, Variables: map[string]any{"date": time.Unix(1, 1)}}, admodel.ErrValuePrecision},
		{`Enabled -like '*'`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser}, admodel.ErrADFilterConversion},
		{`ProtectedFromAccidentalDeletion -eq $true`, admodel.ADFilterOptions{}, admodel.ErrADFilterProperty},
		{`LockedOut -eq $true`, admodel.ADFilterOptions{Profile: admodel.ADFilterUser}, admodel.ErrADFilterProperty},
		{`SamAccountName -eq 'HOST'`, admodel.ADFilterOptions{Profile: admodel.ADFilterComputer}, admodel.ErrADFilterProperty},
		{`memberOf -recursivematch 'CN=Group(x),DC=test'`, admodel.ADFilterOptions{}, admodel.ErrUnsupportedFilterValue},
		{`cn -eq $value`, admodel.ADFilterOptions{Variables: map[string]any{"value": "x", "VALUE": "y"}}, admodel.ErrADFilterVariable},
		{`cn -eq 'x'`, admodel.ADFilterOptions{Variables: map[string]any{"true": false}}, admodel.ErrADFilterVariable},
		{`cn -eq 'x'`, admodel.ADFilterOptions{Properties: map[string]admodel.ADFilterProperty{"cn": {Attribute: "cn)(objectClass"}}}, admodel.ErrADFilterProperty},
	} {
		_, err := admodel.ParseADFilter(test.InternalExpression, test.InternalOptions)
		if !errors.Is(err, test.InternalCause) {
			t.Fatalf(
				"expression=%q err=%v want=%v",
				test.InternalExpression,
				err,
				test.InternalCause,
			)
		}
	}
	_, err := admodel.ParseADFilter(
		"cn -eq 'Dŵr' -and\n mail -eq $missing",
		admodel.ADFilterOptions{},
	)
	var located *admodel.ADFilterError
	if !errors.As(err, &located) || located.Line != 2 || located.Column != 11 ||
		strings.Contains(err.Error(), "Dŵr") {
		t.Fatalf("location/privacy: %+v", err)
	}
	_, err = admodel.ParseADFilter(
		strings.Repeat(
			"(",
			admodel.MaxFilterDepth,
		)+`cn -eq 'x'`+strings.Repeat(
			")",
			admodel.MaxFilterDepth,
		),
		admodel.ADFilterOptions{},
	)
	if !errors.Is(err, admodel.ErrFilterLimit) {
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
		filter, err := admodel.ParseADFilter(
			expression,
			admodel.ADFilterOptions{
				Profile:   admodel.ADFilterUser,
				Variables: map[string]any{"v": "literal"},
			},
		)
		if err != nil {
			var located *admodel.ADFilterError
			if !errors.As(err, &located) || located.Offset < 0 || located.Offset > len(expression) {
				t.Fatalf("unlocated error: %v", err)
			}
			return
		}
		encoded, err := filter.LDAP()
		if err != nil || len(encoded) > admodel.MaxFilterBytes {
			t.Fatalf("invalid successful filter: %v", err)
		}
		if err = (admodel.SearchOptions{TypedFilter: filter}).Validate(); err != nil {
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
		filter, err := admodel.ParseADFilter(
			`unknown -eq $value`,
			admodel.ADFilterOptions{Variables: map[string]any{"value": value}},
		)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := filter.LDAP()
		if !strings.HasPrefix(encoded, "(unknown=") || !strings.HasSuffix(encoded, ")") {
			t.Fatal(encoded)
		}
		got, err := InternalDecodeFilterTestLiteral(encoded[9 : len(encoded)-1])
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("value changed/injected nodes: %x %v", got, err)
		}
	})
}
