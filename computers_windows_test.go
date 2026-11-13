//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
)

// The public workflow writes through actual WinLDAP to a loopback responder;
// all directory observations are injected. No computer or domain is changed.
func TestNativeUpdateComputerFlagsSPNsAndDNSWire(t *testing.T) {
	const target = "<GUID=33221100554477668899aabbccddeeff>"
	modification := func(operation byte, attribute, value string) []byte {
		return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte(attribute)), searchBER(0x31, searchBER(4, []byte(value)))))
	}
	want := append(searchBER(4, []byte(target)), searchBER(0x30,
		modification(1, "servicePrincipalName", "HOST/old"), modification(0, "servicePrincipalName", "HOST/höst.example.test"),
		modification(2, "dNSHostName", "höst.example.test"),
		modification(1, "userAccountControl", "1073745922"), modification(0, "userAccountControl", "1073745920"),
		modification(1, "msDS-SupportedEncryptionTypes", "-2147483372"), modification(0, "msDS-SupportedEncryptionTypes", "-2147483304"))...)
	for _, code := range []byte{0, 16, 50} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, code)
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			reads, writes, closes := 0, 0, 0
			client.session = objectWriteTestSession{testSession: testSession{
				read: func(context.Context, []string) (map[string][][]byte, error) {
					return identityTestRoot(CapabilityActiveDirectory), nil
				},
				search: func(context.Context, SearchOptions) (searchCursor, error) {
					reads++
					flags, mask := Flags32(0x40001002), Flags32(0x80000114)
					spn := "HOST/old"
					if writes != 0 {
						flags, mask = 0x40001000, 0x80000158
						spn = "HOST/höst.example.test"
					}
					entry := computerTestEntry(flags)
					entry.Attributes["msds-supportedencryptiontypes"] = [][]byte{[]byte(mask.LDAPString())}
					entry.Attributes["serviceprincipalname"] = [][]byte{[]byte(spn), []byte("HOST/keep")}
					entry.Attributes["dnshostname"] = [][]byte{[]byte("höst.example.test")}
					return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return []Object{entry}, true, nil }, finish: func() error { closes++; return nil }}, nil
				}, finish: native.close,
			}, write: func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
				writes++
				runtime.GC()
				return native.ldapWrite(ctx, request)
			}}
			enabled, compound, dns, encryption := true, true, "höst.example.test", Flags32(24)
			result, err := client.UpdateComputer(context.Background(), UpdateComputerRequest{Identity: objectTestIdentity(), Properties: ComputerProperties{DNSHostName: &dns, KerberosEncryptionTypes: &encryption, CompoundIdentitySupported: &compound}, Control: AccountControlPatch{Enabled: &enabled}, Changes: []AttributeChange{{Attribute: "servicePrincipalName", Kind: AttributeRemoveValues, Values: []RawValue{NewRawValue([]byte("HOST/old"))}}, {Attribute: "servicePrincipalName", Kind: AttributeAddValues, Values: []RawValue{NewRawValue([]byte("HOST/höst.example.test"))}}}})
			if writes != 1 || reads != closes {
				t.Fatal(writes, reads, closes)
			}
			if code == 0 {
				if err != nil || reads != 2 || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted || result.Computer == nil || *result.Computer.SupportedEncryptionTypes != 0x80000158 {
					t.Fatal(result, err)
				}
			} else {
				var nativeErr *LDAPError
				if !errors.As(err, &nativeErr) || nativeErr.Code != uint32(code) || nativeErr.Diagnostic != "private wire diagnostic" || reads != 1 || result.Mutation.State != ObjectWriteRejected || result.Mutation.Verified {
					t.Fatal(result, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (searchNativeCounts{}) {
				t.Fatalf("native allocation leak: %+v", owners)
			}
		})
	}
}
