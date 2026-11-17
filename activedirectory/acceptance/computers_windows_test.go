//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_computers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
)

// The public workflow writes through actual WinLDAP to a loopback responder;
// all directory observations are injected. No computer or domain is changed.
func TestNativeUpdateComputerFlagsSPNsAndDNSWire(t *testing.T) {
	const target = "<GUID=33221100554477668899aabbccddeeff>"
	modification := func(operation byte, attribute, value string) []byte {
		return InternalSearchBER(
			0x30,
			[]byte{10, 1, operation},
			InternalSearchBER(
				0x30,
				InternalSearchBER(4, []byte(attribute)),
				InternalSearchBER(0x31, InternalSearchBER(4, []byte(value))),
			),
		)
	}
	want := append(InternalSearchBER(4, []byte(target)), InternalSearchBER(
		0x30,
		modification(
			1,
			"servicePrincipalName",
			"HOST/old",
		),
		modification(0, "servicePrincipalName", "HOST/höst.example.test"),
		modification(2, "dNSHostName", "höst.example.test"),
		modification(
			1,
			"userAccountControl",
			"1073745922",
		),
		modification(0, "userAccountControl", "1073745920"),
		modification(
			1,
			"msDS-SupportedEncryptionTypes",
			"-2147483372",
		),
		modification(0, "msDS-SupportedEncryptionTypes", "-2147483304"),
	)...)
	for _, code := range []byte{0, 16, 50} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, nil, code)
			var owners InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&owners),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			reads, writes, closes := 0, 0, 0
			(*adengine.InternalClientSessionPointer(client)) = InternalObjectWriteTestSession{
				InternalTestSession: InternalTestSession{
					InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
						return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
					},
					InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						reads++
						flags, mask := admodel.Flags32(0x40001002), admodel.Flags32(0x80000114)
						spn := "HOST/old"
						if writes != 0 {
							flags, mask = 0x40001000, 0x80000158
							spn = "HOST/höst.example.test"
						}
						entry := InternalComputerTestEntry(flags)
						entry.Attributes["msds-supportedencryptiontypes"] = [][]byte{
							[]byte(mask.LDAPString()),
						}
						entry.Attributes["serviceprincipalname"] = [][]byte{
							[]byte(spn),
							[]byte("HOST/keep"),
						}
						entry.Attributes["dnshostname"] = [][]byte{[]byte("höst.example.test")}
						return InternalTestSearchCursor{
							InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
								return []admodel.Object{entry}, true, nil
							},
							InternalFinish: func() error { closes++; return nil },
						}, nil
					},
					InternalFinish: native.InternalClose,
				},
				InternalWrite: func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					runtime.GC()
					return native.InternalLdapWrite(ctx, request)
				},
			}
			enabled, compound, dns, encryption := true, true, "höst.example.test", admodel.Flags32(
				24,
			)
			result, err := adservice_computers.New(client).
				UpdateComputer(context.Background(), admodel.UpdateComputerRequest{Identity: InternalObjectTestIdentity(), Properties: admodel.ComputerProperties{DNSHostName: &dns, KerberosEncryptionTypes: &encryption, CompoundIdentitySupported: &compound}, Control: admodel.AccountControlPatch{Enabled: &enabled}, Changes: []admodel.AttributeChange{{Attribute: "servicePrincipalName", Kind: admodel.AttributeRemoveValues, Values: []admodel.RawValue{admodel.NewRawValue([]byte("HOST/old"))}}, {Attribute: "servicePrincipalName", Kind: admodel.AttributeAddValues, Values: []admodel.RawValue{admodel.NewRawValue([]byte("HOST/höst.example.test"))}}}})
			if writes != 1 || reads != closes {
				t.Fatal(writes, reads, closes)
			}
			if code == 0 {
				if err != nil || reads != 2 || !result.Mutation.Verified ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					result.Computer == nil ||
					*result.Computer.SupportedEncryptionTypes != 0x80000158 {
					t.Fatal(result, err)
				}
			} else {
				var nativeErr *admodel.LDAPError
				if !errors.As(err, &nativeErr) || nativeErr.Code != uint32(code) ||
					nativeErr.Diagnostic != "private wire diagnostic" ||
					reads != 1 ||
					result.Mutation.State != admodel.ObjectWriteRejected ||
					result.Mutation.Verified {
					t.Fatal(result, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatalf("native allocation leak: %+v", owners)
			}
		})
	}
}
