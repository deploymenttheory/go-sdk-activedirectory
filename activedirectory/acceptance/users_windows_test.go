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
	adservice_users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

// Real WinLDAP runs only against a loopback protocol responder. Directory reads
// are injected, so this never connects to AD or changes a directory account.
func TestNativeUpdateUserConditionalFlagsAndUnicodeWire(t *testing.T) {
	const oldFlags, nextFlags admodel.Flags32 = 0x40000202, 0x40010200
	const target = "<GUID=33221100554477668899aabbccddeeff>"
	modification := func(operation byte, attribute, value string) []byte {
		return InternalSearchBER(0x30, []byte{10, 1, operation}, InternalSearchBER(
			0x30,
			InternalSearchBER(
				4,
				[]byte(attribute),
			),
			InternalSearchBER(0x31, InternalSearchBER(4, []byte(value))),
		))
	}
	want := append(InternalSearchBER(4, []byte(target)), InternalSearchBER(0x30,
		modification(2, "displayName", "Jörg 李"),
		modification(1, "userAccountControl", "1073742338"),
		modification(0, "userAccountControl", "1073807872"))...)
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
						flags := oldFlags
						if writes > 0 {
							flags = nextFlags
						}
						entry := InternalUserTestEntry(flags)
						entry.Attributes["pwdlastset"] = [][]byte{[]byte("123456")}
						entry.Attributes["displayname"] = [][]byte{[]byte("Jörg 李")}
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
			name, enabled, neverExpires := "Jörg 李", true, true
			result, err := adservice_users.New(client).
				UpdateUser(context.Background(), admodel.UpdateUserRequest{Identity: InternalObjectTestIdentity(), Properties: admodel.UserProperties{DisplayName: &name, Enabled: &enabled, PasswordNeverExpires: &neverExpires}})
			if writes != 1 || closes != reads {
				t.Fatalf("writes=%d reads=%d closes=%d", writes, reads, closes)
			}
			if code == 0 {
				if err != nil || reads != 2 ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					!result.Mutation.Verified ||
					result.User == nil ||
					*result.User.UserAccountControl != nextFlags {
					t.Fatal(result, err)
				}
			} else {
				var nativeErr *admodel.LDAPError
				if !errors.As(err, &nativeErr) || nativeErr.Code != uint32(code) ||
					nativeErr.Diagnostic != "private wire diagnostic" ||
					result.Mutation.State != admodel.ObjectWriteRejected ||
					result.Mutation.Verified ||
					reads != 1 {
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
