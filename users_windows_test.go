//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
)

// Real WinLDAP runs only against a loopback protocol responder. Directory reads
// are injected, so this never connects to AD or changes a directory account.
func TestNativeUpdateUserConditionalFlagsAndUnicodeWire(t *testing.T) {
	const oldFlags, nextFlags Flags32 = 0x40000202, 0x40010200
	const target = "<GUID=33221100554477668899aabbccddeeff>"
	modification := func(operation byte, attribute, value string) []byte {
		return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30,
			searchBER(4, []byte(attribute)), searchBER(0x31, searchBER(4, []byte(value)))))
	}
	want := append(searchBER(4, []byte(target)), searchBER(0x30,
		modification(2, "displayName", "Jörg 李"),
		modification(1, "userAccountControl", "1073742338"),
		modification(0, "userAccountControl", "1073807872"))...)
	for _, code := range []byte{0, 16, 50} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, code)
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			reads, writes, closes := 0, 0, 0
			client.session = objectWriteTestSession{
				testSession: testSession{
					read: func(context.Context, []string) (map[string][][]byte, error) {
						return identityTestRoot(CapabilityActiveDirectory), nil
					},
					search: func(context.Context, SearchOptions) (searchCursor, error) {
						reads++
						flags := oldFlags
						if writes > 0 {
							flags = nextFlags
						}
						entry := userTestEntry(flags)
						entry.Attributes["pwdlastset"] = [][]byte{[]byte("123456")}
						entry.Attributes["displayname"] = [][]byte{[]byte("Jörg 李")}
						return testSearchCursor{
							read: func(context.Context, uint32) ([]Object, bool, error) {
								return []Object{entry}, true, nil
							},
							finish: func() error { closes++; return nil },
						}, nil
					},
					finish: native.close,
				},
				write: func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
					writes++
					runtime.GC()
					return native.ldapWrite(ctx, request)
				},
			}
			name, enabled, neverExpires := "Jörg 李", true, true
			result, err := client.UpdateUser(context.Background(), UpdateUserRequest{Identity: objectTestIdentity(), Properties: UserProperties{DisplayName: &name, Enabled: &enabled, PasswordNeverExpires: &neverExpires}})
			if writes != 1 || closes != reads {
				t.Fatalf("writes=%d reads=%d closes=%d", writes, reads, closes)
			}
			if code == 0 {
				if err != nil || reads != 2 || result.Mutation.State != ObjectWriteAccepted || !result.Mutation.Verified || result.User == nil || *result.User.UserAccountControl != nextFlags {
					t.Fatal(result, err)
				}
			} else {
				var nativeErr *LDAPError
				if !errors.As(err, &nativeErr) || nativeErr.Code != uint32(code) || nativeErr.Diagnostic != "private wire diagnostic" || result.Mutation.State != ObjectWriteRejected || result.Mutation.Verified || reads != 1 {
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
