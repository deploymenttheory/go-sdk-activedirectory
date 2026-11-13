//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestNativeAccountControlConditionalFlagsAndUnlockWire(t *testing.T) {
	mod := func(operation byte, attribute, value string) []byte {
		return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte(attribute)), searchBER(0x31, searchBER(4, []byte(value)))))
	}
	for _, unlock := range []bool{false, true} {
		for _, code := range []byte{0, 16, 50} {
			t.Run(fmt.Sprintf("unlock-%t-code-%d", unlock, code), func(t *testing.T) {
				var mods []byte
				if unlock {
					mods = searchBER(0x30, mod(2, "lockoutTime", "0"))
				} else {
					mods = searchBER(0x30, mod(1, "userAccountControl", "1073742336"), mod(0, "userAccountControl", "1073742338"))
				}
				want := append(searchBER(4, []byte("<GUID=33221100554477668899aabbccddeeff>")), mods...)
				fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, code)
				var owners searchNativeCounts
				client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
				native := client.session.(*ldapSession)
				writes, reads, closes := 0, 0, 0
				client.session = objectWriteTestSession{testSession: testSession{
					read: func(context.Context, []string) (map[string][][]byte, error) {
						return identityTestRoot(CapabilityActiveDirectory), nil
					},
					search: func(context.Context, SearchOptions) (searchCursor, error) {
						reads++
						flags := Flags32(0x40000200)
						if writes > 0 && !unlock {
							flags |= 2
						}
						object := accountTestEntry(flags)
						if writes == 0 && unlock {
							object.Attributes["lockouttime"] = [][]byte{[]byte("1234")}
						}
						return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return []Object{object}, true, nil }, finish: func() error { closes++; return nil }}, nil
					}, finish: native.close,
				}, write: func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
					writes++
					return native.ldapWrite(ctx, request)
				}}
				var result AccountControlMutationResult
				var err error
				if unlock {
					result, err = client.UnlockAccount(context.Background(), objectTestIdentity(), ObjectMutationOptions{})
				} else {
					result, err = client.DisableAccount(context.Background(), objectTestIdentity(), ObjectMutationOptions{})
				}
				if writes != 1 || closes != reads {
					t.Fatal(writes, reads, closes)
				}
				if code == 0 {
					if err != nil || reads != 2 || result.Mutation.State != ObjectWriteAccepted || !result.Mutation.Verified {
						t.Fatal(result, err, reads)
					}
				} else {
					var nativeErr *LDAPError
					if !errors.As(err, &nativeErr) || nativeErr.Code != uint32(code) || nativeErr.Diagnostic != "private wire diagnostic" || reads != 1 || result.Mutation.State != ObjectWriteRejected {
						t.Fatal(result, err, reads)
					}
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				if owners != (searchNativeCounts{}) {
					t.Fatal("native owners not released", owners)
				}
			})
		}
	}
}
