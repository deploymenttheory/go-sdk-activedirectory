//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

func TestNativeAccountControlConditionalFlagsAndUnlockWire(t *testing.T) {
	mod := func(operation byte, attribute, value string) []byte {
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
	for _, unlock := range []bool{false, true} {
		for _, code := range []byte{0, 16, 50} {
			t.Run(fmt.Sprintf("unlock-%t-code-%d", unlock, code), func(t *testing.T) {
				var mods []byte
				if unlock {
					mods = InternalSearchBER(0x30, mod(2, "lockoutTime", "0"))
				} else {
					mods = InternalSearchBER(
						0x30,
						mod(1, "userAccountControl", "1073742336"),
						mod(0, "userAccountControl", "1073742338"),
					)
				}
				want := append(
					InternalSearchBER(4, []byte("<GUID=33221100554477668899aabbccddeeff>")),
					mods...)
				fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, nil, code)
				var owners InternalSearchNativeCounts
				client := InternalSearchWireClient(
					t,
					&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
					InternalCountedSearchAPI(&owners),
				)
				native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
				writes, reads, closes := 0, 0, 0
				(*adengine.InternalClientSessionPointer(client)) = InternalObjectWriteTestSession{
					InternalTestSession: InternalTestSession{
						InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
							return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
						},
						InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
							reads++
							flags := admodel.Flags32(0x40000200)
							if writes > 0 && !unlock {
								flags |= 2
							}
							object := InternalAccountTestEntry(flags)
							if writes == 0 && unlock {
								object.Attributes["lockouttime"] = [][]byte{[]byte("1234")}
							}
							return InternalTestSearchCursor{
								InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
									return []admodel.Object{object}, true, nil
								},
								InternalFinish: func() error { closes++; return nil },
							}, nil
						},
						InternalFinish: native.InternalClose,
					},
					InternalWrite: func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						writes++
						return native.InternalLdapWrite(ctx, request)
					},
				}
				var result admodel.AccountControlMutationResult
				var err error
				if unlock {
					result, err = adservice_accounts.New(client).
						UnlockAccount(context.Background(), InternalObjectTestIdentity(), admodel.ObjectMutationOptions{})
				} else {
					result, err = adservice_accounts.New(client).
						DisableAccount(context.Background(), InternalObjectTestIdentity(), admodel.ObjectMutationOptions{})
				}
				if writes != 1 || closes != reads {
					t.Fatal(writes, reads, closes)
				}
				if code == 0 {
					if err != nil || reads != 2 ||
						result.Mutation.State != admodel.ObjectWriteAccepted ||
						!result.Mutation.Verified {
						t.Fatal(result, err, reads)
					}
				} else {
					var nativeErr *admodel.LDAPError
					if !errors.As(err, &nativeErr) || nativeErr.Code != uint32(code) ||
						nativeErr.Diagnostic != "private wire diagnostic" ||
						reads != 1 ||
						result.Mutation.State != admodel.ObjectWriteRejected {
						t.Fatal(result, err, reads)
					}
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				if owners != (InternalSearchNativeCounts{}) {
					t.Fatal("native owners not released", owners)
				}
			})
		}
	}
}
