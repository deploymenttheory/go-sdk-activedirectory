//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Exercise the public workflow with injected directory observations and the
// actual WinLDAP writer on loopback. No directory, account or fixture is changed.
func TestNativeUpdateGroupConditionalTypeWireAndOwnership(t *testing.T) {
	const oldFlags, newFlags Flags32 = 0xc0000002, 0xc0000008
	const target = "<GUID=33221100554477668899aabbccddeeff>"
	modification := func(operation byte, value string) []byte {
		return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30,
			searchBER(4, []byte("groupType")), searchBER(0x31, searchBER(4, []byte(value)))))
	}
	// Both values retain the security and unrelated 0x40000000 bits. Exact
	// signed decimal strings are asserted independently of Flags32.LDAPString.
	want := append(searchBER(4, []byte(target)), searchBER(0x30,
		modification(1, "-1073741822"), modification(0, "-1073741816"))...)
	for _, code := range []byte{0, 16, 50} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, code)
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			reads, writes, cursorCloses := 0, 0, 0
			client.session = objectWriteTestSession{
				testSession: testSession{
					read: func(context.Context, []string) (map[string][][]byte, error) {
						return identityTestRoot(CapabilityActiveDirectory), nil
					},
					search: func(_ context.Context, query SearchOptions) (searchCursor, error) {
						reads++
						flags := oldFlags
						if writes != 0 {
							flags = newFlags
							if code != 0 || query.Scope != ScopeSubtree || query.Filter != `(objectGUID=\33\22\11\00\55\44\77\66\88\99\aa\bb\cc\dd\ee\ff)` {
								t.Fatal("unexpected readback after rejection or incorrect identity", query)
							}
						}
						return testSearchCursor{
							read: func(context.Context, uint32) ([]Object, bool, error) {
								return []Object{groupTestEntry(flags)}, true, nil
							},
							finish: func() error { cursorCloses++; return nil },
						}, nil
					},
					finish: native.close,
				},
				write: func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
					writes++
					// The real encoder and loopback responder verify one Modify,
					// GUID target, delete-before-add order and exact signed values.
					runtime.GC()
					return native.ldapWrite(ctx, request)
				},
			}
			scope := GroupUniversal
			result, err := client.UpdateGroup(context.Background(), UpdateGroupRequest{Identity: objectTestIdentity(), Scope: &scope})
			if writes != 1 || cursorCloses != reads {
				t.Fatalf("writes=%d reads=%d closed=%d", writes, reads, cursorCloses)
			}
			if code == 0 {
				if err != nil || reads != 2 || result.Mutation.State != ObjectWriteAccepted || !result.Mutation.Verified || result.Group == nil || result.Group.Type == nil || *result.Group.Type != newFlags || *result.Group.Category != GroupSecurity || *result.Group.Scope != GroupUniversal {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) || ldapErr.Diagnostic != "private wire diagnostic" || strings.Contains(err.Error(), "private wire diagnostic") || result.Mutation.State != ObjectWriteRejected || result.Mutation.Verified || reads != 1 {
					t.Fatal("rejection lost or write replayed", result, err)
				}
				if code == 50 && !errors.Is(err, ErrObjectWritePermission) {
					t.Fatal("permission classification lost", err)
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
