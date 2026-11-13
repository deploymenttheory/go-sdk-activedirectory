//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNativeAuthorizationTokenGroupsBinaryRangesAndOwnership(t *testing.T) {
	account := membershipObject("account", "DC=example", "user", 1, 1100, 1)
	groups := []Object{membershipObject("first", "DC=example", "group", 2, 513, 1), membershipObject("second", "DC=example", "group", 3, 1000, 1)}
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() { done <- serveAuthorizationRanges(listener, account, groups, denied) }()
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			client.session = groupMemberTestSession{testSession: testSession{
				base: func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
					if dn == "" {
						return identityTestRoot(CapabilityActiveDirectory), nil
					}
					return native.baseObject(ctx, dn, properties)
				},
				search: func(_ context.Context, query SearchOptions) (searchCursor, error) {
					if query.Scope == ScopeBase {
						return objectTestCursor(account), nil
					}
					for _, group := range groups {
						if strings.Contains(query.Filter, membershipFilter("objectSid", group.Attributes["objectsid"][0])) {
							return objectTestCursor(group), nil
						}
					}
					t.Fatal("unexpected authorization lookup", query)
					return nil, ErrInvalidResult
				}, finish: native.close,
			}, memberRead: native.groupMemberBaseObject}
			result, err := client.AccountAuthorizationGroups(context.Background(), groupMemberDN(t, account.DistinguishedName), AccountAuthorizationGroupsOptions{})
			if len(result.SIDs) != 2 || len(result.Ranges) != 2 {
				t.Fatal(result, err)
			}
			if denied {
				if !hasLDAPCode(err, 50) || result.Complete || result.TokensComplete {
					t.Fatal(result, err)
				}
			} else if err != nil || !result.Complete || !result.TokensComplete || len(result.Groups) != 2 {
				t.Fatal(result, err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("authorization responder did not stop")
			}
			if owners != (searchNativeCounts{}) {
				t.Fatalf("native ownership leak: %+v", owners)
			}
		})
	}
}
func serveAuthorizationRanges(listener net.Listener, account Object, groups []Object, denied bool) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for round := 0; round < 2; round++ {
		packet, err := readSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := takeSearchBER(packet, 2)
		if err != nil {
			return err
		}
		request, controls, err := takeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		base, remainder, err := takeSearchBER(request, 4)
		if err != nil || string(base) != membershipObjectKey(account) {
			return errors.New("wrong authorization GUID base")
		}
		scope, _, err := takeSearchBER(remainder, 10)
		if err != nil || !bytes.Equal(scope, []byte{0}) {
			return errors.New("tokenGroups requires BASE search")
		}
		if len(controls) != 0 || !bytes.Contains(request, []byte(fmt.Sprintf("tokenGroups;range=%d-%d", round, round+1499))) || bytes.Contains(request, []byte("NoGCAcceptable")) {
			return errors.New("unexpected tokenGroups request or fallback")
		}
		name := "tokenGroups;range=0-0"
		if round == 1 {
			name = "tokenGroups;range=1-*"
		}
		entry := searchBER(0x64, searchBER(4, []byte(account.DistinguishedName)), searchBER(0x30, searchWireAttribute(name, groups[round].Attributes["objectsid"][0]), searchWireAttribute("objectGUID", account.Attributes["objectguid"][0]), searchWireAttribute("uSNChanged", []byte("7"))))
		if _, err := conn.Write(searchBER(0x30, searchBER(2, id), entry)); err != nil {
			return err
		}
		code := byte(0)
		if denied && round == 1 {
			code = 50
		}
		if _, err := conn.Write(searchBER(0x30, searchBER(2, id), searchBER(0x65, []byte{10, 1, code, 4, 0, 4, 0}))); err != nil {
			return err
		}
	}
	packet, err := readSearchBER(conn)
	if err != nil {
		return err
	}
	_, rest, err := takeSearchBER(packet, 2)
	if err != nil || len(rest) == 0 || rest[0] != 0x42 {
		return errors.New("expected authorization unbind")
	}
	return nil
}

func TestNativePrincipalMembershipUsesResolvedGUIDOnce(t *testing.T) {
	principal := membershipObject("principal", "DC=example", "user", 1, 1100, 1)
	group := membershipObject("group", "DC=example", "group", 2, 1000, 1)
	want := append(searchBER(4, []byte("<GUID=02000000000000000000000000000000>")), searchBER(0x30, searchBER(0x30, []byte{10, 1, 0}, searchBER(0x30, searchBER(4, []byte("member")), searchBER(0x31, searchBER(4, []byte("<GUID=01000000000000000000000000000000>"))))))...)
	for _, code := range []byte{0, 50} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, code)
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			writes := 0
			client.session = objectWriteTestSession{testSession: testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
				return identityTestRoot(CapabilityActiveDirectory), nil
			}, search: func(_ context.Context, query SearchOptions) (searchCursor, error) {
				if query.Base == principal.DistinguishedName {
					return objectTestCursor(principal), nil
				}
				return objectTestCursor(group), nil
			}, finish: native.close}, write: func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
				writes++
				return native.ldapWrite(ctx, request)
			}}
			result, err := client.AddPrincipalGroupMembership(context.Background(), PrincipalGroupMembershipRequest{Principal: groupMemberDN(t, principal.DistinguishedName), Groups: []PrincipalMembershipTarget{{Identity: groupMemberDN(t, group.DistinguishedName)}}, Mode: GroupMembershipStrict})
			if writes != 1 || result.Processed != 1 || len(result.Outcomes) != 1 {
				t.Fatal(result, err)
			}
			if code == 0 {
				if err != nil || !result.Complete || result.Outcomes[0].Result.Mutation.State != ObjectWriteAccepted {
					t.Fatal(result, err)
				}
			} else if !hasLDAPCode(err, 50) || result.Complete || result.Outcomes[0].Result.Mutation.State != ObjectWriteRejected {
				t.Fatal(result, err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (searchNativeCounts{}) {
				t.Fatal(owners)
			}
		})
	}
}
