//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

func TestNativeAuthorizationTokenGroupsBinaryRangesAndOwnership(t *testing.T) {
	account := InternalMembershipObject("account", "DC=example", "user", 1, 1100, 1)
	groups := []admodel.Object{
		InternalMembershipObject("first", "DC=example", "group", 2, 513, 1),
		InternalMembershipObject("second", "DC=example", "group", 3, 1000, 1),
	}
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() { done <- InternalServeAuthorizationRanges(listener, account, groups, denied) }()
			var owners InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: listener},
				InternalCountedSearchAPI(&owners),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			(*adengine.InternalClientSessionPointer(client)) = InternalGroupMemberTestSession{
				InternalTestSession: InternalTestSession{
					InternalBase: func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
						if dn == "" {
							return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
						}
						return native.InternalBaseObject(ctx, dn, properties)
					},
					InternalSearch: func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						if query.Scope == admodel.ScopeBase {
							return InternalObjectTestCursor(account), nil
						}
						for _, group := range groups {
							if strings.Contains(
								query.Filter,
								InternalMembershipFilter(
									"objectSid",
									group.Attributes["objectsid"][0],
								),
							) {
								return InternalObjectTestCursor(group), nil
							}
						}
						t.Fatal("unexpected authorization lookup", query)
						return nil, admodel.ErrInvalidResult
					},
					InternalFinish: native.InternalClose,
				},
				InternalMemberRead: native.InternalGroupMemberBaseObject,
			}
			result, err := adservice_memberships.New(client).
				AccountAuthorizationGroups(context.Background(), InternalGroupMemberDN(t, account.DistinguishedName), adengine.AccountAuthorizationGroupsOptions{})
			if len(result.SIDs) != 2 || len(result.Ranges) != 2 {
				t.Fatal(result, err)
			}
			if denied {
				if !InternalHasLDAPCode(err, 50) || result.Complete || result.TokensComplete {
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
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatalf("native ownership leak: %+v", owners)
			}
		})
	}
}

func InternalServeAuthorizationRanges(
	listener net.Listener,
	account admodel.Object,
	groups []admodel.Object,
	denied bool,
) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for round := 0; round < 2; round++ {
		packet, err := InternalReadSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := InternalTakeSearchBER(packet, 2)
		if err != nil {
			return err
		}
		request, controls, err := InternalTakeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		base, remainder, err := InternalTakeSearchBER(request, 4)
		if err != nil || string(base) != InternalMembershipObjectKey(account) {
			return errors.New("wrong authorization GUID base")
		}
		scope, _, err := InternalTakeSearchBER(remainder, 10)
		if err != nil || !bytes.Equal(scope, []byte{0}) {
			return errors.New("tokenGroups requires BASE search")
		}
		if len(controls) != 0 ||
			!bytes.Contains(
				request,
				[]byte(fmt.Sprintf("tokenGroups;range=%d-%d", round, round+1499)),
			) ||
			bytes.Contains(request, []byte("NoGCAcceptable")) {
			return errors.New("unexpected tokenGroups request or fallback")
		}
		name := "tokenGroups;range=0-0"
		if round == 1 {
			name = "tokenGroups;range=1-*"
		}
		entry := InternalSearchBER(
			0x64,
			InternalSearchBER(4, []byte(account.DistinguishedName)),
			InternalSearchBER(
				0x30,
				InternalSearchWireAttribute(name, groups[round].Attributes["objectsid"][0]),
				InternalSearchWireAttribute("objectGUID", account.Attributes["objectguid"][0]),
				InternalSearchWireAttribute("uSNChanged", []byte("7")),
			),
		)
		if _, err := conn.Write(
			InternalSearchBER(0x30, InternalSearchBER(2, id), entry),
		); err != nil {
			return err
		}
		code := byte(0)
		if denied && round == 1 {
			code = 50
		}
		if _, err := conn.Write(
			InternalSearchBER(
				0x30,
				InternalSearchBER(2, id),
				InternalSearchBER(0x65, []byte{10, 1, code, 4, 0, 4, 0}),
			),
		); err != nil {
			return err
		}
	}
	packet, err := InternalReadSearchBER(conn)
	if err != nil {
		return err
	}
	_, rest, err := InternalTakeSearchBER(packet, 2)
	if err != nil || len(rest) == 0 || rest[0] != 0x42 {
		return errors.New("expected authorization unbind")
	}
	return nil
}

func TestNativePrincipalMembershipUsesResolvedGUIDOnce(t *testing.T) {
	principal := InternalMembershipObject("principal", "DC=example", "user", 1, 1100, 1)
	group := InternalMembershipObject("group", "DC=example", "group", 2, 1000, 1)
	want := append(
		InternalSearchBER(4, []byte("<GUID=02000000000000000000000000000000>")),
		InternalSearchBER(
			0x30,
			InternalSearchBER(
				0x30,
				[]byte{10, 1, 0},
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte("member")),
					InternalSearchBER(
						0x31,
						InternalSearchBER(4, []byte("<GUID=01000000000000000000000000000000>")),
					),
				),
			),
		)...)
	for _, code := range []byte{0, 50} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, nil, code)
			var owners InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&owners),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			writes := 0
			(*adengine.InternalClientSessionPointer(client)) = InternalObjectWriteTestSession{
				InternalTestSession: InternalTestSession{
					InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
						return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
					},
					InternalSearch: func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						if query.Base == principal.DistinguishedName {
							return InternalObjectTestCursor(principal), nil
						}
						return InternalObjectTestCursor(group), nil
					},
					InternalFinish: native.InternalClose,
				},
				InternalWrite: func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return native.InternalLdapWrite(ctx, request)
				},
			}
			result, err := adservice_memberships.New(client).
				AddPrincipalGroupMembership(context.Background(), admodel.PrincipalGroupMembershipRequest{Principal: InternalGroupMemberDN(t, principal.DistinguishedName), Groups: []admodel.PrincipalMembershipTarget{{Identity: InternalGroupMemberDN(t, group.DistinguishedName)}}, Mode: admodel.GroupMembershipStrict})
			if writes != 1 || result.Processed != 1 || len(result.Outcomes) != 1 {
				t.Fatal(result, err)
			}
			if code == 0 {
				if err != nil || !result.Complete ||
					result.Outcomes[0].Result.Mutation.State != admodel.ObjectWriteAccepted {
					t.Fatal(result, err)
				}
			} else if !InternalHasLDAPCode(err, 50) || result.Complete || result.Outcomes[0].Result.Mutation.State != admodel.ObjectWriteRejected {
				t.Fatal(result, err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal(owners)
			}
		})
	}
}
