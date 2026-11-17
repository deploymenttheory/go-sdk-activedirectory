//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

func TestNativeGroupMembershipModifyWire(t *testing.T) {
	for _, mode := range []string{"ttl-permissive", "ttl-zero", "strict-remove", "scope-rejected", "permission"} {
		t.Run(mode, func(t *testing.T) {
			member := InternalGroupMemberDN(t, `CN=Jörg\, Admin,DC=foreign`)
			value, operation, code := member.String(), byte(0), byte(0)
			var controls []byte
			if mode == "ttl-permissive" || mode == "ttl-zero" {
				seconds := "90"
				if mode == "ttl-zero" {
					seconds = "0"
				}
				value = "<TTL=" + seconds + "," + value + ">"
				controls = InternalSearchBER(
					0xa0,
					InternalSearchBER(
						0x30,
						InternalSearchBER(4, []byte(admodel.InternalGroupPermissiveModify)),
						[]byte{1, 1, 255},
						InternalSearchBER(4, nil),
					),
				)
			}
			if mode == "strict-remove" {
				operation = 1
			}
			if mode == "scope-rejected" {
				code = 19
			}
			if mode == "permission" {
				code = 50
			}
			want := append(
				InternalSearchBER(
					4,
					[]byte(admodel.InternalObjectGUIDTarget(InternalObjectTestGUID())),
				),
				InternalSearchBER(
					0x30,
					InternalSearchBER(
						0x30,
						[]byte{10, 1, operation},
						InternalSearchBER(
							0x30,
							InternalSearchBER(4, []byte("member")),
							InternalSearchBER(0x31, InternalSearchBER(4, []byte(value))),
						),
					),
				)...)
			fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, controls, code)
			var counts InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&counts),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			writes, reads := 0, 0
			(*adengine.InternalClientSessionPointer(client)) = InternalObjectWriteTestSession{
				InternalTestSession: InternalTestSession{
					InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
						root := InternalIdentityTestRoot(admodel.CapabilityActiveDirectory)
						root["supportedcontrol"] = [][]byte{
							[]byte(admodel.InternalGroupPermissiveModify),
							[]byte(admodel.InternalGroupLinkTTL),
						}
						return root, nil
					},
					InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						reads++
						return InternalObjectTestCursor(InternalGroupTestEntry(2)), nil
					},
					InternalFinish: native.InternalClose,
				},
				InternalWrite: func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					runtime.GC()
					return native.InternalLdapWrite(ctx, request)
				},
			}
			request := admodel.AddGroupMembersRequest{
				Identity: InternalObjectTestIdentity(),
				Members:  []admodel.Identity{member},
				Mode:     admodel.GroupMembershipStrict,
			}
			ttl := 90 * time.Second
			if mode == "ttl-zero" {
				ttl = 0
			}
			if mode == "ttl-permissive" || mode == "ttl-zero" {
				request.Mode = admodel.GroupMembershipPermissive
				request.TimeToLive = &ttl
			}
			var result admodel.GroupMembershipMutationResult
			var err error
			if mode == "strict-remove" {
				result, err = adservice_memberships.New(client).
					RemoveGroupMembers(context.Background(), admodel.RemoveGroupMembersRequest{Identity: request.Identity, Members: request.Members, Mode: request.Mode})
			} else {
				result, err = adservice_memberships.New(client).
					AddGroupMembers(context.Background(), request)
			}
			if writes != 1 || result.Mutation.Verified {
				t.Fatal(result, err, writes)
			}
			if code == 0 {
				if err != nil || result.Mutation.State != admodel.ObjectWriteAccepted ||
					reads != 2 {
					t.Fatal(result, err)
				}
			} else {
				if !InternalHasLDAPCode(err, uint32(code)) ||
					result.Mutation.State != admodel.ObjectWriteRejected ||
					reads != 1 {
					t.Fatal(result, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("native owners: %+v", counts)
			}
		})
	}
}

// Use real WinLDAP search/BER/value/name/message ownership for two contiguous
// ranges, including critical TTL controls and a partial permission failure.
func TestNativeGroupMemberRangesAndTTL(t *testing.T) {
	for _, mode := range []string{"ordinary", "ttl", "partial-denied"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() { done <- InternalServeGroupMemberRanges(listener, mode) }()
			var counts InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: listener},
				InternalCountedSearchAPI(&counts),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			(*adengine.InternalClientSessionPointer(client)) = InternalGroupMemberTestSession{
				InternalTestSession: InternalTestSession{
					InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
						root := InternalIdentityTestRoot(admodel.CapabilityActiveDirectory)
						root["supportedcontrol"] = [][]byte{[]byte(admodel.InternalGroupLinkTTL)}
						return root, nil
					},
					InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						return InternalObjectTestCursor(InternalGroupTestEntry(2)), nil
					},
					InternalFinish: native.InternalClose,
				},
				InternalMemberRead: func(ctx context.Context, base string, attrs []string, ttl bool) (map[string][][]byte, error) {
					runtime.GC()
					return native.InternalGroupMemberBaseObject(ctx, base, attrs, ttl)
				},
			}
			result, err := adservice_memberships.New(client).
				GroupMemberLinks(context.Background(), InternalObjectTestIdentity(), admodel.GroupMemberLinksOptions{IncludeTTL: mode == "ttl"})
			if len(result.Members) != 2 || len(result.Ranges) != 2 || !result.AttributeReturned {
				t.Fatal(result, err)
			}
			if mode == "partial-denied" {
				if !InternalHasLDAPCode(err, 50) || result.Complete {
					t.Fatal(result, err)
				}
			} else if err != nil || !result.Complete {
				t.Fatal(result, err)
			}
			if mode == "ttl" &&
				(*result.Members[0].RemainingTTLSeconds != 89 || result.Members[0].DistinguishedName != `CN=Jörg\, Admin,DC=foreign`) {
				t.Fatal(result)
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
				t.Fatal("range responder did not stop")
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("native owners: %+v", counts)
			}
		})
	}
}

func InternalServeGroupMemberRanges(listener net.Listener, mode string) error {
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
		base, _, err := InternalTakeSearchBER(request, 4)
		if err != nil ||
			string(base) != admodel.InternalObjectGUIDTarget(InternalObjectTestGUID()) {
			return errors.New("wrong range base")
		}
		// Independently assert requested range and selected consistency attributes.
		if !bytes.Contains(request, []byte(fmt.Sprintf("member;range=%d-%d", round, round+1499))) ||
			!bytes.Contains(request, []byte("objectGUID")) ||
			!bytes.Contains(request, []byte("uSNChanged")) {
			return errors.New("wrong range projection")
		}
		want := []byte(nil)
		if mode == "ttl" {
			want = InternalSearchBER(
				0xa0,
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte(admodel.InternalGroupLinkTTL)),
					[]byte{1, 1, 255},
					InternalSearchBER(4, nil),
				),
			)
		}
		canonical, err := InternalCanonicalWriteBER(controls)
		if err != nil || !bytes.Equal(canonical, want) {
			return fmt.Errorf("wrong TTL controls %x", controls)
		}
		name := "member;range=0-0"
		if round == 1 {
			name = "member;range=1-*"
		}
		value := `CN=Jörg\, Admin,DC=foreign`
		if round == 1 {
			value = "CN=nested,DC=example"
		}
		if mode == "ttl" {
			value = "<TTL=89," + value + ">"
		}
		entry := InternalSearchBER(
			0x64,
			InternalSearchBER(4, []byte("CN=sample,DC=example")),
			InternalSearchBER(
				0x30,
				InternalSearchWireAttribute(name, []byte(value)),
				InternalSearchWireAttribute("objectGUID", InternalObjectTestGUID().Bytes()),
				InternalSearchWireAttribute("uSNChanged", []byte("7")),
			),
		)
		if _, err = conn.Write(
			InternalSearchBER(0x30, InternalSearchBER(2, id), entry),
		); err != nil {
			return err
		}
		code := byte(0)
		if mode == "partial-denied" && round == 1 {
			code = 50
		}
		if _, err = conn.Write(
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
		return errors.New("expected native unbind")
	}
	return nil
}
