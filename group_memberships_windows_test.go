//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestNativeGroupMembershipModifyWire(t *testing.T) {
	for _, mode := range []string{"ttl-permissive", "ttl-zero", "strict-remove", "scope-rejected", "permission"} {
		t.Run(mode, func(t *testing.T) {
			member := groupMemberDN(t, `CN=Jörg\, Admin,DC=foreign`)
			value, operation, code := member.String(), byte(0), byte(0)
			var controls []byte
			if mode == "ttl-permissive" || mode == "ttl-zero" {
				seconds := "90"
				if mode == "ttl-zero" {
					seconds = "0"
				}
				value = "<TTL=" + seconds + "," + value + ">"
				controls = searchBER(0xa0, searchBER(0x30, searchBER(4, []byte(groupPermissiveModify)), []byte{1, 1, 255}, searchBER(4, nil)))
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
			want := append(searchBER(4, []byte(objectGUIDTarget(objectTestGUID()))), searchBER(0x30, searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte("member")), searchBER(0x31, searchBER(4, []byte(value))))))...)
			fixture := newWriteWireFixture(t, 0x66, 0x67, want, controls, code)
			var counts searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
			native := client.session.(*ldapSession)
			writes, reads := 0, 0
			client.session = objectWriteTestSession{testSession: testSession{
				read: func(context.Context, []string) (map[string][][]byte, error) {
					root := identityTestRoot(CapabilityActiveDirectory)
					root["supportedcontrol"] = [][]byte{[]byte(groupPermissiveModify), []byte(groupLinkTTL)}
					return root, nil
				},
				search: func(context.Context, SearchOptions) (searchCursor, error) {
					reads++
					return objectTestCursor(groupTestEntry(2)), nil
				}, finish: native.close,
			}, write: func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
				writes++
				runtime.GC()
				return native.ldapWrite(ctx, request)
			}}
			request := AddGroupMembersRequest{Identity: objectTestIdentity(), Members: []Identity{member}, Mode: GroupMembershipStrict}
			ttl := 90 * time.Second
			if mode == "ttl-zero" {
				ttl = 0
			}
			if mode == "ttl-permissive" || mode == "ttl-zero" {
				request.Mode = GroupMembershipPermissive
				request.TimeToLive = &ttl
			}
			var result GroupMembershipMutationResult
			var err error
			if mode == "strict-remove" {
				result, err = client.RemoveGroupMembers(context.Background(), RemoveGroupMembersRequest{Identity: request.Identity, Members: request.Members, Mode: request.Mode})
			} else {
				result, err = client.AddGroupMembers(context.Background(), request)
			}
			if writes != 1 || result.Mutation.Verified {
				t.Fatal(result, err, writes)
			}
			if code == 0 {
				if err != nil || result.Mutation.State != ObjectWriteAccepted || reads != 2 {
					t.Fatal(result, err)
				}
			} else {
				if !hasLDAPCode(err, uint32(code)) || result.Mutation.State != ObjectWriteRejected || reads != 1 {
					t.Fatal(result, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (searchNativeCounts{}) {
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
			go func() { done <- serveGroupMemberRanges(listener, mode) }()
			var counts searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: listener}, countedSearchAPI(&counts))
			native := client.session.(*ldapSession)
			client.session = groupMemberTestSession{testSession: testSession{
				read: func(context.Context, []string) (map[string][][]byte, error) {
					root := identityTestRoot(CapabilityActiveDirectory)
					root["supportedcontrol"] = [][]byte{[]byte(groupLinkTTL)}
					return root, nil
				},
				search: func(context.Context, SearchOptions) (searchCursor, error) {
					return objectTestCursor(groupTestEntry(2)), nil
				}, finish: native.close,
			}, memberRead: func(ctx context.Context, base string, attrs []string, ttl bool) (map[string][][]byte, error) {
				runtime.GC()
				return native.groupMemberBaseObject(ctx, base, attrs, ttl)
			}}
			result, err := client.GroupMemberLinks(context.Background(), objectTestIdentity(), GroupMemberLinksOptions{IncludeTTL: mode == "ttl"})
			if len(result.Members) != 2 || len(result.Ranges) != 2 || !result.AttributeReturned {
				t.Fatal(result, err)
			}
			if mode == "partial-denied" {
				if !hasLDAPCode(err, 50) || result.Complete {
					t.Fatal(result, err)
				}
			} else if err != nil || !result.Complete {
				t.Fatal(result, err)
			}
			if mode == "ttl" && (*result.Members[0].RemainingTTLSeconds != 89 || result.Members[0].DistinguishedName != `CN=Jörg\, Admin,DC=foreign`) {
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
			if counts != (searchNativeCounts{}) {
				t.Fatalf("native owners: %+v", counts)
			}
		})
	}
}

func serveGroupMemberRanges(listener net.Listener, mode string) error {
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
		base, _, err := takeSearchBER(request, 4)
		if err != nil || string(base) != objectGUIDTarget(objectTestGUID()) {
			return errors.New("wrong range base")
		}
		// Independently assert requested range and selected consistency attributes.
		if !bytes.Contains(request, []byte(fmt.Sprintf("member;range=%d-%d", round, round+1499))) || !bytes.Contains(request, []byte("objectGUID")) || !bytes.Contains(request, []byte("uSNChanged")) {
			return errors.New("wrong range projection")
		}
		want := []byte(nil)
		if mode == "ttl" {
			want = searchBER(0xa0, searchBER(0x30, searchBER(4, []byte(groupLinkTTL)), []byte{1, 1, 255}, searchBER(4, nil)))
		}
		canonical, err := canonicalWriteBER(controls)
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
		entry := searchBER(0x64, searchBER(4, []byte("CN=sample,DC=example")), searchBER(0x30, searchWireAttribute(name, []byte(value)), searchWireAttribute("objectGUID", objectTestGUID().Bytes()), searchWireAttribute("uSNChanged", []byte("7"))))
		if _, err = conn.Write(searchBER(0x30, searchBER(2, id), entry)); err != nil {
			return err
		}
		code := byte(0)
		if mode == "partial-denied" && round == 1 {
			code = 50
		}
		if _, err = conn.Write(searchBER(0x30, searchBER(2, id), searchBER(0x65, []byte{10, 1, code, 4, 0, 4, 0}))); err != nil {
			return err
		}
	}
	packet, err := readSearchBER(conn)
	if err != nil {
		return err
	}
	_, rest, err := takeSearchBER(packet, 2)
	if err != nil || len(rest) == 0 || rest[0] != 0x42 {
		return errors.New("expected native unbind")
	}
	return nil
}
