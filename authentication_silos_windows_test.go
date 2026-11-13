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

func siloWireModification(operation byte, name string, values ...[]byte) []byte {
	return searchBER(0x30, []byte{10, 1, operation}, authWireAttribute(name, values...))
}

func TestNativeAuthenticationSiloPublicWireAndOwnership(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete", "grant", "revoke", "assign", "clear"} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("%s-%d", operation, code), func(t *testing.T) {
				f := newAuthenticationSiloFixture()
				f.objects[siloTestDN].Attributes[strings.ToLower(siloMembersAttribute)] = [][]byte{[]byte("CN=Other,DC=example")}
				if operation == "revoke" {
					f.objects[siloTestDN].Attributes[strings.ToLower(siloMembersAttribute)] = append(f.objects[siloTestDN].Attributes[strings.ToLower(siloMembersAttribute)], []byte(authTestAccount))
				}
				guid, _ := GUIDFromBytes(f.objects[siloTestDN].Attributes["objectguid"][0])
				dn := objectGUIDTarget(guid)
				tag, response := byte(0x66), byte(0x67)
				var body []byte
				switch operation {
				case "create":
					tag, response = 0x68, 0x69
					dn = `cn=李\, Silo,` + siloTestContainer
					body = append(searchBER(4, []byte(dn)), searchBER(0x30, authWireAttribute("msDS-AuthNPolicySiloEnforced", []byte("FALSE")), authWireAttribute("objectClass", []byte("msDS-AuthNPolicySilo")), authWireAttribute("cn", []byte("李, Silo")))...)
				case "delete":
					tag, response, body = 0x4a, 0x6b, []byte(dn)
				case "update":
					body = append(searchBER(4, []byte(dn)), searchBER(0x30, siloWireModification(2, "msDS-AuthNPolicySiloEnforced", []byte("TRUE")), siloWireModification(2, "msDS-UserAuthNPolicy", []byte(authTestPolicy)))...)
				case "grant", "revoke":
					op := byte(0)
					if operation == "revoke" {
						op = 1
					}
					body = append(searchBER(4, []byte(dn)), searchBER(0x30, siloWireModification(op, siloMembersAttribute, []byte(authTestAccount)))...)
				default:
					guid, _ = GUIDFromBytes(f.objects[authTestAccount].Attributes["objectguid"][0])
					dn = objectGUIDTarget(guid)
					if operation == "assign" {
						body = append(searchBER(4, []byte(dn)), searchBER(0x30, siloWireModification(2, "msDS-AssignedAuthNPolicySilo", []byte(siloTestDN)), siloWireModification(2, "msDS-AssignedAuthNPolicy", []byte(authTestPolicy)))...)
					} else {
						body = append(searchBER(4, []byte(dn)), searchBER(0x30, siloWireModification(1, "msDS-AssignedAuthNPolicySilo"), siloWireModification(1, "msDS-AssignedAuthNPolicy"))...)
					}
				}
				wire := newWriteWireFixture(t, tag, response, body, nil, code)
				var owners searchNativeCounts
				native := searchWireClient(t, &searchWireFixture{listener: wire.listener}, countedSearchAPI(&owners))
				f.write = func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
					return native.session.(*ldapSession).ldapWrite(ctx, request)
				}
				client := f.client(t)
				silo, policy := authTestIdentity(siloTestDN), authTestIdentity(authTestPolicy)
				var result ObjectMutationResult
				var err error
				switch operation {
				case "create":
					created, e := client.CreateAuthenticationPolicySilo(context.Background(), CreateAuthenticationPolicySiloRequest{Name: "李, Silo"})
					result, err = created.Mutation, e
				case "update":
					value := true
					updated, e := client.UpdateAuthenticationPolicySilo(context.Background(), UpdateAuthenticationPolicySiloRequest{Identity: silo, Properties: AuthenticationPolicySiloProperties{Enforced: &value, UserAuthenticationPolicy: &policy}})
					result, err = updated.Mutation, e
				case "delete":
					result, err = client.DeleteAuthenticationPolicySilo(context.Background(), DeleteAuthenticationPolicySiloRequest{Identity: silo})
				case "grant", "revoke":
					changed, e := client.changeAuthenticationSiloAccess(context.Background(), AuthenticationPolicySiloAccessRequest{Identity: silo, Account: authTestIdentity(authTestAccount)}, operation == "grant")
					result, err = changed.Mutation, e
				default:
					request := SetAccountAuthenticationPolicySiloRequest{Identity: authTestIdentity(authTestAccount), Silo: &silo, Policy: &policy}
					if operation == "clear" {
						request.Silo, request.Policy = nil, nil
						request.ClearSilo, request.ClearPolicy = true, true
					}
					changed, e := client.SetAccountAuthenticationPolicySilo(context.Background(), request)
					result, err = changed.Mutation, e
				}
				if code == 0 {
					if result.State != ObjectWriteAccepted {
						t.Fatal(result, err)
					}
					if operation == "clear" {
						if !errors.Is(err, ErrObjectVerification) || result.Verified {
							t.Fatal(result, err)
						}
					} else if err != nil || !result.Verified {
						t.Fatal(result, err)
					}
				} else {
					var nativeErr *LDAPError
					if result.State != ObjectWriteRejected || !errors.As(err, &nativeErr) || nativeErr.Code != 50 || nativeErr.Diagnostic != "private wire diagnostic" {
						t.Fatal(result, err)
					}
				}
				if len(f.writes) != 1 {
					t.Fatal("replayed", f.writes)
				}
				if err := native.Close(); err != nil {
					t.Fatal(err)
				}
				if owners != (searchNativeCounts{}) {
					t.Fatal(owners)
				}
			})
		}
	}
}

func TestNativeAuthenticationSiloLinkedRangesAndPartialReply(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			f := newAuthenticationSiloFixture()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() { done <- serveSiloRanges(listener, f.objects[siloTestDN], denied) }()
			var owners searchNativeCounts
			native := searchWireClient(t, &searchWireFixture{listener: listener}, countedSearchAPI(&owners))
			f.rangeRead = native.session.(*ldapSession).rangedBaseObject
			result, err := f.client(t).AuthenticationPolicySilo(context.Background(), authTestIdentity(siloTestDN), AuthenticationPolicySiloReadOptions{})
			if len(result.Members.DistinguishedNames) != 2 || len(result.Members.Observations) != 2 {
				t.Fatal(result, err)
			}
			if denied {
				var nativeErr *LDAPError
				if !errors.As(err, &nativeErr) || nativeErr.Code != 50 || result.Members.Complete {
					t.Fatal(result, err)
				}
			} else if err != nil || !result.Members.Complete || !result.AssignedAccounts.Complete || result.AssignedAccounts.AttributeReturned {
				t.Fatal(result, err)
			}
			if err := native.Close(); err != nil {
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
			if owners != (searchNativeCounts{}) {
				t.Fatal(owners)
			}
		})
	}
}

func serveSiloRanges(listener net.Listener, object Object, denied bool) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	count := 3
	if denied {
		count = 2
	}
	guid, _ := GUIDFromBytes(object.Attributes["objectguid"][0])
	for round := 0; round < count; round++ {
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
		if err != nil || string(base) != objectGUIDTarget(guid) {
			return errors.New("wrong silo GUID base")
		}
		scope, _, err := takeSearchBER(remainder, 10)
		if err != nil || !bytes.Equal(scope, []byte{0}) || len(controls) != 0 {
			return errors.New("silo range requires plain BASE search")
		}
		wanted := fmt.Sprintf("%s;range=%d-*", siloMembersAttribute, round)
		if round == 2 {
			wanted = siloAssignedAttribute + ";range=0-*"
		}
		if !bytes.Contains(request, []byte(wanted)) {
			return errors.New("wrong silo range request")
		}
		attrs := [][]byte{authWireAttribute("objectGUID", object.Attributes["objectguid"][0]), authWireAttribute("uSNChanged", []byte("1"))}
		if round < 2 {
			name := siloMembersAttribute + ";range=0-0"
			if round == 1 {
				name = siloMembersAttribute + ";range=1-*"
			}
			attrs = append(attrs, authWireAttribute(name, []byte(fmt.Sprintf("CN=Account%d,DC=example", round))))
		}
		entry := searchBER(0x64, searchBER(4, []byte(object.DistinguishedName)), searchBER(0x30, attrs...))
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
		return errors.New("expected silo unbind")
	}
	return nil
}
