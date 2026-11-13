//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNativeRODCResultantPolicyAndRevealedRanges(t *testing.T) {
	for _, ranges := range []bool{false, true} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("ranges-%t-code-%d", ranges, code), func(t *testing.T) {
				f := newRODCPolicyFixture(t)
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() { done <- serveRODCReadWire(listener, f.controller, f.account, ranges, code) }()
				var owners searchNativeCounts
				wireClient := searchWireClient(t, &searchWireFixture{listener: listener}, countedSearchAPI(&owners))
				native := wireClient.session.(*ldapSession)
				f.session.policy = native.objectSyncPasswordPolicy
				f.session.memberRead = native.groupMemberBaseObject
				f.session.finish = native.close
				if ranges {
					result, err := f.client.RODCPasswordReplicationPolicyUsage(context.Background(), f.controllerIdentity(t), RODCPasswordRevealed, RODCPasswordReplicationOptions{})
					if len(result.Entries) != 2 || len(result.Ranges) != 2 || result.Entries[0].SecretAttribute != "unicodePwd" {
						t.Fatal(result, err)
					}
					if code == 0 {
						if err != nil || !result.Complete || len(result.Principals) != 1 {
							t.Fatal(result, err)
						}
					} else if !hasLDAPCode(err, 50) || result.Complete {
						t.Fatal(result, err)
					}
				} else {
					result, err := f.client.AccountResultantPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), groupMemberDN(t, f.account.DistinguishedName), RODCPasswordReplicationOptions{})
					if result.Policy == nil || *result.Policy != RODCPasswordPolicyDenyExplicit {
						t.Fatal(result, err)
					}
					if code == 0 {
						if err != nil || !result.Complete {
							t.Fatal(result, err)
						}
					} else if !hasLDAPCode(err, 50) || result.Complete {
						t.Fatal(result, err)
					}
				}
				if err := f.client.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("native RODC read did not terminate")
				}
				if owners != (searchNativeCounts{}) {
					t.Fatal("native ownership leak", owners)
				}
			})
		}
	}
}

func serveRODCReadWire(listener net.Listener, controller, account Object, ranges bool, code byte) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	rounds := 1
	if ranges {
		rounds = 2
	}
	for round := 0; round < rounds; round++ {
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
		if err != nil || string(base) != membershipObjectKey(controller) {
			return errors.New("wrong RODC GUID target")
		}
		scope, _, err := takeSearchBER(remainder, 10)
		if err != nil || !bytes.Equal(scope, []byte{0}) {
			return errors.New("RODC read must use BASE scope")
		}
		var attributes []byte
		if ranges {
			if len(controls) != 0 || !bytes.Contains(request, []byte(fmt.Sprintf("msDS-RevealedList;range=%d-%d", round, round+1499))) {
				return errors.New("wrong revealed range request")
			}
			name := "msDS-RevealedList;range=0-0"
			value := "S:10:unicodePwd:" + account.DistinguishedName
			if round == 1 {
				name = "msDS-RevealedList;range=1-*"
				value = "S:23:supplementalCredentials:" + account.DistinguishedName
			}
			attributes = append(attributes, searchWireAttribute(name, []byte(value))...)
			attributes = append(attributes, searchWireAttribute("objectGUID", controller.Attributes["objectguid"][0])...)
			attributes = append(attributes, searchWireAttribute("uSNChanged", []byte("7"))...)
		} else {
			if !bytes.Contains(request, []byte("msDS-IsUserCachableAtRodc")) {
				return errors.New("wrong constructed policy attribute")
			}
			outer, rest, err := takeSearchBER(controls, 0xa0)
			if err != nil || len(rest) != 0 {
				return errors.New("missing DN-input control")
			}
			control, rest, err := takeSearchBER(outer, 0x30)
			if err != nil || len(rest) != 0 {
				return errors.New("unexpected control count")
			}
			oid, rest, err := takeSearchBER(control, 4)
			if err != nil || string(oid) != objectSyncDNInputOID {
				return errors.New("wrong DN-input OID")
			}
			critical, rest, err := takeSearchBER(rest, 1)
			if err != nil || len(critical) != 1 || critical[0] == 0 {
				return errors.New("DN-input must be critical")
			}
			value, rest, err := takeSearchBER(rest, 4)
			if err != nil || len(rest) != 0 {
				return errors.New("invalid DN-input payload")
			}
			var decoded struct{ InputDN []byte }
			rest, err = asn1.Unmarshal(value, &decoded)
			if err != nil || len(rest) != 0 || string(decoded.InputDN) != membershipObjectKey(account) {
				return errors.New("wrong account GUID control value")
			}
			attributes = searchWireAttribute("msDS-IsUserCachableAtRodc", []byte("0"))
		}
		entry := searchBER(0x64, searchBER(4, []byte(controller.DistinguishedName)), searchBER(0x30, attributes))
		if _, err := conn.Write(searchBER(0x30, searchBER(2, id), entry)); err != nil {
			return err
		}
		resultCode := byte(0)
		if round == rounds-1 {
			resultCode = code
		}
		if _, err := conn.Write(searchBER(0x30, searchBER(2, id), searchBER(0x65, []byte{10, 1, resultCode, 4, 0, 4, 0}))); err != nil {
			return err
		}
	}
	packet, err := readSearchBER(conn)
	if err != nil {
		return err
	}
	_, rest, err := takeSearchBER(packet, 2)
	if err != nil || len(rest) == 0 || rest[0] != 0x42 {
		return errors.New("expected RODC read unbind")
	}
	return nil
}

func TestNativeRODCPasswordPolicyModifyWire(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, list := range []RODCPasswordReplicationList{RODCPasswordAllowed, RODCPasswordDenied} {
			for _, code := range []byte{0, 50} {
				t.Run(fmt.Sprintf("remove-%t-list-%d-code-%d", remove, list, code), func(t *testing.T) {
					f := newRODCPolicyFixture(t)
					attribute, _ := list.attribute()
					operation := byte(0)
					if remove {
						operation = 1
					}
					values := searchBER(0x31, searchBER(4, []byte(membershipObjectKey(f.account))), searchBER(4, []byte(membershipObjectKey(f.group))))
					modification := searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte(attribute)), values))
					want := append(searchBER(4, []byte(membershipObjectKey(f.controller))), searchBER(0x30, modification)...)
					fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, code)
					var owners searchNativeCounts
					wireClient := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
					native := wireClient.session.(*ldapSession)
					f.session.write = func(request ldapWriteRequest) ldapWriteAttempt {
						f.writes++
						return native.ldapWrite(context.Background(), request)
					}
					f.session.finish = native.close
					request := RODCPasswordReplicationChange{Controller: f.controllerIdentity(t), List: list, Principals: []Identity{groupMemberDN(t, f.account.DistinguishedName), groupMemberDN(t, f.group.DistinguishedName)}, Mode: GroupMembershipStrict}
					var result RODCPasswordReplicationMutationResult
					var err error
					if remove {
						result, err = f.client.RemoveRODCPasswordReplicationPolicy(context.Background(), request)
					} else {
						result, err = f.client.AddRODCPasswordReplicationPolicy(context.Background(), request)
					}
					if f.writes != 1 || result.Mutation.Verified {
						t.Fatal(result, err)
					}
					if code == 0 {
						if err != nil || result.Mutation.State != ObjectWriteAccepted {
							t.Fatal(result, err)
						}
					} else if !hasLDAPCode(err, 50) || result.Mutation.State != ObjectWriteRejected {
						t.Fatal(result, err)
					}
					if err := f.client.Close(); err != nil {
						t.Fatal(err)
					}
					if owners != (searchNativeCounts{}) {
						t.Fatal(owners)
					}
				})
			}
		}
	}
}
