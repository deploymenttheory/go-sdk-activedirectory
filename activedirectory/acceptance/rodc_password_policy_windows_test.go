//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

func TestNativeRODCResultantPolicyAndRevealedRanges(t *testing.T) {
	for _, ranges := range []bool{false, true} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("ranges-%t-code-%d", ranges, code), func(t *testing.T) {
				f := InternalNewRODCPolicyFixture(t)
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() {
					done <- InternalServeRODCReadWire(listener, f.InternalController, f.InternalAccount, ranges, code)
				}()
				var owners InternalSearchNativeCounts
				wireClient := InternalSearchWireClient(
					t,
					&InternalSearchWireFixture{InternalListener: listener},
					InternalCountedSearchAPI(&owners),
				)
				native := adengine.InternalClientSession(wireClient).(*adengine.InternalLdapSession)
				f.InternalSession.InternalPolicy = native.InternalObjectSyncPasswordPolicy
				f.InternalSession.InternalMemberRead = native.InternalGroupMemberBaseObject
				f.InternalSession.InternalFinish = native.InternalClose
				if ranges {
					result, err := adservice_memberships.New(f.InternalClient).
						RODCPasswordReplicationPolicyUsage(context.Background(), f.InternalControllerIdentity(t), admodel.RODCPasswordRevealed, admodel.RODCPasswordReplicationOptions{})
					if len(result.Entries) != 2 || len(result.Ranges) != 2 ||
						result.Entries[0].SecretAttribute != "unicodePwd" {
						t.Fatal(result, err)
					}
					if code == 0 {
						if err != nil || !result.Complete || len(result.Principals) != 1 {
							t.Fatal(result, err)
						}
					} else if !InternalHasLDAPCode(err, 50) || result.Complete {
						t.Fatal(result, err)
					}
				} else {
					result, err := adservice_memberships.New(f.InternalClient).
						AccountResultantPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName), admodel.RODCPasswordReplicationOptions{})
					if result.Policy == nil ||
						*result.Policy != admodel.RODCPasswordPolicyDenyExplicit {
						t.Fatal(result, err)
					}
					if code == 0 {
						if err != nil || !result.Complete {
							t.Fatal(result, err)
						}
					} else if !InternalHasLDAPCode(err, 50) || result.Complete {
						t.Fatal(result, err)
					}
				}
				if err := f.InternalClient.Close(); err != nil {
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
				if owners != (InternalSearchNativeCounts{}) {
					t.Fatal("native ownership leak", owners)
				}
			})
		}
	}
}

func InternalServeRODCReadWire(
	listener net.Listener,
	controller, account admodel.Object,
	ranges bool,
	code byte,
) error {
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
		if err != nil || string(base) != InternalMembershipObjectKey(controller) {
			return errors.New("wrong RODC GUID target")
		}
		scope, _, err := InternalTakeSearchBER(remainder, 10)
		if err != nil || !bytes.Equal(scope, []byte{0}) {
			return errors.New("RODC read must use BASE scope")
		}
		var attributes []byte
		if ranges {
			if len(controls) != 0 ||
				!bytes.Contains(
					request,
					[]byte(fmt.Sprintf("msDS-RevealedList;range=%d-%d", round, round+1499)),
				) {
				return errors.New("wrong revealed range request")
			}
			name := "msDS-RevealedList;range=0-0"
			value := "S:10:unicodePwd:" + account.DistinguishedName
			if round == 1 {
				name = "msDS-RevealedList;range=1-*"
				value = "S:23:supplementalCredentials:" + account.DistinguishedName
			}
			attributes = append(attributes, InternalSearchWireAttribute(name, []byte(value))...)
			attributes = append(
				attributes,
				InternalSearchWireAttribute(
					"objectGUID",
					controller.Attributes["objectguid"][0],
				)...)
			attributes = append(
				attributes,
				InternalSearchWireAttribute("uSNChanged", []byte("7"))...)
		} else {
			if !bytes.Contains(request, []byte("msDS-IsUserCachableAtRodc")) {
				return errors.New("wrong constructed policy attribute")
			}
			outer, rest, err := InternalTakeSearchBER(controls, 0xa0)
			if err != nil || len(rest) != 0 {
				return errors.New("missing DN-input control")
			}
			control, rest, err := InternalTakeSearchBER(outer, 0x30)
			if err != nil || len(rest) != 0 {
				return errors.New("unexpected control count")
			}
			oid, rest, err := InternalTakeSearchBER(control, 4)
			if err != nil || string(oid) != admodel.InternalObjectSyncDNInputOID {
				return errors.New("wrong DN-input OID")
			}
			critical, rest, err := InternalTakeSearchBER(rest, 1)
			if err != nil || len(critical) != 1 || critical[0] == 0 {
				return errors.New("DN-input must be critical")
			}
			value, rest, err := InternalTakeSearchBER(rest, 4)
			if err != nil || len(rest) != 0 {
				return errors.New("invalid DN-input payload")
			}
			var decoded struct{ InputDN []byte }
			rest, err = asn1.Unmarshal(value, &decoded)
			if err != nil || len(rest) != 0 ||
				string(decoded.InputDN) != InternalMembershipObjectKey(account) {
				return errors.New("wrong account GUID control value")
			}
			attributes = InternalSearchWireAttribute("msDS-IsUserCachableAtRodc", []byte("0"))
		}
		entry := InternalSearchBER(
			0x64,
			InternalSearchBER(4, []byte(controller.DistinguishedName)),
			InternalSearchBER(0x30, attributes),
		)
		if _, err := conn.Write(
			InternalSearchBER(0x30, InternalSearchBER(2, id), entry),
		); err != nil {
			return err
		}
		resultCode := byte(0)
		if round == rounds-1 {
			resultCode = code
		}
		if _, err := conn.Write(
			InternalSearchBER(
				0x30,
				InternalSearchBER(2, id),
				InternalSearchBER(0x65, []byte{10, 1, resultCode, 4, 0, 4, 0}),
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
		return errors.New("expected RODC read unbind")
	}
	return nil
}

func TestNativeRODCPasswordPolicyModifyWire(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, list := range []admodel.RODCPasswordReplicationList{admodel.RODCPasswordAllowed, admodel.RODCPasswordDenied} {
			for _, code := range []byte{0, 50} {
				t.Run(
					fmt.Sprintf("remove-%t-list-%d-code-%d", remove, list, code),
					func(t *testing.T) {
						f := InternalNewRODCPolicyFixture(t)
						attribute, _ := admodel.InternalRODCPasswordReplicationListAttribute(list)
						operation := byte(0)
						if remove {
							operation = 1
						}
						values := InternalSearchBER(
							0x31,
							InternalSearchBER(
								4,
								[]byte(InternalMembershipObjectKey(f.InternalAccount)),
							),
							InternalSearchBER(
								4,
								[]byte(InternalMembershipObjectKey(f.InternalGroup)),
							),
						)
						modification := InternalSearchBER(
							0x30,
							[]byte{10, 1, operation},
							InternalSearchBER(
								0x30,
								InternalSearchBER(4, []byte(attribute)),
								values,
							),
						)
						want := append(
							InternalSearchBER(
								4,
								[]byte(InternalMembershipObjectKey(f.InternalController)),
							),
							InternalSearchBER(0x30, modification)...)
						fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, nil, code)
						var owners InternalSearchNativeCounts
						wireClient := InternalSearchWireClient(
							t,
							&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
							InternalCountedSearchAPI(&owners),
						)
						native := adengine.InternalClientSession(wireClient).(*adengine.InternalLdapSession)
						f.InternalSession.InternalWrite = func(request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
							f.InternalWrites++
							return native.InternalLdapWrite(context.Background(), request)
						}
						f.InternalSession.InternalFinish = native.InternalClose
						request := admodel.RODCPasswordReplicationChange{
							Controller: f.InternalControllerIdentity(t),
							List:       list,
							Principals: []admodel.Identity{
								InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName),
								InternalGroupMemberDN(t, f.InternalGroup.DistinguishedName),
							},
							Mode: admodel.GroupMembershipStrict,
						}
						var result admodel.RODCPasswordReplicationMutationResult
						var err error
						if remove {
							result, err = adservice_memberships.New(f.InternalClient).
								RemoveRODCPasswordReplicationPolicy(context.Background(), request)
						} else {
							result, err = adservice_memberships.New(f.InternalClient).
								AddRODCPasswordReplicationPolicy(context.Background(), request)
						}
						if f.InternalWrites != 1 || result.Mutation.Verified {
							t.Fatal(result, err)
						}
						if code == 0 {
							if err != nil || result.Mutation.State != admodel.ObjectWriteAccepted {
								t.Fatal(result, err)
							}
						} else if !InternalHasLDAPCode(err, 50) || result.Mutation.State != admodel.ObjectWriteRejected {
							t.Fatal(result, err)
						}
						if err := f.InternalClient.Close(); err != nil {
							t.Fatal(err)
						}
						if owners != (InternalSearchNativeCounts{}) {
							t.Fatal(owners)
						}
					},
				)
			}
		}
	}
}
