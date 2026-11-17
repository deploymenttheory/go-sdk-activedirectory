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
	adservice_authentication_silos "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_silos"
)

func InternalSiloWireModification(operation byte, name string, values ...[]byte) []byte {
	return InternalSearchBER(
		0x30,
		[]byte{10, 1, operation},
		InternalAuthWireAttribute(name, values...),
	)
}

func TestNativeAuthenticationSiloPublicWireAndOwnership(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete", "grant", "revoke", "assign", "clear"} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("%s-%d", operation, code), func(t *testing.T) {
				f := InternalNewAuthenticationSiloFixture()
				f.InternalObjects[InternalSiloTestDN].Attributes[strings.ToLower(admodel.InternalSiloMembersAttribute)] = [][]byte{
					[]byte("CN=Other,DC=example"),
				}
				if operation == "revoke" {
					f.InternalObjects[InternalSiloTestDN].Attributes[strings.ToLower(admodel.InternalSiloMembersAttribute)] = append(
						f.InternalObjects[InternalSiloTestDN].Attributes[strings.ToLower(admodel.InternalSiloMembersAttribute)],
						[]byte(InternalAuthTestAccount),
					)
				}
				guid, _ := admodel.GUIDFromBytes(
					f.InternalObjects[InternalSiloTestDN].Attributes["objectguid"][0],
				)
				dn := admodel.InternalObjectGUIDTarget(guid)
				tag, response := byte(0x66), byte(0x67)
				var body []byte
				switch operation {
				case "create":
					tag, response = 0x68, 0x69
					dn = `cn=李\, Silo,` + InternalSiloTestContainer
					body = append(
						InternalSearchBER(4, []byte(dn)),
						InternalSearchBER(
							0x30,
							InternalAuthWireAttribute(
								"msDS-AuthNPolicySiloEnforced",
								[]byte("FALSE"),
							),
							InternalAuthWireAttribute(
								"objectClass",
								[]byte("msDS-AuthNPolicySilo"),
							),
							InternalAuthWireAttribute("cn", []byte("李, Silo")),
						)...)
				case "delete":
					tag, response, body = 0x4a, 0x6b, []byte(dn)
				case "update":
					body = append(
						InternalSearchBER(4, []byte(dn)),
						InternalSearchBER(
							0x30,
							InternalSiloWireModification(
								2,
								"msDS-AuthNPolicySiloEnforced",
								[]byte("TRUE"),
							),
							InternalSiloWireModification(
								2,
								"msDS-UserAuthNPolicy",
								[]byte(InternalAuthTestPolicy),
							),
						)...)
				case "grant", "revoke":
					op := byte(0)
					if operation == "revoke" {
						op = 1
					}
					body = append(
						InternalSearchBER(4, []byte(dn)),
						InternalSearchBER(
							0x30,
							InternalSiloWireModification(
								op,
								admodel.InternalSiloMembersAttribute,
								[]byte(InternalAuthTestAccount),
							),
						)...)
				default:
					guid, _ = admodel.GUIDFromBytes(
						f.InternalObjects[InternalAuthTestAccount].Attributes["objectguid"][0],
					)
					dn = admodel.InternalObjectGUIDTarget(guid)
					if operation == "assign" {
						body = append(
							InternalSearchBER(4, []byte(dn)),
							InternalSearchBER(
								0x30,
								InternalSiloWireModification(
									2,
									"msDS-AssignedAuthNPolicySilo",
									[]byte(InternalSiloTestDN),
								),
								InternalSiloWireModification(
									2,
									"msDS-AssignedAuthNPolicy",
									[]byte(InternalAuthTestPolicy),
								),
							)...)
					} else {
						body = append(
							InternalSearchBER(4, []byte(dn)),
							InternalSearchBER(
								0x30,
								InternalSiloWireModification(1, "msDS-AssignedAuthNPolicySilo"),
								InternalSiloWireModification(1, "msDS-AssignedAuthNPolicy"),
							)...)
					}
				}
				wire := InternalNewWriteWireFixture(t, tag, response, body, nil, code)
				var owners InternalSearchNativeCounts
				native := InternalSearchWireClient(
					t,
					&InternalSearchWireFixture{InternalListener: wire.InternalListener},
					InternalCountedSearchAPI(&owners),
				)
				f.InternalWrite = func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					return adengine.InternalClientSession(native).(*adengine.InternalLdapSession).InternalLdapWrite(
						ctx,
						request,
					)
				}
				client := f.InternalClient(t)
				silo, policy := InternalAuthTestIdentity(
					InternalSiloTestDN,
				), InternalAuthTestIdentity(
					InternalAuthTestPolicy,
				)
				var result admodel.ObjectMutationResult
				var err error
				switch operation {
				case "create":
					created, e := adservice_authentication_silos.New(client).
						CreateAuthenticationPolicySilo(context.Background(), admodel.CreateAuthenticationPolicySiloRequest{Name: "李, Silo"})
					result, err = created.Mutation, e
				case "update":
					value := true
					updated, e := adservice_authentication_silos.New(client).
						UpdateAuthenticationPolicySilo(context.Background(), admodel.UpdateAuthenticationPolicySiloRequest{Identity: silo, Properties: admodel.AuthenticationPolicySiloProperties{Enforced: &value, UserAuthenticationPolicy: &policy}})
					result, err = updated.Mutation, e
				case "delete":
					result, err = adservice_authentication_silos.New(client).
						DeleteAuthenticationPolicySilo(context.Background(), admodel.DeleteAuthenticationPolicySiloRequest{Identity: silo})
				case "grant", "revoke":
					changed, e := adservice_authentication_silos.InternalServiceChangeAuthenticationSiloAccess(
						adservice_authentication_silos.New(client),
						context.Background(),
						admodel.AuthenticationPolicySiloAccessRequest{
							Identity: silo,
							Account:  InternalAuthTestIdentity(InternalAuthTestAccount),
						},
						operation == "grant",
					)
					result, err = changed.Mutation, e
				default:
					request := admodel.SetAccountAuthenticationPolicySiloRequest{
						Identity: InternalAuthTestIdentity(InternalAuthTestAccount),
						Silo:     &silo,
						Policy:   &policy,
					}
					if operation == "clear" {
						request.Silo, request.Policy = nil, nil
						request.ClearSilo, request.ClearPolicy = true, true
					}
					changed, e := adservice_authentication_silos.New(client).
						SetAccountAuthenticationPolicySilo(context.Background(), request)
					result, err = changed.Mutation, e
				}
				if code == 0 {
					if result.State != admodel.ObjectWriteAccepted {
						t.Fatal(result, err)
					}
					if operation == "clear" {
						if !errors.Is(err, admodel.ErrObjectVerification) || result.Verified {
							t.Fatal(result, err)
						}
					} else if err != nil || !result.Verified {
						t.Fatal(result, err)
					}
				} else {
					var nativeErr *admodel.LDAPError
					if result.State != admodel.ObjectWriteRejected || !errors.As(err, &nativeErr) ||
						nativeErr.Code != 50 ||
						nativeErr.Diagnostic != "private wire diagnostic" {
						t.Fatal(result, err)
					}
				}
				if len(f.InternalWrites) != 1 {
					t.Fatal("replayed", f.InternalWrites)
				}
				if err := native.Close(); err != nil {
					t.Fatal(err)
				}
				if owners != (InternalSearchNativeCounts{}) {
					t.Fatal(owners)
				}
			})
		}
	}
}

func TestNativeAuthenticationSiloLinkedRangesAndPartialReply(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			f := InternalNewAuthenticationSiloFixture()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() { done <- InternalServeSiloRanges(listener, f.InternalObjects[InternalSiloTestDN], denied) }()
			var owners InternalSearchNativeCounts
			native := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: listener},
				InternalCountedSearchAPI(&owners),
			)
			f.InternalRangeRead = adengine.InternalClientSession(native).(*adengine.InternalLdapSession).InternalRangedBaseObject
			result, err := adservice_authentication_silos.New(f.InternalClient(t)).
				AuthenticationPolicySilo(context.Background(), InternalAuthTestIdentity(InternalSiloTestDN), admodel.AuthenticationPolicySiloReadOptions{})
			if len(result.Members.DistinguishedNames) != 2 ||
				len(result.Members.Observations) != 2 {
				t.Fatal(result, err)
			}
			if denied {
				var nativeErr *admodel.LDAPError
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
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal(owners)
			}
		})
	}
}

func InternalServeSiloRanges(listener net.Listener, object admodel.Object, denied bool) error {
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
	guid, _ := admodel.GUIDFromBytes(object.Attributes["objectguid"][0])
	for round := 0; round < count; round++ {
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
		if err != nil || string(base) != admodel.InternalObjectGUIDTarget(guid) {
			return errors.New("wrong silo GUID base")
		}
		scope, _, err := InternalTakeSearchBER(remainder, 10)
		if err != nil || !bytes.Equal(scope, []byte{0}) || len(controls) != 0 {
			return errors.New("silo range requires plain BASE search")
		}
		wanted := fmt.Sprintf("%s;range=%d-*", admodel.InternalSiloMembersAttribute, round)
		if round == 2 {
			wanted = admodel.InternalSiloAssignedAttribute + ";range=0-*"
		}
		if !bytes.Contains(request, []byte(wanted)) {
			return errors.New("wrong silo range request")
		}
		attrs := [][]byte{
			InternalAuthWireAttribute("objectGUID", object.Attributes["objectguid"][0]),
			InternalAuthWireAttribute("uSNChanged", []byte("1")),
		}
		if round < 2 {
			name := admodel.InternalSiloMembersAttribute + ";range=0-0"
			if round == 1 {
				name = admodel.InternalSiloMembersAttribute + ";range=1-*"
			}
			attrs = append(
				attrs,
				InternalAuthWireAttribute(
					name,
					[]byte(fmt.Sprintf("CN=Account%d,DC=example", round)),
				),
			)
		}
		entry := InternalSearchBER(
			0x64,
			InternalSearchBER(4, []byte(object.DistinguishedName)),
			InternalSearchBER(0x30, attrs...),
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
		return errors.New("expected silo unbind")
	}
	return nil
}
