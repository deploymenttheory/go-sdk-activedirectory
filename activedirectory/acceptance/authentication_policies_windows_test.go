//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_authentication_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func InternalAuthWireAttribute(name string, values ...[]byte) []byte {
	var encoded [][]byte
	for _, value := range values {
		encoded = append(encoded, InternalSearchBER(4, value))
	}
	return InternalSearchBER(
		0x30,
		InternalSearchBER(4, []byte(name)),
		InternalSearchBER(0x31, encoded...),
	)
}

func TestNativeAuthenticationPolicyPublicWireAndOwnership(t *testing.T) {
	sddl, err := conditions.Compile(
		conditions.ACE{
			TrusteeSID: "S-1-1-0",
			AccessMask: 0x100,
			Condition:  conditions.MemberOf(true, "S-1-5-32-544"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := conditions.DescriptorBytes(sddl)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"create", "descriptor", "delete", "assign", "clear"} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("%s-code%d", operation, code), func(t *testing.T) {
				f := InternalNewAuthenticationPolicyFixture()
				guid, _ := admodel.GUIDFromBytes(
					f.InternalObjects[InternalAuthTestPolicy].Attributes["objectguid"][0],
				)
				dn := admodel.InternalObjectGUIDTarget(guid)
				tag, response := byte(0x66), byte(0x67)
				var body []byte
				switch operation {
				case "create":
					tag, response = 0x68, 0x69
					dn = `cn=Cymru\, 李,` + InternalAuthTestContainer
					body = append(
						InternalSearchBER(4, []byte(dn)),
						InternalSearchBER(
							0x30,
							InternalAuthWireAttribute("msDS-AuthNPolicyEnforced", []byte("FALSE")),
							InternalAuthWireAttribute("msDS-UserTGTLifetime", []byte("600000001")),
							InternalAuthWireAttribute("objectClass", []byte("msDS-AuthNPolicy")),
							InternalAuthWireAttribute("cn", []byte("Cymru, 李")),
						)...)
				case "delete":
					tag, response, body = 0x4a, 0x6b, []byte(dn)
				case "descriptor":
					body = append(
						InternalSearchBER(4, []byte(dn)),
						InternalSearchBER(
							0x30,
							InternalSearchBER(
								0x30,
								[]byte{10, 1, 2},
								InternalAuthWireAttribute(
									"msDS-UserAllowedToAuthenticateFrom",
									descriptor,
								),
							),
						)...)
				default:
					guid, _ = admodel.GUIDFromBytes(
						f.InternalObjects[InternalAuthTestAccount].Attributes["objectguid"][0],
					)
					dn = admodel.InternalObjectGUIDTarget(guid)
					op := byte(2)
					attribute := InternalAuthWireAttribute(
						"msDS-AssignedAuthNPolicy",
						[]byte(InternalAuthTestPolicy),
					)
					if operation == "clear" {
						op = 1
						attribute = InternalAuthWireAttribute("msDS-AssignedAuthNPolicy")
					}
					body = append(
						InternalSearchBER(4, []byte(dn)),
						InternalSearchBER(
							0x30,
							InternalSearchBER(0x30, []byte{10, 1, op}, attribute),
						)...)
				}
				wire := InternalNewWriteWireFixture(t, tag, response, body, nil, code)
				var counts InternalSearchNativeCounts
				native := InternalSearchWireClient(
					t,
					&InternalSearchWireFixture{InternalListener: wire.InternalListener},
					InternalCountedSearchAPI(&counts),
				)
				f.InternalWrite = func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					return adengine.InternalClientSession(native).(*adengine.InternalLdapSession).InternalLdapWrite(
						ctx,
						request,
					)
				}
				client := f.InternalClient(t)
				var result admodel.ObjectMutationResult
				var writeErr error
				switch operation {
				case "create":
					lifetime := admodel.Interval100ns(600000001)
					changed, err := adservice_authentication_policies.New(client).
						CreateAuthenticationPolicy(context.Background(), admodel.CreateAuthenticationPolicyRequest{Name: "Cymru, 李", Properties: admodel.AuthenticationPolicyProperties{UserTGTLifetime: &lifetime}})
					result, writeErr = changed.Mutation, err
				case "descriptor":
					changed, err := adservice_authentication_policies.New(client).
						UpdateAuthenticationPolicy(context.Background(), admodel.UpdateAuthenticationPolicyRequest{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy), Properties: admodel.AuthenticationPolicyProperties{UserAllowedToAuthenticateFrom: &sddl}})
					result, writeErr = changed.Mutation, err
				case "delete":
					result, writeErr = adservice_authentication_policies.New(client).
						DeleteAuthenticationPolicy(context.Background(), admodel.DeleteAuthenticationPolicyRequest{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy)})
				default:
					request := admodel.SetAccountAuthenticationPolicyRequest{
						Identity: InternalAuthTestIdentity(InternalAuthTestAccount),
						Clear:    operation == "clear",
					}
					if !request.Clear {
						policy := InternalAuthTestIdentity(InternalAuthTestPolicy)
						request.Policy = &policy
					}
					changed, err := adservice_authentication_policies.New(client).
						SetAccountAuthenticationPolicy(context.Background(), request)
					result, writeErr = changed.Mutation, err
				}
				if code == 0 {
					if operation == "clear" || operation == "delete" {
						if !errors.Is(writeErr, admodel.ErrObjectUnverifiable) || result.Verified {
							t.Fatal(result, writeErr)
						}
					} else if writeErr != nil || !result.Verified {
						t.Fatal(result, writeErr)
					}
					if result.State != admodel.ObjectWriteAccepted {
						t.Fatal(result)
					}
				} else {
					var ldapErr *admodel.LDAPError
					if result.State != admodel.ObjectWriteRejected ||
						!errors.As(writeErr, &ldapErr) ||
						ldapErr.Code != uint32(code) ||
						ldapErr.Diagnostic != "private wire diagnostic" ||
						!errors.Is(writeErr, admodel.ErrObjectWritePermission) {
						t.Fatal(result, writeErr)
					}
				}
				if len(f.InternalWrites) != 1 {
					t.Fatal("replayed write", f.InternalWrites)
				}
				if err := native.Close(); err != nil {
					t.Fatal(err)
				}
				if counts != (InternalSearchNativeCounts{}) {
					t.Fatal("native ownership leak", counts)
				}
			})
		}
	}
}

func TestNativeAuthenticationPolicyDescriptorSemantics(t *testing.T) {
	for _, sddl := range []string{`D:(XA;;CR;;;WD;(@User.Name === "x"))`, `D:(A;;RC;;;WD)`, `D:NO_ACCESS_CONTROL`, `O:SYG:SY`} {
		f := InternalNewAuthenticationPolicyFixture()
		_, err := adservice_authentication_policies.New(f.InternalClient(t)).
			UpdateAuthenticationPolicy(context.Background(), admodel.UpdateAuthenticationPolicyRequest{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy), Properties: admodel.AuthenticationPolicyProperties{UserAllowedToAuthenticateTo: &sddl}})
		if !errors.Is(err, admodel.ErrAuthenticationPolicyDescriptor) ||
			len(f.InternalWrites) != 0 {
			t.Fatal(sddl, err, f.InternalWrites)
		}
	}
	for _, sddl := range []string{`O:SYG:SYD:(D;;CR;;;AN)(XA;;CR;;;WD;(@Device.Department == "Finance"))`, `D:`} {
		f := InternalNewAuthenticationPolicyFixture()
		result, err := adservice_authentication_policies.New(f.InternalClient(t)).
			UpdateAuthenticationPolicy(context.Background(), admodel.UpdateAuthenticationPolicyRequest{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy), Properties: admodel.AuthenticationPolicyProperties{ServiceAllowedToAuthenticateFrom: &sddl}})
		if err != nil || !result.Mutation.Verified ||
			result.Policy.ServiceAllowedToAuthenticateFrom == nil {
			t.Fatal(result, err)
		}
	}
}
