//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func authWireAttribute(name string, values ...[]byte) []byte {
	var encoded [][]byte
	for _, value := range values {
		encoded = append(encoded, searchBER(4, value))
	}
	return searchBER(0x30, searchBER(4, []byte(name)), searchBER(0x31, encoded...))
}

func TestNativeAuthenticationPolicyPublicWireAndOwnership(t *testing.T) {
	sddl, err := conditions.Compile(conditions.ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: conditions.MemberOf(true, "S-1-5-32-544")})
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
				f := newAuthenticationPolicyFixture()
				guid, _ := GUIDFromBytes(f.objects[authTestPolicy].Attributes["objectguid"][0])
				dn := objectGUIDTarget(guid)
				tag, response := byte(0x66), byte(0x67)
				var body []byte
				switch operation {
				case "create":
					tag, response = 0x68, 0x69
					dn = `cn=Cymru\, 李,` + authTestContainer
					body = append(searchBER(4, []byte(dn)), searchBER(0x30, authWireAttribute("msDS-AuthNPolicyEnforced", []byte("FALSE")), authWireAttribute("msDS-UserTGTLifetime", []byte("600000001")), authWireAttribute("objectClass", []byte("msDS-AuthNPolicy")), authWireAttribute("cn", []byte("Cymru, 李")))...)
				case "delete":
					tag, response, body = 0x4a, 0x6b, []byte(dn)
				case "descriptor":
					body = append(searchBER(4, []byte(dn)), searchBER(0x30, searchBER(0x30, []byte{10, 1, 2}, authWireAttribute("msDS-UserAllowedToAuthenticateFrom", descriptor)))...)
				default:
					guid, _ = GUIDFromBytes(f.objects[authTestAccount].Attributes["objectguid"][0])
					dn = objectGUIDTarget(guid)
					op := byte(2)
					attribute := authWireAttribute("msDS-AssignedAuthNPolicy", []byte(authTestPolicy))
					if operation == "clear" {
						op = 1
						attribute = authWireAttribute("msDS-AssignedAuthNPolicy")
					}
					body = append(searchBER(4, []byte(dn)), searchBER(0x30, searchBER(0x30, []byte{10, 1, op}, attribute))...)
				}
				wire := newWriteWireFixture(t, tag, response, body, nil, code)
				var counts searchNativeCounts
				native := searchWireClient(t, &searchWireFixture{listener: wire.listener}, countedSearchAPI(&counts))
				f.write = func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
					return native.session.(*ldapSession).ldapWrite(ctx, request)
				}
				client := f.client(t)
				var result ObjectMutationResult
				var writeErr error
				switch operation {
				case "create":
					lifetime := Interval100ns(600000001)
					changed, err := client.CreateAuthenticationPolicy(context.Background(), CreateAuthenticationPolicyRequest{Name: "Cymru, 李", Properties: AuthenticationPolicyProperties{UserTGTLifetime: &lifetime}})
					result, writeErr = changed.Mutation, err
				case "descriptor":
					changed, err := client.UpdateAuthenticationPolicy(context.Background(), UpdateAuthenticationPolicyRequest{Identity: authTestIdentity(authTestPolicy), Properties: AuthenticationPolicyProperties{UserAllowedToAuthenticateFrom: &sddl}})
					result, writeErr = changed.Mutation, err
				case "delete":
					result, writeErr = client.DeleteAuthenticationPolicy(context.Background(), DeleteAuthenticationPolicyRequest{Identity: authTestIdentity(authTestPolicy)})
				default:
					request := SetAccountAuthenticationPolicyRequest{Identity: authTestIdentity(authTestAccount), Clear: operation == "clear"}
					if !request.Clear {
						policy := authTestIdentity(authTestPolicy)
						request.Policy = &policy
					}
					changed, err := client.SetAccountAuthenticationPolicy(context.Background(), request)
					result, writeErr = changed.Mutation, err
				}
				if code == 0 {
					if operation == "clear" {
						if !errors.Is(writeErr, ErrObjectVerification) || result.Verified {
							t.Fatal(result, writeErr)
						}
					} else if writeErr != nil || !result.Verified {
						t.Fatal(result, writeErr)
					}
					if result.State != ObjectWriteAccepted {
						t.Fatal(result)
					}
				} else {
					var ldapErr *LDAPError
					if result.State != ObjectWriteRejected || !errors.As(writeErr, &ldapErr) || ldapErr.Code != uint32(code) || ldapErr.Diagnostic != "private wire diagnostic" || !errors.Is(writeErr, ErrObjectWritePermission) {
						t.Fatal(result, writeErr)
					}
				}
				if len(f.writes) != 1 {
					t.Fatal("replayed write", f.writes)
				}
				if err := native.Close(); err != nil {
					t.Fatal(err)
				}
				if counts != (searchNativeCounts{}) {
					t.Fatal("native ownership leak", counts)
				}
			})
		}
	}
}

func TestNativeAuthenticationPolicyDescriptorSemantics(t *testing.T) {
	for _, sddl := range []string{`D:(XA;;CR;;;WD;(@User.Name === "x"))`, `D:(A;;RC;;;WD)`, `D:NO_ACCESS_CONTROL`, `O:SYG:SY`} {
		f := newAuthenticationPolicyFixture()
		_, err := f.client(t).UpdateAuthenticationPolicy(context.Background(), UpdateAuthenticationPolicyRequest{Identity: authTestIdentity(authTestPolicy), Properties: AuthenticationPolicyProperties{UserAllowedToAuthenticateTo: &sddl}})
		if !errors.Is(err, ErrAuthenticationPolicyDescriptor) || len(f.writes) != 0 {
			t.Fatal(sddl, err, f.writes)
		}
	}
	for _, sddl := range []string{`O:SYG:SYD:(D;;CR;;;AN)(XA;;CR;;;WD;(@Device.Department == "Finance"))`, `D:`} {
		f := newAuthenticationPolicyFixture()
		result, err := f.client(t).UpdateAuthenticationPolicy(context.Background(), UpdateAuthenticationPolicyRequest{Identity: authTestIdentity(authTestPolicy), Properties: AuthenticationPolicyProperties{ServiceAllowedToAuthenticateFrom: &sddl}})
		if err != nil || !result.Mutation.Verified || result.Policy.ServiceAllowedToAuthenticateFrom == nil {
			t.Fatal(result, err)
		}
	}
}
