//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type fgppWireSession struct {
	*fgppTestSession
	native *ldapSession
	calls  int
}

func (s *fgppWireSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	s.calls++
	attempt := s.native.ldapWrite(ctx, request)
	if attempt.State == ldapWriteAccepted {
		// The loopback peer acknowledges a fixed independent expected wire body.
		// This local fixture supplies only subsequent directory observations.
		if simulated := s.fgppTestSession.ldapWrite(ctx, request); simulated.Err != nil {
			return simulated
		}
	}
	return attempt
}

func TestNativeFineGrainedPolicyIntervalsAndSubjectLinksWire(t *testing.T) {
	mod := func(operation byte, attribute string, values ...string) []byte {
		var encoded [][]byte
		for _, value := range values {
			encoded = append(encoded, searchBER(4, []byte(value)))
		}
		return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte(attribute)), searchBER(0x31, encoded...)))
	}
	for _, operation := range []string{"settings", "add-subjects", "remove-subjects"} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("%s-code-%d", operation, code), func(t *testing.T) {
				var mods []byte
				if operation == "settings" {
					mods = searchBER(0x30, mod(2, "msDS-PasswordHistoryLength", "12"), mod(2, "msDS-MaximumPasswordAge", "-9223372036854775808"))
				} else {
					kind := byte(0)
					if operation == "remove-subjects" {
						kind = 1
					}
					mods = searchBER(0x30, mod(kind, "msDS-PSOAppliesTo", "<GUID=07000000000000000000000000000000>", "<GUID=08000000000000000000000000000000>"))
				}
				want := append(searchBER(4, []byte("<GUID=06000000000000000000000000000000>")), mods...)
				fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, code)
				var owners searchNativeCounts
				wireClient := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
				client, observations := newFGPPTestClient(t)
				if operation == "remove-subjects" {
					object := observations.objects["cn=policy,cn=password settings container,cn=system,dc=example"]
					object.Attributes["msds-psoappliesto"] = [][]byte{[]byte("CN=user,DC=example"), []byte("CN=group,DC=example")}
				}
				session := &fgppWireSession{fgppTestSession: observations, native: wireClient.session.(*ldapSession)}
				client.session = session
				var mutation ObjectMutationResult
				var err error
				if operation == "settings" {
					result, e := client.UpdateFineGrainedPasswordPolicy(context.Background(), UpdateFineGrainedPasswordPolicyRequest{Identity: fgppTestIdentity(), Settings: FineGrainedPasswordPolicySettings{PasswordHistoryCount: fgppPointer(uint16(12)), MaxPasswordAge: fgppPointer(PolicyNever)}})
					mutation, err = result.Mutation, e
				} else {
					user, _ := IdentityByDN("CN=user,DC=example")
					group, _ := IdentityByDN("CN=group,DC=example")
					request := FineGrainedPolicySubjectsRequest{Identity: fgppTestIdentity(), Subjects: []Identity{user, group}}
					var result FineGrainedPolicySubjectsMutationResult
					if operation == "add-subjects" {
						result, err = client.AddFineGrainedPasswordPolicySubjects(context.Background(), request)
					} else {
						result, err = client.RemoveFineGrainedPasswordPolicySubjects(context.Background(), request)
					}
					mutation = result.Mutation
				}
				if session.calls != 1 {
					t.Fatal("request replay", session.calls)
				}
				if code == 0 {
					if err != nil || mutation.State != ObjectWriteAccepted || !mutation.Verified {
						t.Fatal(mutation, err)
					}
				} else {
					var nativeErr *LDAPError
					if !errors.As(err, &nativeErr) || nativeErr.Code != 50 || nativeErr.Diagnostic != "private wire diagnostic" || mutation.State != ObjectWriteRejected || len(observations.writes) != 0 {
						t.Fatal(mutation, err)
					}
				}
				if err := wireClient.Close(); err != nil {
					t.Fatal(err)
				}
				if owners != (searchNativeCounts{}) {
					t.Fatal("native owners leaked", owners)
				}
			})
		}
	}
}
