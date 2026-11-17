//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_password_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/password_policies"
)

type InternalFgppWireSession struct {
	*InternalFgppTestSession
	InternalNative *adengine.InternalLdapSession
	InternalCalls  int
}

func (s *InternalFgppWireSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	s.InternalCalls++
	attempt := s.InternalNative.InternalLdapWrite(ctx, request)
	if attempt.State == admodel.InternalLdapWriteAccepted {
		// The loopback peer acknowledges a fixed independent expected wire body.
		// This local fixture supplies only subsequent directory observations.
		if simulated := s.InternalFgppTestSession.InternalLdapWrite(
			ctx,
			request,
		); simulated.Err != nil {
			return simulated
		}
	}
	return attempt
}

func TestNativeFineGrainedPolicyIntervalsAndSubjectLinksWire(t *testing.T) {
	mod := func(operation byte, attribute string, values ...string) []byte {
		var encoded [][]byte
		for _, value := range values {
			encoded = append(encoded, InternalSearchBER(4, []byte(value)))
		}
		return InternalSearchBER(
			0x30,
			[]byte{10, 1, operation},
			InternalSearchBER(
				0x30,
				InternalSearchBER(4, []byte(attribute)),
				InternalSearchBER(0x31, encoded...),
			),
		)
	}
	for _, operation := range []string{"settings", "add-subjects", "remove-subjects"} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("%s-code-%d", operation, code), func(t *testing.T) {
				var mods []byte
				if operation == "settings" {
					mods = InternalSearchBER(
						0x30,
						mod(2, "msDS-PasswordHistoryLength", "12"),
						mod(2, "msDS-MaximumPasswordAge", "-9223372036854775808"),
					)
				} else {
					kind := byte(0)
					if operation == "remove-subjects" {
						kind = 1
					}
					mods = InternalSearchBER(
						0x30,
						mod(
							kind,
							"msDS-PSOAppliesTo",
							"<GUID=07000000000000000000000000000000>",
							"<GUID=08000000000000000000000000000000>",
						),
					)
				}
				want := append(
					InternalSearchBER(4, []byte("<GUID=06000000000000000000000000000000>")),
					mods...)
				fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, nil, code)
				var owners InternalSearchNativeCounts
				wireClient := InternalSearchWireClient(
					t,
					&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
					InternalCountedSearchAPI(&owners),
				)
				client, observations := InternalNewFGPPTestClient(t)
				if operation == "remove-subjects" {
					object := observations.InternalObjects["cn=policy,cn=password settings container,cn=system,dc=example"]
					object.Attributes["msds-psoappliesto"] = [][]byte{
						[]byte("CN=user,DC=example"),
						[]byte("CN=group,DC=example"),
					}
				}
				session := &InternalFgppWireSession{
					InternalFgppTestSession: observations,
					InternalNative:          (*adengine.InternalClientSessionPointer(wireClient)).(*adengine.InternalLdapSession),
				}
				(*adengine.InternalClientSessionPointer(client)) = session
				var mutation admodel.ObjectMutationResult
				var err error
				if operation == "settings" {
					result, e := adservice_password_policies.New(client).
						UpdateFineGrainedPasswordPolicy(context.Background(), admodel.UpdateFineGrainedPasswordPolicyRequest{Identity: InternalFgppTestIdentity(), Settings: admodel.FineGrainedPasswordPolicySettings{PasswordHistoryCount: InternalFgppPointer(uint16(12)), MaxPasswordAge: InternalFgppPointer(admodel.PolicyNever)}})
					mutation, err = result.Mutation, e
				} else {
					user, _ := admodel.IdentityByDN("CN=user,DC=example")
					group, _ := admodel.IdentityByDN("CN=group,DC=example")
					request := admodel.FineGrainedPolicySubjectsRequest{
						Identity: InternalFgppTestIdentity(),
						Subjects: []admodel.Identity{user, group},
					}
					var result admodel.FineGrainedPolicySubjectsMutationResult
					if operation == "add-subjects" {
						result, err = adservice_password_policies.New(client).
							AddFineGrainedPasswordPolicySubjects(context.Background(), request)
					} else {
						result, err = adservice_password_policies.New(client).
							RemoveFineGrainedPasswordPolicySubjects(context.Background(), request)
					}
					mutation = result.Mutation
				}
				if session.InternalCalls != 1 {
					t.Fatal("request replay", session.InternalCalls)
				}
				if code == 0 {
					if err != nil || mutation.State != admodel.ObjectWriteAccepted ||
						!mutation.Verified {
						t.Fatal(mutation, err)
					}
				} else {
					var nativeErr *admodel.LDAPError
					if !errors.As(err, &nativeErr) || nativeErr.Code != 50 ||
						nativeErr.Diagnostic != "private wire diagnostic" ||
						mutation.State != admodel.ObjectWriteRejected ||
						len(observations.InternalWrites) != 0 {
						t.Fatal(mutation, err)
					}
				}
				if err := wireClient.Close(); err != nil {
					t.Fatal(err)
				}
				if owners != (InternalSearchNativeCounts{}) {
					t.Fatal("native owners leaked", owners)
				}
			})
		}
	}
}
