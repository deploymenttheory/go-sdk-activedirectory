package acceptance

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

type InternalPasswordPermissionTestSession struct {
	*InternalOuTestSession
	InternalReadbackTransform func(admodel.Object) admodel.Object
	InternalDaclProperties    [][]string
}

func (s *InternalPasswordPermissionTestSession) InternalReadDirectoryDACL(
	ctx context.Context,
	dn string,
	extra []string,
) (admodel.Object, error) {
	object, err := s.InternalReadOUDACL(ctx, dn)
	properties := admodel.InternalDirectoryDACLProperties(extra)
	s.InternalDaclProperties = append(s.InternalDaclProperties, slices.Clone(properties))
	attrs := make(map[string][][]byte)
	for _, name := range properties {
		if values, ok := object.Attributes[strings.ToLower(name)]; ok {
			attrs[strings.ToLower(name)] = values
		}
	}
	object.Attributes = attrs
	object.RequestedProperties = properties
	if len(s.InternalWrites) > 0 && s.InternalReadbackTransform != nil {
		object = s.InternalReadbackTransform(object)
	}
	return object, err
}

func (*InternalPasswordPermissionTestSession) InternalEncodeDACL(
	_ []byte,
	aces [][]byte,
) ([]byte, error) {
	return InternalOuTestDescriptor(aces...), nil
}

func InternalNewPasswordPermissionClient(
	t *testing.T,
) (*adengine.Client, *InternalPasswordPermissionTestSession) {
	client, base := InternalNewOUTestClient(t)
	object := base.InternalObjects["ou=target,dc=example"]
	object.Attributes["objectclass"] = [][]byte{
		[]byte("top"),
		[]byte("person"),
		[]byte("user"),
		[]byte("computer"),
	}
	object.Attributes["useraccountcontrol"] = [][]byte{[]byte("4096")}
	session := &InternalPasswordPermissionTestSession{InternalOuTestSession: base}
	(*adengine.InternalClientSessionPointer(client)) = session
	return client, session
}

func TestPasswordPermissionRoundTripAndIdempotence(t *testing.T) {
	client, session := InternalNewPasswordPermissionClient(t)
	original := slices.Clone(
		session.InternalObjects["ou=target,dc=example"].Attributes["ntsecuritydescriptor"][0],
	)
	result, err := adservice_accounts.New(client).
		SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
	if err != nil || !result.Changed || !result.Mutation.Verified ||
		result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.After == nil ||
		result.After.CannotChangePassword == nil ||
		!*result.After.CannotChangePassword ||
		!result.After.Self.ExplicitDeny ||
		!result.After.Everyone.ExplicitDeny {
		t.Fatal(result, err)
	}
	result, err = adservice_accounts.New(client).
		SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
	if err != nil || result.Changed || !result.Mutation.Verified ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted ||
		len(session.InternalWrites) != 1 {
		t.Fatal(result, err)
	}
	result, err = adservice_accounts.New(client).
		SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), false, admodel.ObjectMutationOptions{})
	if err != nil || !result.Mutation.Verified || result.After.CannotChangePassword == nil ||
		*result.After.CannotChangePassword ||
		!result.After.Self.ExplicitAllow ||
		!result.After.Everyone.ExplicitAllow ||
		result.After.Self.ExplicitDeny ||
		result.After.Everyone.ExplicitDeny {
		t.Fatal(result, err)
	}
	originalACL, _ := admodel.InternalDecodeDirectoryDACL(original)
	afterACL, _ := admodel.InternalDecodeDirectoryDACL(
		result.After.Raw.Attributes["ntsecuritydescriptor"][0],
	)
	if !admodel.InternalDirectoryACEsRetained(originalACL.InternalAces, afterACL.InternalAces) {
		t.Fatal("unrelated ACE lost")
	}
	for _, write := range session.InternalWrites {
		if write.InternalOperation != admodel.InternalLdapWriteModify ||
			len(write.InternalModifications) != 1 ||
			write.InternalModifications[0].InternalAttribute != "nTSecurityDescriptor" ||
			write.InternalModifications[0].InternalOperation != 2 ||
			len(write.InternalControls) != 2 ||
			write.InternalControls[0].InternalOid != admodel.InternalObjectAssertionControl || !write.InternalControls[0].InternalCritical ||
			write.InternalControls[1].InternalOid != admodel.InternalOuSDFlagsControl ||
			!write.InternalControls[1].InternalCritical ||
			!slices.Equal(write.InternalControls[1].InternalValue, []byte{0x30, 3, 2, 1, 4}) {
			t.Fatal("wrong native write", write)
		}
	}
	if string(
		session.InternalObjects["ou=target,dc=example"].Attributes["useraccountcontrol"][0],
	) != "4096" {
		t.Fatal("permission changed stored UAC")
	}
}

func TestPasswordPermissionNativeErrorsAndReadbackRemainObservable(t *testing.T) {
	permission := &admodel.LDAPError{Code: 50}
	for _, phase := range []string{"preflight", "rejected", "uncertain", "readback"} {
		client, session := InternalNewPasswordPermissionClient(t)
		switch phase {
		case "preflight":
			session.InternalReadFailure = permission
		case "readback":
			session.InternalReadbackFailure = permission
		case "rejected":
			session.InternalFailAt = 1
			session.InternalFailure = admodel.InternalLdapWriteAttempt{
				State: admodel.InternalLdapWriteRejected,
				Err:   permission,
			}
		case "uncertain":
			session.InternalFailAt = 1
			session.InternalFailure = admodel.InternalLdapWriteAttempt{
				State: admodel.InternalLdapWriteUncertain,
				Err:   &admodel.LDAPError{Code: 81},
			}
		}
		result, err := adservice_accounts.New(client).
			SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
		if err == nil || result.Mutation.Verified || result.Before == nil ||
			result.Mutation.Before == nil {
			t.Fatal(phase, result, err)
		}
		if phase == "preflight" {
			if len(session.InternalWrites) != 0 || result.Before.CannotChangePassword != nil {
				t.Fatal(phase, result, err)
			}
			continue
		}
		if len(session.InternalWrites) != 1 {
			t.Fatal("write replayed", phase)
		}
		if phase == "uncertain" &&
			(!errors.Is(err, admodel.ErrObjectWriteUncertain) || result.Mutation.State != admodel.ObjectWriteUncertain) {
			t.Fatal(result, err)
		}
		if phase == "rejected" &&
			(!errors.Is(err, permission) || !errors.Is(err, admodel.ErrObjectWritePermission) || result.Mutation.State != admodel.ObjectWriteRejected) {
			t.Fatal(result, err)
		}
		if phase == "readback" &&
			(result.Mutation.State != admodel.ObjectWriteAccepted || result.After == nil || result.After.CannotChangePassword != nil || len(result.Mutation.ReadbackCandidates) != 1 || result.Mutation.ReadbackComplete) {
			t.Fatal(result, err)
		}
	}
}

func TestPasswordPermissionNoOpCannotClaimVersionGuard(t *testing.T) {
	client, session := InternalNewPasswordPermissionClient(t)
	object := session.InternalObjects["ou=target,dc=example"]
	object.Attributes["ntsecuritydescriptor"] = [][]byte{
		InternalOuTestDescriptor(
			admodel.InternalPasswordChangeRule(0, true),
			admodel.InternalPasswordChangeRule(1, true),
		),
	}
	originalRead := session.InternalRead
	session.InternalRead = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
		root, err := originalRead(ctx, properties)
		root["supportedcontrol"] = append(
			root["supportedcontrol"],
			[]byte(admodel.InternalObjectAssertionControl),
		)
		return root, err
	}
	value, _ := object.Values("objectGUID").Single()
	guid, _ := value.GUID()
	result, err := adservice_accounts.New(client).
		SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{ExpectedVersion: &admodel.ObjectVersion{Source: (*adengine.InternalClientConfigPointer(client)).Endpoint, GUID: guid, USNChanged: 7}})
	if !errors.Is(err, admodel.ErrObjectControlUnsupported) || len(session.InternalWrites) != 0 ||
		result.Mutation.Verified ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
}

func TestPasswordPermissionPreservesInheritedAndRejectsUnknown(t *testing.T) {
	for _, kind := range []string{"inherited", "unknown", "missing"} {
		client, session := InternalNewPasswordPermissionClient(t)
		object := session.InternalObjects["ou=target,dc=example"]
		switch kind {
		case "inherited":
			ace := admodel.InternalPasswordChangeRule(0, true)
			ace[1] = 0x10
			object.Attributes["ntsecuritydescriptor"] = [][]byte{InternalOuTestDescriptor(ace)}
		case "unknown":
			object.Attributes["ntsecuritydescriptor"] = [][]byte{
				InternalOuTestDescriptor([]byte{0x42, 0, 8, 0, 1, 2, 3, 4}),
			}
		case "missing":
			delete(object.Attributes, "ntsecuritydescriptor")
		}
		before := slices.Clone(object.Attributes["ntsecuritydescriptor"])
		result, err := adservice_accounts.New(client).
			SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), false, admodel.ObjectMutationOptions{})
		if !errors.Is(err, admodel.ErrAccountPasswordPermission) ||
			len(session.InternalWrites) != 0 ||
			result.Mutation.Verified {
			t.Fatal(kind, result, err)
		}
		if !slices.EqualFunc(
			before,
			object.Attributes["ntsecuritydescriptor"],
			slices.Equal[[]byte],
		) {
			t.Fatal("original descriptor mutated")
		}
		observed, err := adservice_accounts.New(client).
			AccountPasswordChangePermission(context.Background(), InternalOuTestIdentity(), admodel.ResolveIdentityOptions{})
		if observed.Permission == nil {
			t.Fatal(kind, err)
		}
		if kind == "inherited" &&
			(err != nil || observed.Permission.CannotChangePassword == nil || !*observed.Permission.CannotChangePassword || !observed.Permission.Self.InheritedDeny) {
			t.Fatal(observed, err)
		}
		if kind != "inherited" && observed.Permission.CannotChangePassword != nil {
			t.Fatal("unknown converted to false", observed)
		}
	}
}

func TestPasswordPermissionPreservesUnrelatedMaskAndObjectACEs(t *testing.T) {
	combined := admodel.InternalPasswordChangeRule(0, true)
	binary.LittleEndian.PutUint32(combined[4:8], 0x120)
	unrelated := admodel.InternalPasswordChangeRule(1, true)
	unrelated[12] ^= 0xff
	inherited := admodel.InternalPasswordChangeRule(0, false)
	inherited[1] = 0x10
	acl, _ := admodel.InternalDecodeDirectoryDACL(
		InternalOuTestDescriptor(combined, unrelated, inherited),
	)
	aces, changed, err := admodel.InternalChangePasswordPermissionACEs(acl, false)
	if err != nil || !changed ||
		!admodel.InternalDirectoryACEsRetained([][]byte{unrelated, inherited}, aces) {
		t.Fatal(aces, changed, err)
	}
	remaining := slices.Clone(combined)
	binary.LittleEndian.PutUint32(remaining[4:8], 0x20)
	if !admodel.InternalDirectoryACEsRetained(
		[][]byte{
			remaining,
			admodel.InternalPasswordChangeRule(0, false),
			admodel.InternalPasswordChangeRule(1, false),
		},
		aces,
	) {
		t.Fatal("unrelated access mask was lost")
	}
	if binary.LittleEndian.Uint32(combined[4:8]) != 0x120 {
		t.Fatal("input changed")
	}
}

func TestPasswordPermissionAmbiguousMixedRightsDoNotWrite(t *testing.T) {
	client, session := InternalNewPasswordPermissionClient(t)
	combined := admodel.InternalPasswordChangeRule(0, true)
	binary.LittleEndian.PutUint32(combined[4:8], 0x120)
	session.InternalObjects["ou=target,dc=example"].Attributes["ntsecuritydescriptor"] = [][]byte{
		InternalOuTestDescriptor(combined),
	}
	result, err := adservice_accounts.New(client).
		SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), false, admodel.ObjectMutationOptions{})
	if !errors.Is(err, admodel.ErrAccountPasswordPermission) || len(session.InternalWrites) != 0 ||
		result.Mutation.Verified {
		t.Fatal(result, err)
	}
}

func TestPasswordPermissionReadbackMustProveIdentityAndPreservedRules(t *testing.T) {
	for _, failure := range []string{"wrong-guid", "lost-unrelated-ace", "missing-descriptor"} {
		client, session := InternalNewPasswordPermissionClient(t)
		session.InternalReadbackTransform = func(object admodel.Object) admodel.Object {
			switch failure {
			case "wrong-guid":
				object.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
			case "lost-unrelated-ace":
				object.Attributes["ntsecuritydescriptor"] = [][]byte{
					InternalOuTestDescriptor(
						admodel.InternalPasswordChangeRule(0, true),
						admodel.InternalPasswordChangeRule(1, true),
					),
				}
			case "missing-descriptor":
				delete(object.Attributes, "ntsecuritydescriptor")
			}
			return object
		}
		result, err := adservice_accounts.New(client).
			SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
		if err == nil || result.Mutation.State != admodel.ObjectWriteAccepted ||
			result.Mutation.Verified ||
			result.After == nil ||
			len(session.InternalWrites) != 1 {
			t.Fatal(failure, result, err)
		}
	}
}

func TestPasswordPermissionClassAndCancellationGuard(t *testing.T) {
	client, session := InternalNewPasswordPermissionClient(t)
	identity, _ := admodel.IdentityByDN("DC=example")
	_, err := adservice_accounts.New(client).
		SetAccountCannotChangePassword(context.Background(), identity, true, admodel.ObjectMutationOptions{})
	if !errors.Is(err, admodel.ErrAccountControlTarget) || len(session.InternalWrites) != 0 {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = adservice_accounts.New(client).
		SetAccountCannotChangePassword(ctx, InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
	if !errors.Is(err, context.Canceled) || len(session.InternalWrites) != 0 {
		t.Fatal(err)
	}
}

func TestPasswordPermissionRequestedPropertiesSurviveControlledReadAndMutation(t *testing.T) {
	for _, operation := range []string{"read", "no-op", "changed", "readback-error"} {
		t.Run(operation, func(t *testing.T) {
			client, session := InternalNewPasswordPermissionClient(t)
			object := session.InternalObjects["ou=target,dc=example"]
			object.Attributes["description"] = [][]byte{[]byte("before")}
			object.Attributes["custombinary"] = [][]byte{{0, 0xff, 0x80}, {}}
			if operation == "no-op" {
				object.Attributes["ntsecuritydescriptor"] = [][]byte{
					InternalOuTestDescriptor(
						admodel.InternalPasswordChangeRule(0, true),
						admodel.InternalPasswordChangeRule(1, true),
					),
				}
			}
			session.InternalReadbackTransform = func(after admodel.Object) admodel.Object {
				after.Attributes["description"] = [][]byte{[]byte("controlled readback")}
				return after
			}
			properties := []string{"description", "customBinary"}
			check := func(observed admodel.Object, description string) {
				t.Helper()
				if values := observed.Attributes["description"]; len(values) != 1 ||
					string(values[0]) != description {
					t.Fatal("requested text missing or stale", observed)
				}
				if values := observed.Attributes["custombinary"]; len(values) != 2 ||
					!slices.Equal(values[0], []byte{0, 0xff, 0x80}) ||
					len(values[1]) != 0 {
					t.Fatal("requested binary values lost", observed)
				}
				for _, name := range properties {
					if !slices.Contains(observed.RequestedProperties, name) {
						t.Fatal("selection metadata lost", observed.RequestedProperties)
					}
				}
			}
			if operation == "read" {
				result, err := adservice_accounts.New(client).
					AccountPasswordChangePermission(context.Background(), InternalOuTestIdentity(), admodel.ResolveIdentityOptions{Properties: properties})
				if err != nil || result.Permission == nil ||
					len(session.InternalDaclProperties) != 1 ||
					len(session.InternalWrites) != 0 {
					t.Fatal(result, err)
				}
				check(result.Permission.Raw, "before")
				return
			}
			if operation == "readback-error" {
				session.InternalReadbackFailure = &admodel.LDAPError{Code: 50}
			}
			result, err := adservice_accounts.New(client).
				SetAccountCannotChangePassword(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{Properties: properties})
			if (operation == "readback-error") != (err != nil) || result.Before == nil ||
				result.After == nil ||
				result.Mutation.Before == nil ||
				result.Mutation.After == nil {
				t.Fatal(result, err)
			}
			check(result.Before.Raw, "before")
			check(*result.Mutation.Before, "before")
			want := "controlled readback"
			if operation == "no-op" {
				want = "before"
				if len(session.InternalDaclProperties) != 1 || len(session.InternalWrites) != 0 ||
					result.Mutation.State != admodel.ObjectWriteNotAttempted ||
					!result.Mutation.Verified {
					t.Fatal(result, err)
				}
			} else if len(session.InternalDaclProperties) != 2 || len(session.InternalWrites) != 1 || result.Mutation.State != admodel.ObjectWriteAccepted {
				t.Fatal(result, err)
			}
			check(result.After.Raw, want)
			check(*result.Mutation.After, want)
			if operation == "readback-error" &&
				(result.Mutation.ReadbackComplete || result.Mutation.Verified || len(result.Mutation.ReadbackCandidates) != 1) {
				t.Fatal(result, err)
			}
		})
	}
}
