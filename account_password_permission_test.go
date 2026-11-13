package activedirectory

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

type passwordPermissionTestSession struct {
	*ouTestSession
	readbackTransform func(Object) Object
	daclProperties    [][]string
}

func (s *passwordPermissionTestSession) readDirectoryDACL(ctx context.Context, dn string, extra []string) (Object, error) {
	object, err := s.readOUDACL(ctx, dn)
	properties := directoryDACLProperties(extra)
	s.daclProperties = append(s.daclProperties, slices.Clone(properties))
	attrs := make(map[string][][]byte)
	for _, name := range properties {
		if values, ok := object.Attributes[strings.ToLower(name)]; ok {
			attrs[strings.ToLower(name)] = values
		}
	}
	object.Attributes = attrs
	object.RequestedProperties = properties
	if len(s.writes) > 0 && s.readbackTransform != nil {
		object = s.readbackTransform(object)
	}
	return object, err
}
func (*passwordPermissionTestSession) encodeDACL(_ []byte, aces [][]byte) ([]byte, error) {
	return ouTestDescriptor(aces...), nil
}

func newPasswordPermissionClient(t *testing.T) (*Client, *passwordPermissionTestSession) {
	client, base := newOUTestClient(t)
	object := base.objects["ou=target,dc=example"]
	object.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("person"), []byte("user"), []byte("computer")}
	object.Attributes["useraccountcontrol"] = [][]byte{[]byte("4096")}
	session := &passwordPermissionTestSession{ouTestSession: base}
	client.session = session
	return client, session
}

func TestPasswordPermissionRoundTripAndIdempotence(t *testing.T) {
	client, session := newPasswordPermissionClient(t)
	original := slices.Clone(session.objects["ou=target,dc=example"].Attributes["ntsecuritydescriptor"][0])
	result, err := client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{})
	if err != nil || !result.Changed || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted || result.After == nil || result.After.CannotChangePassword == nil || !*result.After.CannotChangePassword || !result.After.Self.ExplicitDeny || !result.After.Everyone.ExplicitDeny {
		t.Fatal(result, err)
	}
	result, err = client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{})
	if err != nil || result.Changed || !result.Mutation.Verified || result.Mutation.State != ObjectWriteNotAttempted || len(session.writes) != 1 {
		t.Fatal(result, err)
	}
	result, err = client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), false, ObjectMutationOptions{})
	if err != nil || !result.Mutation.Verified || result.After.CannotChangePassword == nil || *result.After.CannotChangePassword || !result.After.Self.ExplicitAllow || !result.After.Everyone.ExplicitAllow || result.After.Self.ExplicitDeny || result.After.Everyone.ExplicitDeny {
		t.Fatal(result, err)
	}
	originalACL, _ := decodeDirectoryDACL(original)
	afterACL, _ := decodeDirectoryDACL(result.After.Raw.Attributes["ntsecuritydescriptor"][0])
	if !directoryACEsRetained(originalACL.aces, afterACL.aces) {
		t.Fatal("unrelated ACE lost")
	}
	for _, write := range session.writes {
		if write.operation != ldapWriteModify || len(write.modifications) != 1 || write.modifications[0].attribute != "nTSecurityDescriptor" || write.modifications[0].operation != 2 || len(write.controls) != 1 || write.controls[0].oid != ouSDFlagsControl || !write.controls[0].critical || !slices.Equal(write.controls[0].value, []byte{0x30, 3, 2, 1, 4}) {
			t.Fatal("wrong native write", write)
		}
	}
	if string(session.objects["ou=target,dc=example"].Attributes["useraccountcontrol"][0]) != "4096" {
		t.Fatal("permission changed stored UAC")
	}
}

func TestPasswordPermissionNativeErrorsAndReadbackRemainObservable(t *testing.T) {
	permission := &LDAPError{Code: 50}
	for _, phase := range []string{"preflight", "rejected", "uncertain", "readback"} {
		client, session := newPasswordPermissionClient(t)
		switch phase {
		case "preflight":
			session.readFailure = permission
		case "readback":
			session.readbackFailure = permission
		case "rejected":
			session.failAt = 1
			session.failure = ldapWriteAttempt{State: ldapWriteRejected, Err: permission}
		case "uncertain":
			session.failAt = 1
			session.failure = ldapWriteAttempt{State: ldapWriteUncertain, Err: &LDAPError{Code: 81}}
		}
		result, err := client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{})
		if err == nil || result.Mutation.Verified || result.Before == nil || result.Mutation.Before == nil {
			t.Fatal(phase, result, err)
		}
		if phase == "preflight" {
			if len(session.writes) != 0 || result.Before.CannotChangePassword != nil {
				t.Fatal(phase, result, err)
			}
			continue
		}
		if len(session.writes) != 1 {
			t.Fatal("write replayed", phase)
		}
		if phase == "uncertain" && (!errors.Is(err, ErrObjectWriteUncertain) || result.Mutation.State != ObjectWriteUncertain) {
			t.Fatal(result, err)
		}
		if phase == "rejected" && (!errors.Is(err, permission) || !errors.Is(err, ErrObjectWritePermission) || result.Mutation.State != ObjectWriteRejected) {
			t.Fatal(result, err)
		}
		if phase == "readback" && (result.Mutation.State != ObjectWriteAccepted || result.After == nil || result.After.CannotChangePassword != nil || len(result.Mutation.ReadbackCandidates) != 1 || result.Mutation.ReadbackComplete) {
			t.Fatal(result, err)
		}
	}
}

func TestPasswordPermissionNoOpCannotClaimVersionGuard(t *testing.T) {
	client, session := newPasswordPermissionClient(t)
	object := session.objects["ou=target,dc=example"]
	object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(passwordChangeRule(0, true), passwordChangeRule(1, true))}
	originalRead := session.read
	session.read = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
		root, err := originalRead(ctx, properties)
		root["supportedcontrol"] = append(root["supportedcontrol"], []byte(objectAssertionControl))
		return root, err
	}
	value, _ := object.Values("objectGUID").Single()
	guid, _ := value.GUID()
	result, err := client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{ExpectedVersion: &ObjectVersion{Source: client.config.Endpoint, GUID: guid, USNChanged: 7}})
	if !errors.Is(err, ErrObjectControlUnsupported) || len(session.writes) != 0 || result.Mutation.Verified || result.Mutation.State != ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
}

func TestPasswordPermissionPreservesInheritedAndRejectsUnknown(t *testing.T) {
	for _, kind := range []string{"inherited", "unknown", "missing"} {
		client, session := newPasswordPermissionClient(t)
		object := session.objects["ou=target,dc=example"]
		switch kind {
		case "inherited":
			ace := passwordChangeRule(0, true)
			ace[1] = 0x10
			object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(ace)}
		case "unknown":
			object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor([]byte{0x42, 0, 8, 0, 1, 2, 3, 4})}
		case "missing":
			delete(object.Attributes, "ntsecuritydescriptor")
		}
		before := slices.Clone(object.Attributes["ntsecuritydescriptor"])
		result, err := client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), false, ObjectMutationOptions{})
		if !errors.Is(err, ErrAccountPasswordPermission) || len(session.writes) != 0 || result.Mutation.Verified {
			t.Fatal(kind, result, err)
		}
		if !slices.EqualFunc(before, object.Attributes["ntsecuritydescriptor"], slices.Equal[[]byte]) {
			t.Fatal("original descriptor mutated")
		}
		observed, err := client.AccountPasswordChangePermission(context.Background(), ouTestIdentity(), ResolveIdentityOptions{})
		if observed.Permission == nil {
			t.Fatal(kind, err)
		}
		if kind == "inherited" && (err != nil || observed.Permission.CannotChangePassword == nil || !*observed.Permission.CannotChangePassword || !observed.Permission.Self.InheritedDeny) {
			t.Fatal(observed, err)
		}
		if kind != "inherited" && observed.Permission.CannotChangePassword != nil {
			t.Fatal("unknown converted to false", observed)
		}
	}
}

func TestPasswordPermissionPreservesUnrelatedMaskAndObjectACEs(t *testing.T) {
	combined := passwordChangeRule(0, true)
	binary.LittleEndian.PutUint32(combined[4:8], 0x120)
	unrelated := passwordChangeRule(1, true)
	unrelated[12] ^= 0xff
	inherited := passwordChangeRule(0, false)
	inherited[1] = 0x10
	acl, _ := decodeDirectoryDACL(ouTestDescriptor(combined, unrelated, inherited))
	aces, changed, err := changePasswordPermissionACEs(acl, false)
	if err != nil || !changed || !directoryACEsRetained([][]byte{unrelated, inherited}, aces) {
		t.Fatal(aces, changed, err)
	}
	remaining := slices.Clone(combined)
	binary.LittleEndian.PutUint32(remaining[4:8], 0x20)
	if !directoryACEsRetained([][]byte{remaining, passwordChangeRule(0, false), passwordChangeRule(1, false)}, aces) {
		t.Fatal("unrelated access mask was lost")
	}
	if binary.LittleEndian.Uint32(combined[4:8]) != 0x120 {
		t.Fatal("input changed")
	}
}

func TestPasswordPermissionAmbiguousMixedRightsDoNotWrite(t *testing.T) {
	client, session := newPasswordPermissionClient(t)
	combined := passwordChangeRule(0, true)
	binary.LittleEndian.PutUint32(combined[4:8], 0x120)
	session.objects["ou=target,dc=example"].Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(combined)}
	result, err := client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), false, ObjectMutationOptions{})
	if !errors.Is(err, ErrAccountPasswordPermission) || len(session.writes) != 0 || result.Mutation.Verified {
		t.Fatal(result, err)
	}
}

func TestPasswordPermissionReadbackMustProveIdentityAndPreservedRules(t *testing.T) {
	for _, failure := range []string{"wrong-guid", "lost-unrelated-ace", "missing-descriptor"} {
		client, session := newPasswordPermissionClient(t)
		session.readbackTransform = func(object Object) Object {
			switch failure {
			case "wrong-guid":
				object.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
			case "lost-unrelated-ace":
				object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(passwordChangeRule(0, true), passwordChangeRule(1, true))}
			case "missing-descriptor":
				delete(object.Attributes, "ntsecuritydescriptor")
			}
			return object
		}
		result, err := client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{})
		if err == nil || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || result.After == nil || len(session.writes) != 1 {
			t.Fatal(failure, result, err)
		}
	}
}

func TestPasswordPermissionClassAndCancellationGuard(t *testing.T) {
	client, session := newPasswordPermissionClient(t)
	identity, _ := IdentityByDN("DC=example")
	_, err := client.SetAccountCannotChangePassword(context.Background(), identity, true, ObjectMutationOptions{})
	if !errors.Is(err, ErrAccountControlTarget) || len(session.writes) != 0 {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.SetAccountCannotChangePassword(ctx, ouTestIdentity(), true, ObjectMutationOptions{})
	if !errors.Is(err, context.Canceled) || len(session.writes) != 0 {
		t.Fatal(err)
	}
}

func TestPasswordPermissionRequestedPropertiesSurviveControlledReadAndMutation(t *testing.T) {
	for _, operation := range []string{"read", "no-op", "changed", "readback-error"} {
		t.Run(operation, func(t *testing.T) {
			client, session := newPasswordPermissionClient(t)
			object := session.objects["ou=target,dc=example"]
			object.Attributes["description"] = [][]byte{[]byte("before")}
			object.Attributes["custombinary"] = [][]byte{{0, 0xff, 0x80}, {}}
			if operation == "no-op" {
				object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(passwordChangeRule(0, true), passwordChangeRule(1, true))}
			}
			session.readbackTransform = func(after Object) Object {
				after.Attributes["description"] = [][]byte{[]byte("controlled readback")}
				return after
			}
			properties := []string{"description", "customBinary"}
			check := func(observed Object, description string) {
				t.Helper()
				if values := observed.Attributes["description"]; len(values) != 1 || string(values[0]) != description {
					t.Fatal("requested text missing or stale", observed)
				}
				if values := observed.Attributes["custombinary"]; len(values) != 2 || !slices.Equal(values[0], []byte{0, 0xff, 0x80}) || len(values[1]) != 0 {
					t.Fatal("requested binary values lost", observed)
				}
				for _, name := range properties {
					if !slices.Contains(observed.RequestedProperties, name) {
						t.Fatal("selection metadata lost", observed.RequestedProperties)
					}
				}
			}
			if operation == "read" {
				result, err := client.AccountPasswordChangePermission(context.Background(), ouTestIdentity(), ResolveIdentityOptions{Properties: properties})
				if err != nil || result.Permission == nil || len(session.daclProperties) != 1 || len(session.writes) != 0 {
					t.Fatal(result, err)
				}
				check(result.Permission.Raw, "before")
				return
			}
			if operation == "readback-error" {
				session.readbackFailure = &LDAPError{Code: 50}
			}
			result, err := client.SetAccountCannotChangePassword(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{Properties: properties})
			if (operation == "readback-error") != (err != nil) || result.Before == nil || result.After == nil || result.Mutation.Before == nil || result.Mutation.After == nil {
				t.Fatal(result, err)
			}
			check(result.Before.Raw, "before")
			check(*result.Mutation.Before, "before")
			want := "controlled readback"
			if operation == "no-op" {
				want = "before"
				if len(session.daclProperties) != 1 || len(session.writes) != 0 || result.Mutation.State != ObjectWriteNotAttempted || !result.Mutation.Verified {
					t.Fatal(result, err)
				}
			} else if len(session.daclProperties) != 2 || len(session.writes) != 1 || result.Mutation.State != ObjectWriteAccepted {
				t.Fatal(result, err)
			}
			check(result.After.Raw, want)
			check(*result.Mutation.After, want)
			if operation == "readback-error" && (result.Mutation.ReadbackComplete || result.Mutation.Verified || len(result.Mutation.ReadbackCandidates) != 1) {
				t.Fatal(result, err)
			}
		})
	}
}
