package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// This fixture models observable LDAP replies, not AD authorization. Native
// descriptor tests separately exercise Windows ownership and opaque ACE copying.
type ouTestSession struct {
	testSession
	objects         map[string]Object
	writes          []ldapWriteRequest
	failAt          int
	failure         ldapWriteAttempt
	readFailure     error
	readbackFailure error
}

func ouTestObject(dn, class string, id byte) Object {
	guid := make([]byte, 16)
	guid[0] = id
	return Object{DistinguishedName: dn, Attributes: map[string][][]byte{
		"objectguid": {guid}, "objectclass": {[]byte("top"), []byte(class)},
		"usnchanged": {[]byte("7")}, "ntsecuritydescriptor": {ouTestDescriptor(ouTestACE(0, 0, 0x20000))},
	}}
}

func newOUTestClient(t *testing.T) (*Client, *ouTestSession) {
	t.Helper()
	s := &ouTestSession{objects: map[string]Object{}}
	for _, object := range []Object{ouTestObject("DC=example", "domainDNS", 1), ouTestObject("OU=target,DC=example", "organizationalUnit", 2), ouTestObject("OU=child,OU=target,DC=example", "organizationalUnit", 3)} {
		s.objects[strings.ToLower(object.DistinguishedName)] = object
	}
	s.read = func(context.Context, []string) (map[string][][]byte, error) {
		root := identityTestRoot(CapabilityActiveDirectory)
		root["schemanamingcontext"] = [][]byte{[]byte("CN=Schema,CN=Configuration,DC=example")}
		root["supportedcontrol"] = [][]byte{[]byte(ouSDFlagsControl), []byte("1.2.840.113556.1.4.805")}
		return root, nil
	}
	s.search = func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if query.Base == "CN=Schema,CN=Configuration,DC=example" {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("ou")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		if strings.Contains(query.Filter, "objectGUID=") {
			for _, object := range s.objects {
				guid, _ := object.Values("objectGUID").Single()
				if strings.Contains(query.Filter, identityBinaryLiteral(guid.Bytes())) {
					return objectTestCursor(object), nil
				}
			}
			return objectTestCursor(), nil
		}
		if object, ok := s.lookup(query.Base); ok {
			return objectTestCursor(object), nil
		}
		return objectTestCursor(), nil
	}
	s.finish = func() error { return nil }
	client := newClient(Config{Endpoint: Endpoint{Host: "dc.example", Port: 389}, Timeout: time.Second}, s)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client, s
}

func (s *ouTestSession) lookup(target string) (Object, bool) {
	if object, ok := s.objects[strings.ToLower(target)]; ok {
		return object, true
	}
	for _, object := range s.objects {
		value, _ := object.Values("objectGUID").Single()
		guid, _ := value.GUID()
		if objectGUIDTarget(guid) == target {
			return object, true
		}
	}
	return Object{}, false
}

func (s *ouTestSession) readOUDACL(_ context.Context, dn string) (Object, error) {
	object, _ := s.lookup(dn)
	if len(s.writes) > 0 && s.readbackFailure != nil {
		return object, s.readbackFailure
	}
	return object, s.readFailure
}

func (*ouTestSession) editOUDACL(raw []byte, mask uint32, protect bool) ([]byte, bool, error) {
	acl, err := decodeOUDACL(raw)
	if err != nil {
		return nil, false, err
	}
	aces, changed := changeOUACEs(acl, mask, protect)
	return ouTestDescriptor(aces...), changed, nil
}

func (s *ouTestSession) ldapWrite(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
	s.writes = append(s.writes, request)
	if s.failAt == len(s.writes) {
		return s.failure
	}
	if request.operation == ldapWriteAdd {
		object := ouTestObject(request.dn, "organizationalUnit", 4)
		for _, mod := range request.modifications {
			object.Attributes[strings.ToLower(mod.attribute)] = mod.values
		}
		object.Attributes["name"] = object.Attributes["ou"]
		s.objects[strings.ToLower(request.dn)] = object
		return ldapWriteAttempt{State: ldapWriteAccepted}
	}
	object, ok := s.lookup(request.dn)
	if !ok {
		return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 32}}
	}
	if request.operation == ldapWriteDelete {
		delete(s.objects, strings.ToLower(object.DistinguishedName))
		return ldapWriteAttempt{State: ldapWriteAccepted}
	}
	// Clone rows so previously returned observations cannot change retroactively.
	attributes := make(map[string][][]byte, len(object.Attributes))
	for name, values := range object.Attributes {
		attributes[name] = values
	}
	object.Attributes = attributes
	for _, mod := range request.modifications {
		if mod.operation == 1 && len(mod.values) == 0 {
			delete(object.Attributes, strings.ToLower(mod.attribute))
		} else {
			object.Attributes[strings.ToLower(mod.attribute)] = mod.values
		}
	}
	s.objects[strings.ToLower(object.DistinguishedName)] = object
	return ldapWriteAttempt{State: ldapWriteAccepted}
}

func ouTestIdentity() Identity { identity, _ := IdentityByDN("OU=target,DC=example"); return identity }

func TestOUProtectionParentFirstPartialAndNoReplay(t *testing.T) {
	for _, state := range []ldapWriteState{ldapWriteRejected, ldapWriteUncertain} {
		client, session := newOUTestClient(t)
		session.failAt = 2
		session.failure = ldapWriteAttempt{State: state, Err: &LDAPError{Code: 50}}
		result, err := client.SetOrganizationalUnitProtection(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{})
		if err == nil || len(session.writes) != 2 || len(result.Steps) != 2 || result.ProtectedFromAccidentalDeletion != nil || result.Steps[0].TargetDN != "DC=example" || result.Steps[0].State != ObjectWriteAccepted || !result.Steps[0].Verified || result.Steps[1].Verified {
			t.Fatalf("result=%+v writes=%d err=%v", result, len(session.writes), err)
		}
		if state == ldapWriteUncertain && (!errors.Is(err, ErrObjectWriteUncertain) || result.Steps[1].State != ObjectWriteUncertain) {
			t.Fatal(result, err)
		}
		for _, write := range session.writes {
			if len(write.controls) != 1 || write.controls[0].oid != ouSDFlagsControl || !write.controls[0].critical || !slices.Equal(write.controls[0].value, []byte{0x30, 3, 2, 1, 4}) {
				t.Fatal("DACL scope lost", write)
			}
		}
	}
}

func TestOUProtectionEnableDisablePreservesParentAndDescendants(t *testing.T) {
	client, session := newOUTestClient(t)
	childBefore := slices.Clone(session.objects["ou=child,ou=target,dc=example"].Attributes["ntsecuritydescriptor"][0])
	result, err := client.SetOrganizationalUnitProtection(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{})
	if err != nil || result.ProtectedFromAccidentalDeletion == nil || !*result.ProtectedFromAccidentalDeletion {
		t.Fatal(result, err)
	}
	parentBefore := slices.Clone(session.objects["dc=example"].Attributes["ntsecuritydescriptor"][0])
	result, err = client.SetOrganizationalUnitProtection(context.Background(), ouTestIdentity(), false, ObjectMutationOptions{})
	if err != nil || result.ProtectedFromAccidentalDeletion == nil || *result.ProtectedFromAccidentalDeletion || len(session.writes) != 3 || result.Steps[0].State != ObjectWriteAccepted || result.Steps[1].Changed {
		t.Fatal(result, err)
	}
	if !slices.Equal(parentBefore, session.objects["dc=example"].Attributes["ntsecuritydescriptor"][0]) || !slices.Equal(childBefore, session.objects["ou=child,ou=target,dc=example"].Attributes["ntsecuritydescriptor"][0]) {
		t.Fatal("unprotect changed parent or nested OU")
	}
	if _, err := client.SetOrganizationalUnitProtection(context.Background(), ouTestIdentity(), false, ObjectMutationOptions{}); err != nil || len(session.writes) != 3 {
		t.Fatal("non-idempotent unprotect", err)
	}
}

func TestOUProtectionPermissionAndReadbackFailurePreserveObservations(t *testing.T) {
	permission := &LDAPError{Code: 50}
	for _, phase := range []string{"preflight", "readback"} {
		client, session := newOUTestClient(t)
		if phase == "preflight" {
			session.readFailure = permission
		} else {
			session.readbackFailure = permission
		}
		result, err := client.SetOrganizationalUnitProtection(context.Background(), ouTestIdentity(), true, ObjectMutationOptions{})
		if !errors.Is(err, permission) || result.ProtectedFromAccidentalDeletion != nil || len(result.Steps) == 0 || result.Steps[0].Before == nil {
			t.Fatal(result, err)
		}
		if phase == "preflight" && len(session.writes) != 0 {
			t.Fatal("write after unreadable ACL")
		}
		if phase == "readback" && (len(session.writes) != 1 || result.Steps[0].State != ObjectWriteAccepted || result.Steps[0].After == nil || result.Steps[0].Verified) {
			t.Fatal("accepted parent outcome lost", result)
		}
	}
}

func TestOUCreateExplicitPartitionSelectsDefaultParent(t *testing.T) {
	for _, partition := range []string{"", "DC=app"} {
		want := "DC=example"
		if partition != "" {
			want = partition
		}
		seen := false
		denied := &LDAPError{Code: 50}
		client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
			seen = true
			if query.Base != want {
				t.Fatalf("selected %q, want explicit/default parent %q", query.Base, want)
			}
			return nil, denied
		}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
			t.Fatal("write after unresolved parent")
			return ldapWriteAttempt{}
		})
		client.config.Partition = "DC=example"
		result, err := client.CreateOrganizationalUnit(context.Background(), CreateOrganizationalUnitRequest{Name: "test", Options: ObjectMutationOptions{Partition: partition}})
		if !seen || !errors.Is(err, denied) || result.Object.State != ObjectWriteNotAttempted {
			t.Fatal(result, err, seen)
		}
	}
}

func TestOUCreateDefaultsAndExplicitUnprotected(t *testing.T) {
	for _, protect := range []*bool{nil, new(bool)} {
		client, session := newOUTestClient(t)
		description := "created"
		result, err := client.CreateOrganizationalUnit(context.Background(), CreateOrganizationalUnitRequest{Name: "李, People", Properties: OUProperties{Description: &description}, ProtectedFromAccidentalDeletion: protect})
		want := protect == nil
		if err != nil || result.Object.State != ObjectWriteAccepted || !result.Object.Verified || result.Unit == nil || result.Unit.Description == nil || *result.Unit.Description != description || result.Unit.ProtectedFromAccidentalDeletion == nil || *result.Unit.ProtectedFromAccidentalDeletion != want {
			t.Fatalf("%+v err=%v", result, err)
		}
		if session.writes[0].operation != ldapWriteAdd || session.writes[0].dn != `ou=李\, People,DC=example` {
			t.Fatal(session.writes[0])
		}
		if (want && len(session.writes) != 3) || (!want && len(session.writes) != 1) {
			t.Fatal("wrong ACL dispatch count", len(session.writes))
		}
	}
}

func TestOUCreateRetainsAcceptedAddOnProtectionFailure(t *testing.T) {
	client, session := newOUTestClient(t)
	session.failAt = 2
	session.failure = ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50}}
	result, err := client.CreateOrganizationalUnit(context.Background(), CreateOrganizationalUnitRequest{Name: "created"})
	if err == nil || result.Object.State != ObjectWriteAccepted || !result.Object.Verified || result.Unit == nil || result.Protection.Steps[0].State != ObjectWriteRejected || len(session.writes) != 2 {
		t.Fatal(result, err)
	}
}

func TestOUUpdateAndProtectedDeleteKeepNativeFailure(t *testing.T) {
	client, session := newOUTestClient(t)
	city := "London"
	result, err := client.UpdateOrganizationalUnit(context.Background(), UpdateOrganizationalUnitRequest{Identity: ouTestIdentity(), Properties: OUProperties{City: &city}})
	if err != nil || !result.Object.Verified || result.Unit == nil || result.Unit.City == nil || *result.Unit.City != city {
		t.Fatal(result, err)
	}
	session.failAt = 2
	native := &LDAPError{Code: 50}
	session.failure = ldapWriteAttempt{State: ldapWriteRejected, Err: native}
	deleted, err := client.DeleteOrganizationalUnit(context.Background(), DeleteOrganizationalUnitRequest{Identity: ouTestIdentity(), Recursive: true})
	if !errors.Is(err, native) || !errors.Is(err, ErrObjectWritePermission) || deleted.State != ObjectWriteRejected || !deleted.PartialEffectsPossible || len(session.writes) != 2 || session.writes[1].operation != ldapWriteDelete {
		t.Fatal(deleted, err)
	}
	if len(session.writes[1].controls) != 1 || session.writes[1].controls[0].oid != "1.2.840.113556.1.4.805" || !session.writes[1].controls[0].critical {
		t.Fatal("recursive intent lost")
	}
}

func TestOUClassAndCancellationPreventWrites(t *testing.T) {
	client, session := newOUTestClient(t)
	identity, _ := IdentityByDN("DC=example")
	_, err := client.DeleteOrganizationalUnit(context.Background(), DeleteOrganizationalUnitRequest{Identity: identity})
	if !errors.Is(err, ErrNotOrganizationalUnit) || len(session.writes) != 0 {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.SetOrganizationalUnitProtection(ctx, ouTestIdentity(), true, ObjectMutationOptions{})
	if !errors.Is(err, context.Canceled) || len(session.writes) != 0 {
		t.Fatal(err)
	}
}

func TestOULDSNamingContextHeadUsesOnlyObjectACL(t *testing.T) {
	client, session := newOUTestClient(t)
	client.config.Endpoint.Port = 3268 // An LDS custom port is not an AD DS GC.
	object := ouTestObject("OU=application", "organizationalUnit", 8)
	session.objects = map[string]Object{"ou=application": object}
	session.read = func(context.Context, []string) (map[string][][]byte, error) {
		return map[string][][]byte{"supportedcapabilities": {[]byte(CapabilityADLDS)}, "namingcontexts": {[]byte("OU=application")}, "defaultnamingcontext": {[]byte("OU=application")}, "supportedcontrol": {[]byte(ouSDFlagsControl)}}, nil
	}
	identity, _ := IdentityByDN("OU=application")
	result, err := client.SetOrganizationalUnitProtection(context.Background(), identity, true, ObjectMutationOptions{})
	if err != nil || len(session.writes) != 1 || len(result.Steps) != 1 || result.ProtectedFromAccidentalDeletion == nil || !*result.ProtectedFromAccidentalDeletion {
		t.Fatal(result, err)
	}
	result, err = client.SetOrganizationalUnitProtection(context.Background(), identity, false, ObjectMutationOptions{})
	if err != nil || len(session.writes) != 2 || result.ProtectedFromAccidentalDeletion == nil || *result.ProtectedFromAccidentalDeletion {
		t.Fatal(result, err)
	}
}

func TestOUProtectionUnknownAndMissingAreNotFalse(t *testing.T) {
	for _, kind := range []string{"opaque", "missing"} {
		client, session := newOUTestClient(t)
		object := session.objects["ou=target,dc=example"]
		if kind == "missing" {
			delete(object.Attributes, "ntsecuritydescriptor")
		} else {
			object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor([]byte{0x42, 0, 8, 0, 1, 2, 3, 4})}
		}
		result, err := client.OrganizationalUnit(context.Background(), ouTestIdentity(), ResolveIdentityOptions{Properties: []string{"ProtectedFromAccidentalDeletion"}})
		if result.Unit == nil || result.Unit.ProtectedFromAccidentalDeletion != nil || len(session.writes) != 0 || len(result.Protection.Steps) == 0 {
			t.Fatal(result, err)
		}
		if kind == "missing" && err == nil {
			t.Fatal("unreadable descriptor became success")
		}
	}
}

func TestOUInheritedProtectionCannotBeSilentlyRemoved(t *testing.T) {
	client, session := newOUTestClient(t)
	object := session.objects["ou=target,dc=example"]
	object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(ouTestACE(1, 0x10, ouObjectProtectionMask))}
	parent := session.objects["dc=example"]
	parent.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(ouTestACE(1, 0, ouParentProtectionMask))}
	result, err := client.SetOrganizationalUnitProtection(context.Background(), ouTestIdentity(), false, ObjectMutationOptions{})
	if !errors.Is(err, ErrOUProtection) || len(session.writes) != 0 || result.ProtectedFromAccidentalDeletion != nil {
		t.Fatal(result, err)
	}
}

func TestOUProtectionNoOpCannotEnforceExpectedVersion(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		client, session := newOUTestClient(t)
		originalRead := session.read
		session.read = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
			root, err := originalRead(ctx, properties)
			root["supportedcontrol"] = append(root["supportedcontrol"], []byte(objectAssertionControl))
			return root, err
		}
		object := session.objects["ou=target,dc=example"]
		if inherited {
			object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(ouTestACE(1, 0x10, ouObjectProtectionMask))}
			session.objects["dc=example"].Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(ouTestACE(1, 0, ouParentProtectionMask))}
		}
		value, _ := object.Values("objectGUID").Single()
		guid, _ := value.GUID()
		result, err := client.SetOrganizationalUnitProtection(context.Background(), ouTestIdentity(), false, ObjectMutationOptions{ExpectedVersion: &ObjectVersion{Source: client.config.Endpoint, GUID: guid, USNChanged: 7}})
		if !errors.Is(err, ErrObjectControlUnsupported) || len(session.writes) != 0 || result.ProtectedFromAccidentalDeletion != nil {
			t.Fatal(result, err)
		}
		for _, step := range result.Steps {
			if step.Verified {
				t.Fatal("no-op falsely enforced expected version", step)
			}
		}
	}
}

func TestOUSearchComposesTypedFilterAndRetainsPartialRawValues(t *testing.T) {
	client, session := newOUTestClient(t)
	partial := &LDAPError{Code: 4}
	session.search = func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if query.Base != "DC=example" || query.Scope != ScopeSubtree || query.Filter != `(&(objectClass=organizationalUnit)(name=a\2a\29\28name=\2a\29))` {
			t.Fatalf("wrong bounded query: %+v", query)
		}
		object := session.objects["ou=target,dc=example"]
		object.Attributes["description"] = [][]byte{{0xff, 0}}
		return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return []Object{object}, false, partial }, finish: func() error { return nil }}, nil
	}
	result, err := client.OrganizationalUnits(context.Background(), SearchOptions{Scope: ScopeSubtree, TypedFilter: FilterEqual("name", FilterText("a*)(name=*)"))})
	if !errors.Is(err, partial) || result.Observation.Complete || len(result.Units) != 1 || result.Units[0].Description != nil || !slices.Equal(result.Units[0].Raw.Attributes["description"][0], []byte{0xff, 0}) {
		t.Fatal(result, err)
	}
}
