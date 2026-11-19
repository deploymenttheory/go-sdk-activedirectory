package acceptance

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_organizational_units "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/organizational_units"
)

// This fixture models observable LDAP replies, not AD authorization. Native
// descriptor tests separately exercise Windows ownership and opaque ACE copying.
type InternalOuTestSession struct {
	InternalTestSession
	InternalObjects         map[string]admodel.Object
	InternalWrites          []admodel.InternalLdapWriteRequest
	InternalFailAt          int
	InternalFailure         admodel.InternalLdapWriteAttempt
	InternalReadFailure     error
	InternalReadbackFailure error
}

func InternalOuTestObject(dn, class string, id byte) admodel.Object {
	guid := make([]byte, 16)
	guid[0] = id
	return admodel.Object{DistinguishedName: dn, Attributes: map[string][][]byte{
		"objectguid":  {guid},
		"objectclass": {[]byte("top"), []byte(class)},
		"usnchanged": {
			[]byte("7"),
		},
		"ntsecuritydescriptor": {InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x20000))},
	}}
}

func InternalNewOUTestClient(t *testing.T) (*adengine.Client, *InternalOuTestSession) {
	t.Helper()
	s := &InternalOuTestSession{InternalObjects: map[string]admodel.Object{}}
	for _, object := range []admodel.Object{InternalOuTestObject("DC=example", "domainDNS", 1), InternalOuTestObject("OU=target,DC=example", "organizationalUnit", 2), InternalOuTestObject("OU=child,OU=target,DC=example", "organizationalUnit", 3)} {
		s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
	}
	s.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
		root := InternalIdentityTestRoot(admodel.CapabilityActiveDirectory)
		root["schemanamingcontext"] = [][]byte{[]byte("CN=Schema,CN=Configuration,DC=example")}
		root["supportedcontrol"] = [][]byte{
			[]byte(admodel.InternalOuSDFlagsControl),
			[]byte("1.2.840.113556.1.4.805"),
		}
		return root, nil
	}
	s.InternalSearch = func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if query.Base == "CN=Schema,CN=Configuration,DC=example" {
			return InternalObjectTestCursor(
				admodel.Object{
					Attributes: map[string][][]byte{
						"rdnattid":            {[]byte("ou")},
						"objectclasscategory": {[]byte("1")},
					},
				},
			), nil
		}
		if strings.Contains(query.Filter, "objectGUID=") {
			for _, object := range s.InternalObjects {
				guid, _ := object.Values("objectGUID").Single()
				if strings.Contains(
					query.Filter,
					admodel.InternalIdentityBinaryLiteral(guid.Bytes()),
				) {
					return InternalObjectTestCursor(object), nil
				}
			}
			return InternalObjectTestCursor(), nil
		}
		if object, ok := s.InternalLookup(query.Base); ok {
			return InternalObjectTestCursor(object), nil
		}
		return InternalObjectTestCursor(), nil
	}
	s.InternalFinish = func() error { return nil }
	client := adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example", Port: 389},
			Timeout:  time.Second,
		},
		s,
	)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client, s
}

func (s *InternalOuTestSession) InternalLookup(target string) (admodel.Object, bool) {
	if object, ok := s.InternalObjects[strings.ToLower(target)]; ok {
		return object, true
	}
	for _, object := range s.InternalObjects {
		value, _ := object.Values("objectGUID").Single()
		guid, _ := value.GUID()
		if admodel.InternalObjectGUIDTarget(guid) == target {
			return object, true
		}
	}
	return admodel.Object{}, false
}

func (s *InternalOuTestSession) InternalReadOUDACL(
	_ context.Context,
	dn string,
) (admodel.Object, error) {
	object, _ := s.InternalLookup(dn)
	if len(s.InternalWrites) > 0 && s.InternalReadbackFailure != nil {
		return object, s.InternalReadbackFailure
	}
	return object, s.InternalReadFailure
}

func (*InternalOuTestSession) InternalEditOUDACL(
	raw []byte,
	mask uint32,
	protect bool,
) ([]byte, bool, error) {
	acl, err := admodel.InternalDecodeOUDACL(raw)
	if err != nil {
		return nil, false, err
	}
	aces, changed := admodel.InternalChangeOUACEs(acl, mask, protect)
	return InternalOuTestDescriptor(aces...), changed, nil
}

func (s *InternalOuTestSession) InternalLdapWrite(
	_ context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	s.InternalWrites = append(s.InternalWrites, request)
	if s.InternalFailAt == len(s.InternalWrites) {
		return s.InternalFailure
	}
	if request.InternalOperation == admodel.InternalLdapWriteAdd {
		object := InternalOuTestObject(request.InternalDn, "organizationalUnit", 4)
		for _, mod := range request.InternalModifications {
			object.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
		}
		object.Attributes["name"] = object.Attributes["ou"]
		s.InternalObjects[strings.ToLower(request.InternalDn)] = object
		return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
	}
	object, ok := s.InternalLookup(request.InternalDn)
	if !ok {
		return admodel.InternalLdapWriteAttempt{
			State: admodel.InternalLdapWriteRejected,
			Err:   &admodel.LDAPError{Code: 32},
		}
	}
	if request.InternalOperation == admodel.InternalLdapWriteDelete {
		delete(s.InternalObjects, strings.ToLower(object.DistinguishedName))
		return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
	}
	// Clone rows so previously returned observations cannot change retroactively.
	attributes := make(map[string][][]byte, len(object.Attributes))
	for name, values := range object.Attributes {
		attributes[name] = values
	}
	object.Attributes = attributes
	for _, mod := range request.InternalModifications {
		if mod.InternalOperation == 1 && len(mod.InternalValues) == 0 {
			delete(object.Attributes, strings.ToLower(mod.InternalAttribute))
		} else {
			object.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
		}
	}
	s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
	return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
}

func InternalOuTestIdentity() admodel.Identity {
	identity, _ := admodel.IdentityByDN("OU=target,DC=example")
	return identity
}

func TestOUProtectionParentFirstPartialAndNoReplay(t *testing.T) {
	for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain} {
		client, session := InternalNewOUTestClient(t)
		session.InternalFailAt = 2
		session.InternalFailure = admodel.InternalLdapWriteAttempt{
			State: state,
			Err:   &admodel.LDAPError{Code: 50},
		}
		result, err := adservice_organizational_units.New(client).
			SetOrganizationalUnitProtection(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
		if err == nil || len(session.InternalWrites) != 2 || len(result.Steps) != 2 ||
			result.ProtectedFromAccidentalDeletion != nil ||
			result.Steps[0].TargetDN != "DC=example" ||
			result.Steps[0].State != admodel.ObjectWriteAccepted ||
			!result.Steps[0].Verified ||
			result.Steps[1].Verified {
			t.Fatalf("result=%+v writes=%d err=%v", result, len(session.InternalWrites), err)
		}
		if state == admodel.InternalLdapWriteUncertain &&
			(!errors.Is(err, admodel.ErrObjectWriteUncertain) || result.Steps[1].State != admodel.ObjectWriteUncertain) {
			t.Fatal(result, err)
		}
		for _, write := range session.InternalWrites {
			if len(write.InternalControls) != 1 ||
				write.InternalControls[0].InternalOid != admodel.InternalOuSDFlagsControl ||
				!write.InternalControls[0].InternalCritical ||
				!slices.Equal(write.InternalControls[0].InternalValue, []byte{0x30, 3, 2, 1, 4}) {
				t.Fatal("DACL scope lost", write)
			}
		}
	}
}

func TestOUProtectionEnableDisablePreservesParentAndDescendants(t *testing.T) {
	client, session := InternalNewOUTestClient(t)
	childBefore := slices.Clone(
		session.InternalObjects["ou=child,ou=target,dc=example"].Attributes["ntsecuritydescriptor"][0],
	)
	result, err := adservice_organizational_units.New(client).
		SetOrganizationalUnitProtection(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
	if err != nil || result.ProtectedFromAccidentalDeletion == nil ||
		!*result.ProtectedFromAccidentalDeletion {
		t.Fatal(result, err)
	}
	parentBefore := slices.Clone(
		session.InternalObjects["dc=example"].Attributes["ntsecuritydescriptor"][0],
	)
	result, err = adservice_organizational_units.New(client).
		SetOrganizationalUnitProtection(context.Background(), InternalOuTestIdentity(), false, admodel.ObjectMutationOptions{})
	if err != nil || result.ProtectedFromAccidentalDeletion == nil ||
		*result.ProtectedFromAccidentalDeletion ||
		len(session.InternalWrites) != 3 ||
		result.Steps[0].State != admodel.ObjectWriteAccepted ||
		result.Steps[1].Changed {
		t.Fatal(result, err)
	}
	if !slices.Equal(
		parentBefore,
		session.InternalObjects["dc=example"].Attributes["ntsecuritydescriptor"][0],
	) ||
		!slices.Equal(
			childBefore,
			session.InternalObjects["ou=child,ou=target,dc=example"].Attributes["ntsecuritydescriptor"][0],
		) {
		t.Fatal("unprotect changed parent or nested OU")
	}
	if _, err := adservice_organizational_units.New(client).
		SetOrganizationalUnitProtection(context.Background(), InternalOuTestIdentity(), false, admodel.ObjectMutationOptions{}); err != nil ||
		len(session.InternalWrites) != 3 {
		t.Fatal("non-idempotent unprotect", err)
	}
}

func TestOUProtectionPermissionAndReadbackFailurePreserveObservations(t *testing.T) {
	permission := &admodel.LDAPError{Code: 50}
	for _, phase := range []string{"preflight", "readback"} {
		client, session := InternalNewOUTestClient(t)
		if phase == "preflight" {
			session.InternalReadFailure = permission
		} else {
			session.InternalReadbackFailure = permission
		}
		result, err := adservice_organizational_units.New(client).
			SetOrganizationalUnitProtection(context.Background(), InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
		if !errors.Is(err, permission) || result.ProtectedFromAccidentalDeletion != nil ||
			len(result.Steps) == 0 ||
			result.Steps[0].Before == nil {
			t.Fatal(result, err)
		}
		if phase == "preflight" && len(session.InternalWrites) != 0 {
			t.Fatal("write after unreadable ACL")
		}
		if phase == "readback" &&
			(len(session.InternalWrites) != 1 || result.Steps[0].State != admodel.ObjectWriteAccepted || result.Steps[0].After == nil || result.Steps[0].Verified) {
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
		denied := &admodel.LDAPError{Code: 50}
		client := InternalObjectTestClient(
			t,
			nil,
			func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				seen = true
				if query.Base != want {
					t.Fatalf("selected %q, want explicit/default parent %q", query.Base, want)
				}
				return nil, denied
			},
			func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				t.Fatal("write after unresolved parent")
				return admodel.InternalLdapWriteAttempt{}
			},
		)
		(*adengine.InternalClientConfigPointer(client)).Partition = "DC=example"
		result, err := adservice_organizational_units.New(client).
			CreateOrganizationalUnit(context.Background(), admodel.CreateOrganizationalUnitRequest{Name: "test", ProtectedFromAccidentalDeletion: new(bool), Options: admodel.ObjectMutationOptions{Partition: partition}})
		if !seen || !errors.Is(err, denied) ||
			result.Object.State != admodel.ObjectWriteNotAttempted {
			t.Fatal(result, err, seen)
		}
	}
}

func TestOUCreateDefaultsAndExplicitUnprotected(t *testing.T) {
	for _, protect := range []*bool{nil, new(bool)} {
		client, session := InternalNewOUTestClient(t)
		description := "created"
		result, err := adservice_organizational_units.New(client).
			CreateOrganizationalUnit(context.Background(), admodel.CreateOrganizationalUnitRequest{Name: "李, People", Properties: admodel.OUProperties{Description: &description}, ProtectedFromAccidentalDeletion: protect})
		want := protect == nil
		if err != nil || result.Object.State != admodel.ObjectWriteAccepted ||
			!result.Object.Verified ||
			result.Unit == nil ||
			result.Unit.Description == nil ||
			*result.Unit.Description != description ||
			result.Unit.ProtectedFromAccidentalDeletion == nil ||
			*result.Unit.ProtectedFromAccidentalDeletion != want {
			t.Fatalf("%+v err=%v", result, err)
		}
		if session.InternalWrites[0].InternalOperation != admodel.InternalLdapWriteAdd ||
			session.InternalWrites[0].InternalDn != `ou=李\, People,DC=example` {
			t.Fatal(session.InternalWrites[0])
		}
		if (want && len(session.InternalWrites) != 3) ||
			(!want && len(session.InternalWrites) != 1) {
			t.Fatal("wrong ACL dispatch count", len(session.InternalWrites))
		}
	}
}

func TestOUCreateRetainsAcceptedAddOnProtectionFailure(t *testing.T) {
	client, session := InternalNewOUTestClient(t)
	session.InternalFailAt = 2
	session.InternalFailure = admodel.InternalLdapWriteAttempt{
		State: admodel.InternalLdapWriteRejected,
		Err:   &admodel.LDAPError{Code: 50},
	}
	result, err := adservice_organizational_units.New(client).
		CreateOrganizationalUnit(context.Background(), admodel.CreateOrganizationalUnitRequest{Name: "created"})
	if err == nil || result.Object.State != admodel.ObjectWriteAccepted ||
		!result.Object.Verified ||
		result.Unit == nil ||
		result.Protection.Steps[0].State != admodel.ObjectWriteRejected ||
		len(session.InternalWrites) != 2 {
		t.Fatal(result, err)
	}
}

func TestOUCreateRefusesMissingDACLControlBeforeAdd(t *testing.T) {
	client, session := InternalNewOUTestClient(t)
	read := session.InternalRead
	session.InternalRead = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
		root, err := read(ctx, properties)
		root["supportedcontrol"] = [][]byte{[]byte("1.2.840.113556.1.4.805")}
		return root, err
	}
	result, err := adservice_organizational_units.New(client).CreateOrganizationalUnit(context.Background(), admodel.CreateOrganizationalUnitRequest{Name: "guarded"})
	if !errors.Is(err, admodel.ErrObjectControlUnsupported) || result.Object.State != admodel.ObjectWriteNotAttempted || len(session.InternalWrites) != 0 {
		t.Fatal("missing DACL control still created an unprotected object", result, err)
	}
}

func TestOUUpdateAndProtectedDeleteKeepNativeFailure(t *testing.T) {
	client, session := InternalNewOUTestClient(t)
	city := "London"
	result, err := adservice_organizational_units.New(client).
		UpdateOrganizationalUnit(context.Background(), admodel.UpdateOrganizationalUnitRequest{Identity: InternalOuTestIdentity(), Properties: admodel.OUProperties{City: &city}})
	if err != nil || !result.Object.Verified || result.Unit == nil || result.Unit.City == nil ||
		*result.Unit.City != city {
		t.Fatal(result, err)
	}
	session.InternalFailAt = 2
	native := &admodel.LDAPError{Code: 50}
	session.InternalFailure = admodel.InternalLdapWriteAttempt{
		State: admodel.InternalLdapWriteRejected,
		Err:   native,
	}
	deleted, err := adservice_organizational_units.New(client).
		DeleteOrganizationalUnit(context.Background(), admodel.DeleteOrganizationalUnitRequest{Identity: InternalOuTestIdentity(), Recursive: true})
	if !errors.Is(err, native) || !errors.Is(err, admodel.ErrObjectWritePermission) ||
		deleted.State != admodel.ObjectWriteRejected ||
		!deleted.PartialEffectsPossible ||
		len(session.InternalWrites) != 2 ||
		session.InternalWrites[1].InternalOperation != admodel.InternalLdapWriteDelete {
		t.Fatal(deleted, err)
	}
	if len(session.InternalWrites[1].InternalControls) != 1 ||
		session.InternalWrites[1].InternalControls[0].InternalOid != "1.2.840.113556.1.4.805" ||
		!session.InternalWrites[1].InternalControls[0].InternalCritical {
		t.Fatal("recursive intent lost")
	}
}

func TestOUClassAndCancellationPreventWrites(t *testing.T) {
	client, session := InternalNewOUTestClient(t)
	identity, _ := admodel.IdentityByDN("DC=example")
	_, err := adservice_organizational_units.New(client).
		DeleteOrganizationalUnit(context.Background(), admodel.DeleteOrganizationalUnitRequest{Identity: identity})
	if !errors.Is(err, admodel.ErrNotOrganizationalUnit) || len(session.InternalWrites) != 0 {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = adservice_organizational_units.New(client).
		SetOrganizationalUnitProtection(ctx, InternalOuTestIdentity(), true, admodel.ObjectMutationOptions{})
	if !errors.Is(err, context.Canceled) || len(session.InternalWrites) != 0 {
		t.Fatal(err)
	}
}

func TestOULDSNamingContextHeadUsesOnlyObjectACL(t *testing.T) {
	client, session := InternalNewOUTestClient(t)
	(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268 // An LDS custom port is not an AD DS GC.
	object := InternalOuTestObject("OU=application", "organizationalUnit", 8)
	session.InternalObjects = map[string]admodel.Object{"ou=application": object}
	session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
		return map[string][][]byte{
			"supportedcapabilities": {[]byte(admodel.CapabilityADLDS)},
			"namingcontexts":        {[]byte("OU=application")},
			"defaultnamingcontext":  {[]byte("OU=application")},
			"supportedcontrol":      {[]byte(admodel.InternalOuSDFlagsControl), []byte(admodel.InternalObjectAssertionControl)},
		}, nil
	}
	identity, _ := admodel.IdentityByDN("OU=application")
	result, err := adservice_organizational_units.New(client).
		SetOrganizationalUnitProtection(context.Background(), identity, true, admodel.ObjectMutationOptions{})
	if err != nil || len(session.InternalWrites) != 1 || len(result.Steps) != 1 ||
		result.ProtectedFromAccidentalDeletion == nil ||
		!*result.ProtectedFromAccidentalDeletion {
		t.Fatal(result, err)
	}
	result, err = adservice_organizational_units.New(client).
		SetOrganizationalUnitProtection(context.Background(), identity, false, admodel.ObjectMutationOptions{})
	if err != nil || len(session.InternalWrites) != 2 ||
		result.ProtectedFromAccidentalDeletion == nil ||
		*result.ProtectedFromAccidentalDeletion {
		t.Fatal(result, err)
	}
}

func TestOUProtectionUnknownAndMissingAreNotFalse(t *testing.T) {
	for _, kind := range []string{"opaque", "missing"} {
		client, session := InternalNewOUTestClient(t)
		object := session.InternalObjects["ou=target,dc=example"]
		if kind == "missing" {
			delete(object.Attributes, "ntsecuritydescriptor")
		} else {
			object.Attributes["ntsecuritydescriptor"] = [][]byte{
				InternalOuTestDescriptor([]byte{0x42, 0, 8, 0, 1, 2, 3, 4}),
			}
		}
		result, err := adservice_organizational_units.New(client).
			OrganizationalUnit(context.Background(), InternalOuTestIdentity(), admodel.ResolveIdentityOptions{Properties: []string{"ProtectedFromAccidentalDeletion"}})
		if result.Unit == nil || result.Unit.ProtectedFromAccidentalDeletion != nil ||
			len(session.InternalWrites) != 0 ||
			len(result.Protection.Steps) == 0 {
			t.Fatal(result, err)
		}
		if kind == "missing" && err == nil {
			t.Fatal("unreadable descriptor became success")
		}
	}
}

func TestOUInheritedProtectionCannotBeSilentlyRemoved(t *testing.T) {
	client, session := InternalNewOUTestClient(t)
	object := session.InternalObjects["ou=target,dc=example"]
	object.Attributes["ntsecuritydescriptor"] = [][]byte{
		InternalOuTestDescriptor(
			InternalOuTestACE(1, 0x10, admodel.InternalOuObjectProtectionMask),
		),
	}
	parent := session.InternalObjects["dc=example"]
	parent.Attributes["ntsecuritydescriptor"] = [][]byte{
		InternalOuTestDescriptor(InternalOuTestACE(1, 0, admodel.InternalOuParentProtectionMask)),
	}
	result, err := adservice_organizational_units.New(client).
		SetOrganizationalUnitProtection(context.Background(), InternalOuTestIdentity(), false, admodel.ObjectMutationOptions{})
	if !errors.Is(err, admodel.ErrOUProtection) || len(session.InternalWrites) != 0 ||
		result.ProtectedFromAccidentalDeletion != nil {
		t.Fatal(result, err)
	}
}

func TestOUProtectionNoOpCannotEnforceExpectedVersion(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		client, session := InternalNewOUTestClient(t)
		originalRead := session.InternalRead
		session.InternalRead = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
			root, err := originalRead(ctx, properties)
			root["supportedcontrol"] = append(
				root["supportedcontrol"],
				[]byte(admodel.InternalObjectAssertionControl),
			)
			return root, err
		}
		object := session.InternalObjects["ou=target,dc=example"]
		if inherited {
			object.Attributes["ntsecuritydescriptor"] = [][]byte{
				InternalOuTestDescriptor(
					InternalOuTestACE(1, 0x10, admodel.InternalOuObjectProtectionMask),
				),
			}
			session.InternalObjects["dc=example"].Attributes["ntsecuritydescriptor"] = [][]byte{
				InternalOuTestDescriptor(
					InternalOuTestACE(1, 0, admodel.InternalOuParentProtectionMask),
				),
			}
		}
		value, _ := object.Values("objectGUID").Single()
		guid, _ := value.GUID()
		result, err := adservice_organizational_units.New(client).
			SetOrganizationalUnitProtection(context.Background(), InternalOuTestIdentity(), false, admodel.ObjectMutationOptions{ExpectedVersion: &admodel.ObjectVersion{Source: (*adengine.InternalClientConfigPointer(client)).Endpoint, GUID: guid, USNChanged: 7}})
		if !errors.Is(err, admodel.ErrObjectControlUnsupported) ||
			len(session.InternalWrites) != 0 ||
			result.ProtectedFromAccidentalDeletion != nil {
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
	client, session := InternalNewOUTestClient(t)
	partial := &admodel.LDAPError{Code: 4}
	session.InternalSearch = func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if query.Base != "DC=example" || query.Scope != admodel.ScopeSubtree ||
			query.Filter != `(&(objectClass=organizationalUnit)(name=a\2a\29\28name=\2a\29))` {
			t.Fatalf("wrong bounded query: %+v", query)
		}
		object := session.InternalObjects["ou=target,dc=example"]
		object.Attributes["description"] = [][]byte{{0xff, 0}}
		return InternalTestSearchCursor{
			InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
				return []admodel.Object{object}, false, partial
			},
			InternalFinish: func() error { return nil },
		}, nil
	}
	result, err := adservice_organizational_units.New(client).
		OrganizationalUnits(context.Background(), admodel.SearchOptions{Scope: admodel.ScopeSubtree, TypedFilter: admodel.FilterEqual("name", admodel.FilterText("a*)(name=*)"))})
	if !errors.Is(err, partial) || result.Observation.Complete || len(result.Units) != 1 ||
		result.Units[0].Description != nil ||
		!slices.Equal(result.Units[0].Raw.Attributes["description"][0], []byte{0xff, 0}) {
		t.Fatal(result, err)
	}
}
