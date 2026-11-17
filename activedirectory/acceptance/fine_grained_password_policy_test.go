package acceptance

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_password_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/password_policies"
)

func InternalFgppPointer[T any](value T) *T { return &value }
func InternalFgppTestSettings() admodel.FineGrainedPasswordPolicySettings {
	return admodel.FineGrainedPasswordPolicySettings{
		Precedence:                  InternalFgppPointer(int32(10)),
		ComplexityEnabled:           InternalFgppPointer(true),
		ReversibleEncryptionEnabled: InternalFgppPointer(false),
		PasswordHistoryCount:        InternalFgppPointer(uint16(24)),
		MinPasswordLength:           InternalFgppPointer(uint16(12)),
		LockoutThreshold:            InternalFgppPointer(uint16(5)),
		MinPasswordAge:              InternalFgppPointer(admodel.PolicyInterval(0)),
		MaxPasswordAge:              InternalFgppPointer(admodel.PolicyInterval(10000000)),
		LockoutDuration:             InternalFgppPointer(admodel.PolicyInterval(300000000)),
		LockoutObservationWindow:    InternalFgppPointer(admodel.PolicyInterval(300000000)),
	}
}

const InternalFgppTestDN = "CN=policy,CN=Password Settings Container,CN=System,DC=example"

func InternalFgppTestIdentity() admodel.Identity {
	identity, _ := admodel.IdentityByDN(InternalFgppTestDN)
	return identity
}

func InternalFgppTestObject(dn string, id byte) admodel.Object {
	object := InternalOuTestObject(dn, "msDS-PasswordSettings", id)
	changes, _ := admodel.InternalFineGrainedSettingsChanges(InternalFgppTestSettings(), true)
	for _, change := range changes {
		object.Attributes[strings.ToLower(change.Attribute)] = [][]byte{change.Values[0].Bytes()}
	}
	object.Attributes["name"] = [][]byte{[]byte("policy")}
	return object
}

type InternalFgppTestSession struct {
	*InternalOuTestSession
	InternalRanges     func(context.Context, string, []string) (map[string][][]byte, error)
	InternalRangeCalls int
}

func (s *InternalFgppTestSession) InternalRangedBaseObject(
	ctx context.Context,
	dn string,
	properties []string,
) (map[string][][]byte, error) {
	s.InternalRangeCalls++
	if s.InternalRanges != nil {
		return s.InternalRanges(ctx, dn, properties)
	}
	object, _ := s.InternalLookup(dn)
	attrs := map[string][][]byte{
		"objectguid": object.Attributes["objectguid"],
		"usnchanged": object.Attributes["usnchanged"],
	}
	if values, ok := object.Attributes["msds-psoappliesto"]; ok {
		attrs["msds-psoappliesto"] = values
	}
	return attrs, nil
}

func (s *InternalFgppTestSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	if len(request.InternalModifications) != 1 ||
		!strings.EqualFold(
			request.InternalModifications[0].InternalAttribute,
			"msDS-PSOAppliesTo",
		) {
		attempt := s.InternalOuTestSession.InternalLdapWrite(ctx, request)
		if request.InternalOperation == admodel.InternalLdapWriteAdd &&
			attempt.State == admodel.InternalLdapWriteAccepted {
			object := s.InternalObjects[strings.ToLower(request.InternalDn)]
			object.Attributes["name"] = object.Attributes["cn"]
		}
		return attempt
	}
	s.InternalWrites = append(s.InternalWrites, request)
	if s.InternalFailAt == len(s.InternalWrites) {
		return s.InternalFailure
	}
	object, ok := s.InternalLookup(request.InternalDn)
	if !ok {
		return admodel.InternalLdapWriteAttempt{
			State: admodel.InternalLdapWriteRejected,
			Err:   &admodel.LDAPError{Code: 32},
		}
	}
	values := slices.Clone(object.Attributes["msds-psoappliesto"])
	for _, reference := range request.InternalModifications[0].InternalValues {
		subject, ok := s.InternalLookup(string(reference))
		if !ok {
			return admodel.InternalLdapWriteAttempt{
				State: admodel.InternalLdapWriteRejected,
				Err:   &admodel.LDAPError{Code: 32},
			}
		}
		at := slices.IndexFunc(
			values,
			func(value []byte) bool { return strings.EqualFold(string(value), subject.DistinguishedName) },
		)
		if request.InternalModifications[0].InternalOperation == 0 {
			if at >= 0 {
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: 20},
				}
			}
			values = append(values, []byte(subject.DistinguishedName))
		} else {
			if at < 0 {
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: 16},
				}
			}
			values = slices.Delete(values, at, at+1)
		}
	}
	attrs := make(map[string][][]byte, len(object.Attributes))
	for name, value := range object.Attributes {
		attrs[name] = value
	}
	attrs["msds-psoappliesto"] = values
	object.Attributes = attrs
	s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
	return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
}

func InternalNewFGPPTestClient(t *testing.T) (*adengine.Client, *InternalFgppTestSession) {
	client, base := InternalNewOUTestClient(t)
	base.InternalObjects[strings.ToLower(admodel.InternalFineGrainedPolicyContainer("DC=example"))] = InternalOuTestObject(
		admodel.InternalFineGrainedPolicyContainer("DC=example"),
		"msDS-PasswordSettingsContainer",
		5,
	)
	base.InternalObjects[strings.ToLower(InternalFgppTestDN)] = InternalFgppTestObject(
		InternalFgppTestDN,
		6,
	)
	user := InternalOuTestObject("CN=user,DC=example", "user", 7)
	user.Attributes["useraccountcontrol"] = [][]byte{[]byte("512")}
	base.InternalObjects["cn=user,dc=example"] = user
	group := InternalOuTestObject("CN=group,DC=example", "group", 8)
	group.Attributes["grouptype"] = [][]byte{[]byte("-2147483646")}
	base.InternalObjects["cn=group,dc=example"] = group
	read := base.InternalRead
	base.InternalRead = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
		root, err := read(ctx, properties)
		root["domainfunctionality"] = [][]byte{[]byte("7")}
		return root, err
	}
	search := base.InternalSearch
	base.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if strings.Contains(query.Filter, "lDAPDisplayName=msDS-PasswordSettings") {
			return InternalObjectTestCursor(
				admodel.Object{
					Attributes: map[string][][]byte{
						"rdnattid":            {[]byte("cn")},
						"objectclasscategory": {[]byte("1")},
					},
				},
			), nil
		}
		if query.Base == admodel.InternalFineGrainedPolicyContainer("DC=example") &&
			query.Scope == admodel.ScopeOneLevel {
			var policies []admodel.Object
			for _, object := range base.InternalObjects {
				if admodel.InternalFineGrainedPolicyClass(object) == nil {
					policies = append(policies, object)
				}
			}
			return InternalObjectTestCursor(policies...), nil
		}
		return search(ctx, query)
	}
	session := &InternalFgppTestSession{InternalOuTestSession: base}
	(*adengine.InternalClientSessionPointer(client)) = session
	return client, session
}

func TestFineGrainedPolicyTypedLifecycleAndNativeValues(t *testing.T) {
	client, session := InternalNewFGPPTestClient(t)
	settings := InternalFgppTestSettings()
	settings.MaxPasswordAge = InternalFgppPointer(admodel.PolicyInterval(0))
	created, err := adservice_password_policies.New(client).
		CreateFineGrainedPasswordPolicy(context.Background(), admodel.CreateFineGrainedPasswordPolicyRequest{Name: "新, policy", Settings: settings})
	if err != nil || !created.Mutation.Verified || created.Policy == nil ||
		created.Policy.Settings.MaxPasswordAge == nil ||
		*created.Policy.Settings.MaxPasswordAge != admodel.PolicyNever {
		t.Fatal(created, err)
	}
	if len(session.InternalWrites) != 1 ||
		session.InternalWrites[0].InternalOperation != admodel.InternalLdapWriteAdd ||
		session.InternalWrites[0].InternalDn != `cn=新\, policy,CN=Password Settings Container,CN=System,DC=example` {
		t.Fatal(session.InternalWrites)
	}
	update, err := adservice_password_policies.New(client).
		UpdateFineGrainedPasswordPolicy(context.Background(), admodel.UpdateFineGrainedPasswordPolicyRequest{Identity: InternalFgppTestIdentity(), Settings: admodel.FineGrainedPasswordPolicySettings{PasswordHistoryCount: InternalFgppPointer(uint16(10)), MinPasswordAge: InternalFgppPointer(admodel.PolicyInterval(1))}})
	if err != nil || !update.Mutation.Verified || len(session.InternalWrites) != 2 ||
		len(session.InternalWrites[1].InternalModifications) != 2 ||
		*update.Policy.Settings.MinPasswordAge != 1 {
		t.Fatal(update, err)
	}
	deleted, err := adservice_password_policies.New(client).
		DeleteFineGrainedPasswordPolicy(context.Background(), InternalFgppTestIdentity(), admodel.ObjectMutationOptions{})
	if err != nil || !deleted.Verified || !deleted.AbsentAfter ||
		len(session.InternalWrites) != 3 ||
		session.InternalWrites[2].InternalOperation != admodel.InternalLdapWriteDelete {
		t.Fatal(deleted, err)
	}
}

func TestFineGrainedPolicyCreationSharesOneDeadline(t *testing.T) {
	client, session := InternalNewFGPPTestClient(t)
	read := session.InternalRead
	var first time.Time
	reads := 0
	session.InternalRead = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
		reads++
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("unbounded creation stage")
		}
		if first.IsZero() {
			first = deadline
		} else if !deadline.Equal(first) {
			t.Fatalf("creation restarted timeout: first=%v later=%v", first, deadline)
		}
		return read(ctx, properties)
	}
	result, err := adservice_password_policies.New(client).
		CreateFineGrainedPasswordPolicy(context.Background(), admodel.CreateFineGrainedPasswordPolicyRequest{Name: "bounded", Settings: InternalFgppTestSettings()})
	if err != nil || !result.Mutation.Verified || reads < 2 || len(session.InternalWrites) != 1 {
		t.Fatal(result, err, reads)
	}
}

func TestFineGrainedPolicyIntervalsAndValidation(t *testing.T) {
	for _, value := range []admodel.PolicyInterval{0, 1, admodel.PolicyInterval(math.MaxInt64), admodel.PolicyNever} {
		wire := admodel.InternalFormatPolicyInterval(value)
		actual, err := admodel.InternalParsePolicyInterval(wire)
		if err != nil || actual != value {
			t.Fatal(value, wire, actual, err)
		}
	}
	if _, err := admodel.PolicyIntervalFromDuration(
		time.Nanosecond,
	); !errors.Is(
		err,
		admodel.ErrPolicyIntervalRange,
	) {
		t.Fatal(err)
	}
	for _, change := range []func(*admodel.FineGrainedPasswordPolicySettings){func(s *admodel.FineGrainedPasswordPolicySettings) { s.Precedence = InternalFgppPointer(int32(0)) }, func(s *admodel.FineGrainedPasswordPolicySettings) {
		s.PasswordHistoryCount = InternalFgppPointer(uint16(1025))
	}, func(s *admodel.FineGrainedPasswordPolicySettings) {
		s.MinPasswordLength = InternalFgppPointer(uint16(257))
	}, func(s *admodel.FineGrainedPasswordPolicySettings) { s.MinPasswordAge = s.MaxPasswordAge }, func(s *admodel.FineGrainedPasswordPolicySettings) {
		s.LockoutDuration = InternalFgppPointer(admodel.PolicyInterval(1))
	}, func(s *admodel.FineGrainedPasswordPolicySettings) { s.ComplexityEnabled = nil }} {
		client, session := InternalNewFGPPTestClient(t)
		settings := InternalFgppTestSettings()
		change(&settings)
		_, err := adservice_password_policies.New(client).
			CreateFineGrainedPasswordPolicy(context.Background(), admodel.CreateFineGrainedPasswordPolicyRequest{Name: "invalid", Settings: settings})
		if err == nil || len(session.InternalWrites) != 0 {
			t.Fatal(settings, err)
		}
	}
	object := InternalFgppTestObject(InternalFgppTestDN, 6)
	delete(object.Attributes, "msds-minimumpasswordage")
	object.Attributes["msds-lockoutduration"] = [][]byte{[]byte("-9223372036854775808")}
	policy, err := admodel.InternalDecodeFineGrainedPolicy(object)
	if err != nil || policy.Settings.MinPasswordAge != nil ||
		policy.Settings.LockoutDuration == nil ||
		*policy.Settings.LockoutDuration != admodel.PolicyNever {
		t.Fatal(policy, err)
	}
}

func TestFineGrainedPolicyCapabilityAndSubjectGuards(t *testing.T) {
	for _, mode := range []string{"lds", "old-dfl", "gc", "other-partition"} {
		client, session := InternalNewFGPPTestClient(t)
		read := session.InternalRead
		session.InternalRead = func(ctx context.Context, props []string) (map[string][][]byte, error) {
			root, err := read(ctx, props)
			if mode == "lds" {
				root["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
			}
			if mode == "old-dfl" {
				root["domainfunctionality"] = [][]byte{[]byte("2")}
			}
			return root, err
		}
		if mode == "gc" {
			(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268
		}
		options := admodel.ResolveIdentityOptions{}
		if mode == "other-partition" {
			options.Partition = "DC=app"
		}
		_, err := adservice_password_policies.New(client).
			FineGrainedPasswordPolicy(context.Background(), InternalFgppTestIdentity(), options)
		if !errors.Is(err, admodel.ErrFineGrainedPolicyTarget) || len(session.InternalWrites) != 0 {
			t.Fatal(mode, err)
		}
	}
	for _, kind := range []string{"computer", "distribution", "universal", "other-domain"} {
		client, session := InternalNewFGPPTestClient(t)
		identity, _ := admodel.IdentityByDN("CN=user,DC=example")
		switch kind {
		case "computer":
			session.InternalObjects["cn=user,dc=example"].Attributes["useraccountcontrol"] = [][]byte{
				[]byte("4096"),
			}
		case "distribution":
			identity, _ = admodel.IdentityByDN("CN=group,DC=example")
			session.InternalObjects["cn=group,dc=example"].Attributes["grouptype"] = [][]byte{
				[]byte("2"),
			}
		case "universal":
			identity, _ = admodel.IdentityByDN("CN=group,DC=example")
			session.InternalObjects["cn=group,dc=example"].Attributes["grouptype"] = [][]byte{
				[]byte("-2147483640"),
			}
		case "other-domain":
			identity, _ = admodel.IdentityByDN("CN=user,DC=app")
		}
		_, err := adservice_password_policies.New(client).
			AddFineGrainedPasswordPolicySubjects(context.Background(), admodel.FineGrainedPolicySubjectsRequest{Identity: InternalFgppTestIdentity(), Subjects: []admodel.Identity{identity}})
		if err == nil || len(session.InternalWrites) != 0 {
			t.Fatal(kind, err)
		}
	}
}

func TestFineGrainedPolicySubjectsAtomicStrictAndNoReplay(t *testing.T) {
	client, session := InternalNewFGPPTestClient(t)
	user, _ := admodel.IdentityByDN("CN=user,DC=example")
	group, _ := admodel.IdentityByDN("CN=group,DC=example")
	request := admodel.FineGrainedPolicySubjectsRequest{
		Identity: InternalFgppTestIdentity(),
		Subjects: []admodel.Identity{user, group},
	}
	result, err := adservice_password_policies.New(client).
		AddFineGrainedPasswordPolicySubjects(context.Background(), request)
	if err != nil || !result.Mutation.Verified || !result.After.Complete ||
		len(result.After.Subjects) != 2 ||
		len(session.InternalWrites) != 1 ||
		len(session.InternalWrites[0].InternalModifications) != 1 ||
		len(session.InternalWrites[0].InternalModifications[0].InternalValues) != 2 {
		t.Fatal(result, err)
	}
	for _, value := range session.InternalWrites[0].InternalModifications[0].InternalValues {
		if !strings.HasPrefix(string(value), "<GUID=") {
			t.Fatal("unstable subject reference", string(value))
		}
	}
	_, err = adservice_password_policies.New(client).
		AddFineGrainedPasswordPolicySubjects(context.Background(), request)
	var native *admodel.LDAPError
	if !errors.As(err, &native) || native.Code != 20 || len(session.InternalWrites) != 2 {
		t.Fatal(err)
	}
	result, err = adservice_password_policies.New(client).
		RemoveFineGrainedPasswordPolicySubjects(context.Background(), admodel.FineGrainedPolicySubjectsRequest{Identity: InternalFgppTestIdentity(), Subjects: []admodel.Identity{user}})
	if err != nil || !result.Mutation.Verified || len(result.After.Subjects) != 1 ||
		result.After.Subjects[0].DistinguishedName != group.String() {
		t.Fatal(result, err)
	}
	for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain} {
		client, s := InternalNewFGPPTestClient(t)
		s.InternalFailAt = 1
		s.InternalFailure = admodel.InternalLdapWriteAttempt{
			State: state,
			Err:   &admodel.LDAPError{Code: 50},
		}
		result, err := adservice_password_policies.New(client).
			AddFineGrainedPasswordPolicySubjects(context.Background(), request)
		if err == nil || len(s.InternalWrites) != 1 || result.Mutation.Verified {
			t.Fatal(result, err)
		}
		if state == admodel.InternalLdapWriteUncertain &&
			!errors.Is(err, admodel.ErrObjectWriteUncertain) {
			t.Fatal(err)
		}
	}
}

func TestFineGrainedResultantUsesServerSelectionAndRetainsAbsence(t *testing.T) {
	client, session := InternalNewFGPPTestClient(t)
	user, _ := admodel.IdentityByDN("CN=user,DC=example")
	otherDN := "CN=lowest,CN=Password Settings Container,CN=System,DC=example"
	other := InternalFgppTestObject(otherDN, 9)
	other.Attributes["msds-passwordsettingsprecedence"] = [][]byte{[]byte("1")}
	session.InternalObjects[strings.ToLower(otherDN)] = other
	session.InternalObjects["cn=user,dc=example"].Attributes["msds-resultantpso"] = [][]byte{
		[]byte(InternalFgppTestDN),
	}
	result, err := adservice_password_policies.New(client).
		UserResultantPasswordPolicy(context.Background(), user, admodel.ResolveIdentityOptions{})
	if err != nil || !result.Complete || result.PolicyDN == nil ||
		*result.PolicyDN != InternalFgppTestDN ||
		result.Policy.Policy == nil ||
		*result.Policy.Policy.Settings.Precedence != 10 {
		t.Fatal(result, err)
	}
	delete(session.InternalObjects["cn=user,dc=example"].Attributes, "msds-resultantpso")
	result, err = adservice_password_policies.New(client).
		UserResultantPasswordPolicy(context.Background(), user, admodel.ResolveIdentityOptions{})
	if err != nil || !result.Complete || !result.NotReturned || result.Policy.Policy != nil ||
		result.PolicyDN != nil {
		t.Fatal(result, err)
	}
	session.InternalObjects["cn=user,dc=example"].Attributes["msds-resultantpso"] = [][]byte{
		[]byte("CN=hidden,CN=Password Settings Container,CN=System,DC=example"),
	}
	result, err = adservice_password_policies.New(client).
		UserResultantPasswordPolicy(context.Background(), user, admodel.ResolveIdentityOptions{})
	if err == nil || result.Complete || result.NotReturned || result.PolicyDN == nil ||
		result.User.Object == nil {
		t.Fatal(result, err)
	}
}
