package activedirectory

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

func fgppPointer[T any](value T) *T { return &value }
func fgppTestSettings() FineGrainedPasswordPolicySettings {
	return FineGrainedPasswordPolicySettings{Precedence: fgppPointer(int32(10)), ComplexityEnabled: fgppPointer(true), ReversibleEncryptionEnabled: fgppPointer(false), PasswordHistoryCount: fgppPointer(uint16(24)), MinPasswordLength: fgppPointer(uint16(12)), LockoutThreshold: fgppPointer(uint16(5)), MinPasswordAge: fgppPointer(PolicyInterval(0)), MaxPasswordAge: fgppPointer(PolicyInterval(10000000)), LockoutDuration: fgppPointer(PolicyInterval(300000000)), LockoutObservationWindow: fgppPointer(PolicyInterval(300000000))}
}

const fgppTestDN = "CN=policy,CN=Password Settings Container,CN=System,DC=example"

func fgppTestIdentity() Identity { identity, _ := IdentityByDN(fgppTestDN); return identity }

func fgppTestObject(dn string, id byte) Object {
	object := ouTestObject(dn, "msDS-PasswordSettings", id)
	changes, _ := fineGrainedSettingsChanges(fgppTestSettings(), true)
	for _, change := range changes {
		object.Attributes[strings.ToLower(change.Attribute)] = [][]byte{change.Values[0].Bytes()}
	}
	object.Attributes["name"] = [][]byte{[]byte("policy")}
	return object
}

type fgppTestSession struct {
	*ouTestSession
	ranges     func(context.Context, string, []string) (map[string][][]byte, error)
	rangeCalls int
}

func (s *fgppTestSession) rangedBaseObject(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
	s.rangeCalls++
	if s.ranges != nil {
		return s.ranges(ctx, dn, properties)
	}
	object, _ := s.lookup(dn)
	attrs := map[string][][]byte{"objectguid": object.Attributes["objectguid"], "usnchanged": object.Attributes["usnchanged"]}
	if values, ok := object.Attributes["msds-psoappliesto"]; ok {
		attrs["msds-psoappliesto"] = values
	}
	return attrs, nil
}
func (s *fgppTestSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	if len(request.modifications) != 1 || !strings.EqualFold(request.modifications[0].attribute, "msDS-PSOAppliesTo") {
		attempt := s.ouTestSession.ldapWrite(ctx, request)
		if request.operation == ldapWriteAdd && attempt.State == ldapWriteAccepted {
			object := s.objects[strings.ToLower(request.dn)]
			object.Attributes["name"] = object.Attributes["cn"]
		}
		return attempt
	}
	s.writes = append(s.writes, request)
	if s.failAt == len(s.writes) {
		return s.failure
	}
	object, ok := s.lookup(request.dn)
	if !ok {
		return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 32}}
	}
	values := slices.Clone(object.Attributes["msds-psoappliesto"])
	for _, reference := range request.modifications[0].values {
		subject, ok := s.lookup(string(reference))
		if !ok {
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 32}}
		}
		at := slices.IndexFunc(values, func(value []byte) bool { return strings.EqualFold(string(value), subject.DistinguishedName) })
		if request.modifications[0].operation == 0 {
			if at >= 0 {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 20}}
			}
			values = append(values, []byte(subject.DistinguishedName))
		} else {
			if at < 0 {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 16}}
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
	s.objects[strings.ToLower(object.DistinguishedName)] = object
	return ldapWriteAttempt{State: ldapWriteAccepted}
}

func newFGPPTestClient(t *testing.T) (*Client, *fgppTestSession) {
	client, base := newOUTestClient(t)
	base.objects[strings.ToLower(fineGrainedPolicyContainer("DC=example"))] = ouTestObject(fineGrainedPolicyContainer("DC=example"), "msDS-PasswordSettingsContainer", 5)
	base.objects[strings.ToLower(fgppTestDN)] = fgppTestObject(fgppTestDN, 6)
	user := ouTestObject("CN=user,DC=example", "user", 7)
	user.Attributes["useraccountcontrol"] = [][]byte{[]byte("512")}
	base.objects["cn=user,dc=example"] = user
	group := ouTestObject("CN=group,DC=example", "group", 8)
	group.Attributes["grouptype"] = [][]byte{[]byte("-2147483646")}
	base.objects["cn=group,dc=example"] = group
	read := base.read
	base.read = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
		root, err := read(ctx, properties)
		root["domainfunctionality"] = [][]byte{[]byte("7")}
		return root, err
	}
	search := base.search
	base.search = func(ctx context.Context, query SearchOptions) (searchCursor, error) {
		if strings.Contains(query.Filter, "lDAPDisplayName=msDS-PasswordSettings") {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		if query.Base == fineGrainedPolicyContainer("DC=example") && query.Scope == ScopeOneLevel {
			var policies []Object
			for _, object := range base.objects {
				if fineGrainedPolicyClass(object) == nil {
					policies = append(policies, object)
				}
			}
			return objectTestCursor(policies...), nil
		}
		return search(ctx, query)
	}
	session := &fgppTestSession{ouTestSession: base}
	client.session = session
	return client, session
}

func TestFineGrainedPolicyTypedLifecycleAndNativeValues(t *testing.T) {
	client, session := newFGPPTestClient(t)
	settings := fgppTestSettings()
	settings.MaxPasswordAge = fgppPointer(PolicyInterval(0))
	created, err := client.CreateFineGrainedPasswordPolicy(context.Background(), CreateFineGrainedPasswordPolicyRequest{Name: "新, policy", Settings: settings})
	if err != nil || !created.Mutation.Verified || created.Policy == nil || created.Policy.Settings.MaxPasswordAge == nil || *created.Policy.Settings.MaxPasswordAge != PolicyNever {
		t.Fatal(created, err)
	}
	if len(session.writes) != 1 || session.writes[0].operation != ldapWriteAdd || session.writes[0].dn != `cn=新\, policy,CN=Password Settings Container,CN=System,DC=example` {
		t.Fatal(session.writes)
	}
	update, err := client.UpdateFineGrainedPasswordPolicy(context.Background(), UpdateFineGrainedPasswordPolicyRequest{Identity: fgppTestIdentity(), Settings: FineGrainedPasswordPolicySettings{PasswordHistoryCount: fgppPointer(uint16(10)), MinPasswordAge: fgppPointer(PolicyInterval(1))}})
	if err != nil || !update.Mutation.Verified || len(session.writes) != 2 || len(session.writes[1].modifications) != 2 || *update.Policy.Settings.MinPasswordAge != 1 {
		t.Fatal(update, err)
	}
	deleted, err := client.DeleteFineGrainedPasswordPolicy(context.Background(), fgppTestIdentity(), ObjectMutationOptions{})
	if err != nil || !deleted.Verified || !deleted.AbsentAfter || len(session.writes) != 3 || session.writes[2].operation != ldapWriteDelete {
		t.Fatal(deleted, err)
	}
}

func TestFineGrainedPolicyCreationSharesOneDeadline(t *testing.T) {
	client, session := newFGPPTestClient(t)
	read := session.read
	var first time.Time
	reads := 0
	session.read = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
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
	result, err := client.CreateFineGrainedPasswordPolicy(context.Background(), CreateFineGrainedPasswordPolicyRequest{Name: "bounded", Settings: fgppTestSettings()})
	if err != nil || !result.Mutation.Verified || reads < 2 || len(session.writes) != 1 {
		t.Fatal(result, err, reads)
	}
}

func TestFineGrainedPolicyIntervalsAndValidation(t *testing.T) {
	for _, value := range []PolicyInterval{0, 1, PolicyInterval(math.MaxInt64), PolicyNever} {
		wire := formatPolicyInterval(value)
		actual, err := parsePolicyInterval(wire)
		if err != nil || actual != value {
			t.Fatal(value, wire, actual, err)
		}
	}
	if _, err := PolicyIntervalFromDuration(time.Nanosecond); !errors.Is(err, ErrPolicyIntervalRange) {
		t.Fatal(err)
	}
	for _, change := range []func(*FineGrainedPasswordPolicySettings){func(s *FineGrainedPasswordPolicySettings) { s.Precedence = fgppPointer(int32(0)) }, func(s *FineGrainedPasswordPolicySettings) { s.PasswordHistoryCount = fgppPointer(uint16(1025)) }, func(s *FineGrainedPasswordPolicySettings) { s.MinPasswordLength = fgppPointer(uint16(257)) }, func(s *FineGrainedPasswordPolicySettings) { s.MinPasswordAge = s.MaxPasswordAge }, func(s *FineGrainedPasswordPolicySettings) { s.LockoutDuration = fgppPointer(PolicyInterval(1)) }, func(s *FineGrainedPasswordPolicySettings) { s.ComplexityEnabled = nil }} {
		client, session := newFGPPTestClient(t)
		settings := fgppTestSettings()
		change(&settings)
		_, err := client.CreateFineGrainedPasswordPolicy(context.Background(), CreateFineGrainedPasswordPolicyRequest{Name: "invalid", Settings: settings})
		if err == nil || len(session.writes) != 0 {
			t.Fatal(settings, err)
		}
	}
	object := fgppTestObject(fgppTestDN, 6)
	delete(object.Attributes, "msds-minimumpasswordage")
	object.Attributes["msds-lockoutduration"] = [][]byte{[]byte("-9223372036854775808")}
	policy, err := decodeFineGrainedPolicy(object)
	if err != nil || policy.Settings.MinPasswordAge != nil || policy.Settings.LockoutDuration == nil || *policy.Settings.LockoutDuration != PolicyNever {
		t.Fatal(policy, err)
	}
}

func TestFineGrainedPolicyCapabilityAndSubjectGuards(t *testing.T) {
	for _, mode := range []string{"lds", "old-dfl", "gc", "other-partition"} {
		client, session := newFGPPTestClient(t)
		read := session.read
		session.read = func(ctx context.Context, props []string) (map[string][][]byte, error) {
			root, err := read(ctx, props)
			if mode == "lds" {
				root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			}
			if mode == "old-dfl" {
				root["domainfunctionality"] = [][]byte{[]byte("2")}
			}
			return root, err
		}
		if mode == "gc" {
			client.config.Endpoint.Port = 3268
		}
		options := ResolveIdentityOptions{}
		if mode == "other-partition" {
			options.Partition = "DC=app"
		}
		_, err := client.FineGrainedPasswordPolicy(context.Background(), fgppTestIdentity(), options)
		if !errors.Is(err, ErrFineGrainedPolicyTarget) || len(session.writes) != 0 {
			t.Fatal(mode, err)
		}
	}
	for _, kind := range []string{"computer", "distribution", "universal", "other-domain"} {
		client, session := newFGPPTestClient(t)
		identity, _ := IdentityByDN("CN=user,DC=example")
		switch kind {
		case "computer":
			session.objects["cn=user,dc=example"].Attributes["useraccountcontrol"] = [][]byte{[]byte("4096")}
		case "distribution":
			identity, _ = IdentityByDN("CN=group,DC=example")
			session.objects["cn=group,dc=example"].Attributes["grouptype"] = [][]byte{[]byte("2")}
		case "universal":
			identity, _ = IdentityByDN("CN=group,DC=example")
			session.objects["cn=group,dc=example"].Attributes["grouptype"] = [][]byte{[]byte("-2147483640")}
		case "other-domain":
			identity, _ = IdentityByDN("CN=user,DC=app")
		}
		_, err := client.AddFineGrainedPasswordPolicySubjects(context.Background(), FineGrainedPolicySubjectsRequest{Identity: fgppTestIdentity(), Subjects: []Identity{identity}})
		if err == nil || len(session.writes) != 0 {
			t.Fatal(kind, err)
		}
	}
}

func TestFineGrainedPolicySubjectsAtomicStrictAndNoReplay(t *testing.T) {
	client, session := newFGPPTestClient(t)
	user, _ := IdentityByDN("CN=user,DC=example")
	group, _ := IdentityByDN("CN=group,DC=example")
	request := FineGrainedPolicySubjectsRequest{Identity: fgppTestIdentity(), Subjects: []Identity{user, group}}
	result, err := client.AddFineGrainedPasswordPolicySubjects(context.Background(), request)
	if err != nil || !result.Mutation.Verified || !result.After.Complete || len(result.After.Subjects) != 2 || len(session.writes) != 1 || len(session.writes[0].modifications) != 1 || len(session.writes[0].modifications[0].values) != 2 {
		t.Fatal(result, err)
	}
	for _, value := range session.writes[0].modifications[0].values {
		if !strings.HasPrefix(string(value), "<GUID=") {
			t.Fatal("unstable subject reference", string(value))
		}
	}
	_, err = client.AddFineGrainedPasswordPolicySubjects(context.Background(), request)
	var native *LDAPError
	if !errors.As(err, &native) || native.Code != 20 || len(session.writes) != 2 {
		t.Fatal(err)
	}
	result, err = client.RemoveFineGrainedPasswordPolicySubjects(context.Background(), FineGrainedPolicySubjectsRequest{Identity: fgppTestIdentity(), Subjects: []Identity{user}})
	if err != nil || !result.Mutation.Verified || len(result.After.Subjects) != 1 || result.After.Subjects[0].DistinguishedName != group.String() {
		t.Fatal(result, err)
	}
	for _, state := range []ldapWriteState{ldapWriteRejected, ldapWriteUncertain} {
		client, s := newFGPPTestClient(t)
		s.failAt = 1
		s.failure = ldapWriteAttempt{State: state, Err: &LDAPError{Code: 50}}
		result, err := client.AddFineGrainedPasswordPolicySubjects(context.Background(), request)
		if err == nil || len(s.writes) != 1 || result.Mutation.Verified {
			t.Fatal(result, err)
		}
		if state == ldapWriteUncertain && !errors.Is(err, ErrObjectWriteUncertain) {
			t.Fatal(err)
		}
	}
}

func TestFineGrainedResultantUsesServerSelectionAndRetainsAbsence(t *testing.T) {
	client, session := newFGPPTestClient(t)
	user, _ := IdentityByDN("CN=user,DC=example")
	otherDN := "CN=lowest,CN=Password Settings Container,CN=System,DC=example"
	other := fgppTestObject(otherDN, 9)
	other.Attributes["msds-passwordsettingsprecedence"] = [][]byte{[]byte("1")}
	session.objects[strings.ToLower(otherDN)] = other
	session.objects["cn=user,dc=example"].Attributes["msds-resultantpso"] = [][]byte{[]byte(fgppTestDN)}
	result, err := client.UserResultantPasswordPolicy(context.Background(), user, ResolveIdentityOptions{})
	if err != nil || !result.Complete || result.PolicyDN == nil || *result.PolicyDN != fgppTestDN || result.Policy.Policy == nil || *result.Policy.Policy.Settings.Precedence != 10 {
		t.Fatal(result, err)
	}
	delete(session.objects["cn=user,dc=example"].Attributes, "msds-resultantpso")
	result, err = client.UserResultantPasswordPolicy(context.Background(), user, ResolveIdentityOptions{})
	if err != nil || !result.Complete || !result.NotReturned || result.Policy.Policy != nil || result.PolicyDN != nil {
		t.Fatal(result, err)
	}
	session.objects["cn=user,dc=example"].Attributes["msds-resultantpso"] = [][]byte{[]byte("CN=hidden,CN=Password Settings Container,CN=System,DC=example")}
	result, err = client.UserResultantPasswordPolicy(context.Background(), user, ResolveIdentityOptions{})
	if err == nil || result.Complete || result.NotReturned || result.PolicyDN == nil || result.User.Object == nil {
		t.Fatal(result, err)
	}
}
