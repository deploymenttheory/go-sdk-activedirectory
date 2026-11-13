package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

const centralTestConfiguration = "CN=Configuration,DC=example"

func centralPointer[T any](value T) *T   { return &value }
func centralIdentity(dn string) Identity { identity, _ := IdentityByDN(dn); return identity }

type centralTestSession struct {
	*ouTestSession
	nextID      byte
	rangeRead   func(context.Context, string, []string) (map[string][][]byte, error)
	beforeWrite func()
}

func (s *centralTestSession) validateCentralAccessDescriptor(text string) error {
	if text == "" || text == "BAD" {
		return conditions.ErrInvalidExpression
	}
	return nil
}
func (s *centralTestSession) validateCentralAccessCondition(text string) error {
	if text == "BAD" {
		return conditions.ErrInvalidExpression
	}
	return nil
}
func (s *centralTestSession) rangedBaseObject(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
	if s.rangeRead != nil {
		return s.rangeRead(ctx, dn, properties)
	}
	object, ok := s.lookup(dn)
	if !ok {
		return nil, &LDAPError{Code: 32}
	}
	attribute, _, _ := strings.Cut(strings.ToLower(properties[0]), ";")
	result := map[string][][]byte{"objectguid": object.Attributes["objectguid"], "usnchanged": object.Attributes["usnchanged"]}
	if values, ok := object.Attributes[attribute]; ok {
		result[attribute] = values
	}
	return result, nil
}
func (s *centralTestSession) ldapWrite(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
	if s.beforeWrite != nil {
		s.beforeWrite()
	}
	s.writes = append(s.writes, request)
	if s.failAt == len(s.writes) {
		return s.failure
	}
	reject := func(code uint32) ldapWriteAttempt {
		return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: code, Diagnostic: "directory rejected request"}}
	}
	if request.operation == ldapWriteAdd {
		if _, exists := s.lookup(request.dn); exists {
			return reject(68)
		}
		s.nextID++
		object := ouTestObject(request.dn, "top", s.nextID)
		for _, mod := range request.modifications {
			object.Attributes[strings.ToLower(mod.attribute)] = mod.values
		}
		object.Attributes["name"] = object.Attributes["cn"]
		s.objects[strings.ToLower(request.dn)] = object
		return ldapWriteAttempt{State: ldapWriteAccepted}
	}
	object, ok := s.lookup(request.dn)
	if !ok {
		return reject(32)
	}
	if request.operation == ldapWriteDelete {
		for _, child := range s.objects {
			parent, _ := parentDirectoryDN(child.DistinguishedName)
			if centralSameDN(parent, object.DistinguishedName) {
				return reject(66)
			}
		}
		delete(s.objects, strings.ToLower(object.DistinguishedName))
		return ldapWriteAttempt{State: ldapWriteAccepted}
	}
	attrs := map[string][][]byte{}
	for name, values := range object.Attributes {
		attrs[name] = slices.Clone(values)
	}
	for _, mod := range request.modifications {
		key := strings.ToLower(mod.attribute)
		values := attrs[key]
		switch mod.operation {
		case 2:
			attrs[key] = slices.Clone(mod.values)
		case 0:
			for _, value := range mod.values {
				if slices.ContainsFunc(values, func(prior []byte) bool { return bytes.Equal(prior, value) }) {
					return reject(20)
				}
				values = append(values, value)
			}
			attrs[key] = values
		case 1:
			if len(values) == 0 {
				return reject(16)
			}
			if len(mod.values) == 0 {
				delete(attrs, key)
				continue
			}
			for _, value := range mod.values {
				i := slices.IndexFunc(values, func(prior []byte) bool { return bytes.Equal(prior, value) })
				if i < 0 {
					return reject(16)
				}
				values = slices.Delete(values, i, i+1)
			}
			if len(values) == 0 {
				delete(attrs, key)
			} else {
				attrs[key] = values
			}
		}
	}
	object.Attributes = attrs
	s.objects[strings.ToLower(object.DistinguishedName)] = object
	return ldapWriteAttempt{State: ldapWriteAccepted}
}
func newCentralTestClient(t *testing.T) (*Client, *centralTestSession) {
	t.Helper()
	client, base := newOUTestClient(t)
	session := &centralTestSession{ouTestSession: base, nextID: 10}
	client.session = session
	for i, policy := range []bool{false, true} {
		dn := centralAccessParent(centralTestConfiguration, policy)
		class := "msAuthz-CentralAccessRules"
		if policy {
			class = "msAuthz-CentralAccessPolicies"
		}
		session.objects[strings.ToLower(dn)] = ouTestObject(dn, class, byte(i+5))
	}
	base.read = func(context.Context, []string) (map[string][][]byte, error) {
		root := identityTestRoot(CapabilityActiveDirectory)
		root["configurationnamingcontext"] = [][]byte{[]byte(centralTestConfiguration)}
		root["schemanamingcontext"] = [][]byte{[]byte("CN=Schema," + centralTestConfiguration)}
		root["supportedcontrol"] = [][]byte{[]byte(objectAssertionControl), []byte(ouSDFlagsControl)}
		return root, nil
	}
	base.search = func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if query.Base == "CN=Schema,"+centralTestConfiguration {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		if strings.Contains(query.Filter, "objectGUID=") {
			for _, object := range session.objects {
				guid, _ := centralAccessGUID(object)
				if strings.Contains(query.Filter, identityBinaryLiteral(guid.Bytes())) {
					return objectTestCursor(object), nil
				}
			}
			return objectTestCursor(), nil
		}
		var rows []Object
		for _, object := range session.objects {
			within := centralSameDN(object.DistinguishedName, query.Base)
			if query.Scope == ScopeOneLevel {
				parent, _ := parentDirectoryDN(object.DistinguishedName)
				within = centralSameDN(parent, query.Base)
			}
			if !within {
				continue
			}
			if _, rest, ok := strings.Cut(query.Filter, "(objectClass="); ok {
				class, _, _ := strings.Cut(rest, ")")
				if class != "*" && centralAccessClassCheck(object, class) != nil {
					continue
				}
			}
			rows = append(rows, object)
		}
		return objectTestCursor(rows...), nil
	}
	return client, session
}
func TestCentralAccessLifecycleSeparatesPermissionsConditionsAndIDs(t *testing.T) {
	client, session := newCentralTestClient(t)
	condition := conditions.Compare(conditions.Claim{Scope: conditions.Resource, Name: "Department"}, conditions.Equal, conditions.Text("Finance"))
	proposed := "D:(A;;FR;;;WD)"
	rule, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "Finance", ProposedACL: &proposed, ResourceCondition: &condition})
	if err != nil || !rule.Mutation.Verified || *rule.Rule.CurrentACL != DefaultCentralAccessRuleACL || *rule.Rule.ProposedACL != proposed || rule.Rule.PreviousACL != nil || len(session.writes) != 1 {
		t.Fatal(rule, err)
	}
	identity := objectGUIDIdentity(*rule.Rule.GUID)
	current := "O:SYG:SYD:(XA;;FR;;;WD;(@Resource.Department == \"Finance\"))"
	updated, err := client.UpdateCentralAccessRule(context.Background(), UpdateCentralAccessRuleRequest{Identity: identity, CurrentACL: &current})
	if err != nil || !updated.Mutation.Verified || *updated.Rule.CurrentACL != current || *updated.Rule.PreviousACL != DefaultCentralAccessRuleACL || *updated.Rule.ProposedACL != proposed || *updated.Rule.ResourceCondition != *rule.Rule.ResourceCondition {
		t.Fatal(updated, err)
	}
	mods := session.writes[1].modifications
	if len(mods) != 3 || mods[0].operation != 1 || mods[1].operation != 0 || mods[2].attribute != centralPrevious || string(mods[2].values[0]) != DefaultCentralAccessRuleACL {
		t.Fatal(mods)
	}
	policy, err := client.CreateCentralAccessPolicy(context.Background(), CreateCentralAccessPolicyRequest{Name: "Policy"})
	if err != nil || !policy.Mutation.Verified || !validCentralAccessPolicyID(*policy.Policy.PolicyID) || policy.GeneratedPolicyID.String() != policy.Policy.PolicyID.String() {
		t.Fatal(policy, err)
	}
	policyIdentity := objectGUIDIdentity(*policy.Policy.GUID)
	members, err := client.AddCentralAccessPolicyMembers(context.Background(), CentralAccessPolicyMembersRequest{Identity: policyIdentity, Members: []Identity{identity}})
	if err != nil || !members.Mutation.Verified || len(members.After.References) != 1 {
		t.Fatal(members, err)
	}
	read, err := client.CentralAccessPolicy(context.Background(), policyIdentity, CentralAccessReadOptions{})
	if err != nil || !read.Members.Complete || len(read.Members.References) != 1 {
		t.Fatal(read, err)
	}
	policies, err := client.CentralAccessPolicies(context.Background(), SearchOptions{}, CentralAccessReferenceLimits{})
	if err != nil || len(policies.Policies) != 1 || !policies.Observation.Complete {
		t.Fatal(policies, err)
	}
	removed, err := client.RemoveCentralAccessPolicyMembers(context.Background(), CentralAccessPolicyMembersRequest{Identity: policyIdentity, Members: []Identity{identity}})
	if !errors.Is(err, ErrObjectVerification) || removed.Mutation.State != ObjectWriteAccepted || removed.Mutation.Verified || removed.After.AttributeReturned {
		t.Fatal(removed, err)
	}
	for _, policy := range []bool{true, false} {
		var deleted ObjectMutationResult
		if policy {
			deleted, err = client.DeleteCentralAccessPolicy(context.Background(), policyIdentity, ObjectMutationOptions{})
		} else {
			deleted, err = client.DeleteCentralAccessRule(context.Background(), identity, ObjectMutationOptions{})
		}
		if err != nil || !deleted.Verified || !deleted.AbsentAfter {
			t.Fatal(deleted, err)
		}
	}
}
func TestCentralAccessMembershipLimitDuplicatesAndReferenceClass(t *testing.T) {
	client, s := newCentralTestClient(t)
	rule, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "rule"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := client.CreateCentralAccessPolicy(context.Background(), CreateCentralAccessPolicyRequest{Name: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	identity := objectGUIDIdentity(*policy.Policy.GUID)
	member := objectGUIDIdentity(*rule.Rule.GUID)
	for _, members := range [][]Identity{{member, member}, {identity}, {centralIdentity("CN=outside,DC=elsewhere")}} {
		before := len(s.writes)
		_, err = client.AddCentralAccessPolicyMembers(context.Background(), CentralAccessPolicyMembersRequest{Identity: identity, Members: members})
		if err == nil || len(s.writes) != before {
			t.Fatal(members, err)
		}
	}
	_, err = client.AddCentralAccessPolicyMembers(context.Background(), CentralAccessPolicyMembersRequest{Identity: identity, Members: []Identity{member}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.AddCentralAccessPolicyMembers(context.Background(), CentralAccessPolicyMembersRequest{Identity: identity, Members: []Identity{member}})
	var native *LDAPError
	if !errors.As(err, &native) || native.Code != 20 || result.Mutation.State != ObjectWriteRejected {
		t.Fatal(result, err)
	}
	row := s.objects[strings.ToLower(policy.Mutation.TargetDN)]
	values := make([][]byte, 127)
	for i := range values {
		values[i] = []byte(fmt.Sprintf("CN=rule%d,%s", i, centralAccessParent(centralTestConfiguration, false)))
	}
	row.Attributes[strings.ToLower(centralMembers)] = values
	s.objects[strings.ToLower(row.DistinguishedName)] = row
	before := len(s.writes)
	_, err = client.AddCentralAccessPolicyMembers(context.Background(), CentralAccessPolicyMembersRequest{Identity: identity, Members: []Identity{member}})
	if !errors.Is(err, ErrCentralAccessMemberLimit) || len(s.writes) != before {
		t.Fatal(err, len(s.writes))
	}
	row.Attributes[strings.ToLower(centralMembers)] = values[:126]
	s.objects[strings.ToLower(row.DistinguishedName)] = row
	boundary, err := client.AddCentralAccessPolicyMembers(context.Background(), CentralAccessPolicyMembersRequest{Identity: identity, Members: []Identity{member}})
	if err != nil || !boundary.Mutation.Verified || len(boundary.After.References) != 127 || len(s.writes) != before+1 {
		t.Fatal("the 127th distinct rule was rejected", boundary, err)
	}
}
func TestCentralAccessCurrentACLStaleSnapshotRejectsAtomically(t *testing.T) {
	client, s := newCentralTestClient(t)
	rule, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "rule"})
	if err != nil {
		t.Fatal(err)
	}
	s.beforeWrite = func() {
		row := s.objects[strings.ToLower(rule.Mutation.TargetDN)]
		attrs := map[string][][]byte{}
		for name, values := range row.Attributes {
			attrs[name] = values
		}
		row.Attributes = attrs
		row.Attributes[strings.ToLower(centralCurrent)] = [][]byte{[]byte("D:(A;;GA;;;SY)")}
		s.objects[strings.ToLower(row.DistinguishedName)] = row
	}
	result, err := client.UpdateCentralAccessRule(context.Background(), UpdateCentralAccessRuleRequest{Identity: objectGUIDIdentity(*rule.Rule.GUID), CurrentACL: centralPointer("D:(A;;FR;;;WD)")})
	if err == nil || result.Mutation.State != ObjectWriteRejected || len(s.writes) != 2 {
		t.Fatal(result, err)
	}
	row := s.objects[strings.ToLower(rule.Mutation.TargetDN)]
	if _, found := row.Attributes[strings.ToLower(centralPrevious)]; found {
		t.Fatal("partial atomic update")
	}
}
func TestCentralAccessProtectionPartialAndUnknownWrite(t *testing.T) {
	for _, state := range []ldapWriteState{ldapWriteRejected, ldapWriteUncertain} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			client, s := newCentralTestClient(t)
			s.failAt = 3
			s.failure = ldapWriteAttempt{State: state, Err: &LDAPError{Code: 50}}
			result, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "partial", ProtectedFromAccidentalDeletion: centralPointer(true)})
			if err == nil || result.Mutation.State != ObjectWriteAccepted || len(s.writes) != 3 || len(result.Protection.Steps) != 2 || result.Protection.Steps[0].State != ObjectWriteAccepted || result.Protection.Steps[1].Verified {
				t.Fatal(result, err)
			}
		})
	}
}
func TestCentralAccessInvalidExpressionsAndManagedRawChangesNoWrite(t *testing.T) {
	client, s := newCentralTestClient(t)
	bad := conditions.Raw("BAD")
	for _, request := range []CreateCentralAccessRuleRequest{{Name: "bad", CurrentACL: centralPointer("BAD")}, {Name: "bad", ProposedACL: centralPointer("BAD")}, {Name: "bad", ResourceCondition: &bad}} {
		_, err := client.CreateCentralAccessRule(context.Background(), request)
		if !errors.Is(err, conditions.ErrInvalidExpression) || len(s.writes) != 0 {
			t.Fatal(err, s.writes)
		}
	}
	_, err := client.UpdateCentralAccessRule(context.Background(), UpdateCentralAccessRuleRequest{Identity: centralIdentity("CN=rule," + centralAccessParent(centralTestConfiguration, false)), Changes: []AttributeChange{{Attribute: centralCurrent, Kind: AttributeClear}}})
	if !errors.Is(err, ErrCentralAccess) || len(s.writes) != 0 {
		t.Fatal(err)
	}
}
func TestCentralAccessMissingLDSAndDeletionFailures(t *testing.T) {
	client, s := newCentralTestClient(t)
	_, err := client.DeleteCentralAccessRule(context.Background(), centralIdentity("CN=missing,"+centralAccessParent(centralTestConfiguration, false)), ObjectMutationOptions{})
	if err == nil || len(s.writes) != 0 {
		t.Fatal(err)
	}
	rule, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "protected"})
	if err != nil {
		t.Fatal(err)
	}
	s.failAt = 2
	s.failure = ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50, Diagnostic: "protected rule"}}
	deleted, err := client.DeleteCentralAccessRule(context.Background(), objectGUIDIdentity(*rule.Rule.GUID), ObjectMutationOptions{})
	var native *LDAPError
	if !errors.As(err, &native) || native.Code != 50 || native.Diagnostic != "protected rule" || deleted.State != ObjectWriteRejected || deleted.AbsentAfter || len(s.writes) != 2 {
		t.Fatal(deleted, err)
	}
	original := s.read
	s.read = func(ctx context.Context, attrs []string) (map[string][][]byte, error) {
		root, e := original(ctx, attrs)
		root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
		return root, e
	}
	_, err = client.CreateCentralAccessPolicy(context.Background(), CreateCentralAccessPolicyRequest{Name: "LDS"})
	if !errors.Is(err, ErrUnsupported) || len(s.writes) != 2 {
		t.Fatal(err)
	}
}
func TestCentralAccessRangeFailuresRetainRaw(t *testing.T) {
	for _, kind := range []string{"permission", "gap", "changed", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			client, s := newCentralTestClient(t)
			policy, err := client.CreateCentralAccessPolicy(context.Background(), CreateCentralAccessPolicyRequest{Name: "policy"})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			s.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				calls++
				attrs := map[string][][]byte{"objectguid": policy.Mutation.After.Attributes["objectguid"], "usnchanged": {[]byte("7")}}
				if calls == 1 {
					attrs[centralMembers+";range=0-0"] = [][]byte{[]byte("CN=one," + centralAccessParent(centralTestConfiguration, false))}
					return attrs, nil
				}
				attrs[centralMembers+";range=1-*"] = [][]byte{[]byte("CN=two," + centralAccessParent(centralTestConfiguration, false))}
				switch kind {
				case "permission":
					return attrs, &LDAPError{Code: 50}
				case "gap":
					delete(attrs, centralMembers+";range=1-*")
					attrs[centralMembers+";range=2-*"] = [][]byte{[]byte("CN=two," + centralAccessParent(centralTestConfiguration, false))}
				case "changed":
					attrs["usnchanged"] = [][]byte{[]byte("8")}
				case "duplicate":
					attrs[centralMembers+";range=1-*"] = [][]byte{[]byte("CN=ONE," + centralAccessParent(centralTestConfiguration, false))}
				}
				return attrs, nil
			}
			result, err := client.CentralAccessPolicy(context.Background(), objectGUIDIdentity(*policy.Policy.GUID), CentralAccessReadOptions{})
			if err == nil || result.Members.Complete || len(result.Members.Ranges) != 2 || len(result.Members.References) != 2 {
				t.Fatal(result, err)
			}
		})
	}
}

func TestCentralAccessNoOpPropertiesAndVersionPreconditions(t *testing.T) {
	client, s := newCentralTestClient(t)
	created, err := client.CreateCentralAccessPolicy(context.Background(), CreateCentralAccessPolicyRequest{Name: "properties"})
	if err != nil {
		t.Fatal(err)
	}
	row := s.objects[strings.ToLower(created.Mutation.TargetDN)]
	row.Attributes["displayname"] = [][]byte{[]byte("retained")}
	s.objects[strings.ToLower(row.DistinguishedName)] = row
	search := s.search
	selected := false
	s.search = func(ctx context.Context, query SearchOptions) (searchCursor, error) {
		selected = slices.Contains(query.Properties, "displayName")
		return search(ctx, query)
	}
	identity := objectGUIDIdentity(*created.Policy.GUID)
	result, err := client.UpdateCentralAccessPolicy(context.Background(), UpdateCentralAccessPolicyRequest{Identity: identity, Options: ObjectMutationOptions{Properties: []string{"displayName"}}})
	if err != nil || !selected || !result.Mutation.Verified || result.Mutation.State != ObjectWriteNotAttempted || len(result.Policy.Raw.Attributes["displayname"]) != 1 || len(s.writes) != 1 {
		t.Fatal(result, err, selected)
	}
	for _, protect := range []*bool{nil, centralPointer(false), centralPointer(true)} {
		result, err := client.UpdateCentralAccessPolicy(context.Background(), UpdateCentralAccessPolicyRequest{Identity: identity, ProtectedFromAccidentalDeletion: protect, Options: ObjectMutationOptions{ExpectedVersion: &ObjectVersion{Source: client.config.Endpoint, GUID: *created.Policy.GUID, USNChanged: 7}}})
		if !errors.Is(err, ErrObjectControlUnsupported) || result.Mutation.State != ObjectWriteNotAttempted || len(s.writes) != 1 {
			t.Fatal(result, err)
		}
	}
}

func TestCentralAccessMembershipPreservesOthersAndAcceptedReadbackFailure(t *testing.T) {
	client, s := newCentralTestClient(t)
	first, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "second"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := client.CreateCentralAccessPolicy(context.Background(), CreateCentralAccessPolicyRequest{Name: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	request := CentralAccessPolicyMembersRequest{Identity: objectGUIDIdentity(*policy.Policy.GUID), Members: []Identity{objectGUIDIdentity(*first.Rule.GUID), objectGUIDIdentity(*second.Rule.GUID)}}
	added, err := client.AddCentralAccessPolicyMembers(context.Background(), request)
	if err != nil || !added.Mutation.Verified {
		t.Fatal(added, err)
	}
	request.Members = request.Members[:1]
	removed, err := client.RemoveCentralAccessPolicyMembers(context.Background(), request)
	if err != nil || !removed.Mutation.Verified || len(removed.After.References) != 1 || !centralSameDN(removed.After.References[0].DistinguishedName, second.Mutation.TargetDN) {
		t.Fatal(removed, err)
	}
	reads := 0
	s.rangeRead = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
		reads++
		fn := s.rangeRead
		s.rangeRead = nil
		attrs, e := s.rangedBaseObject(ctx, dn, properties)
		s.rangeRead = fn
		if reads == 2 {
			e = &LDAPError{Code: 50}
		}
		return attrs, e
	}
	before := len(s.writes)
	result, err := client.AddCentralAccessPolicyMembers(context.Background(), request)
	if !errors.Is(err, ErrObjectReadback) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || len(result.After.References) != 2 || result.After.Complete || len(s.writes) != before+1 {
		t.Fatal(result, err)
	}
}

func TestCentralAccessGeneratedIDAndAbsentDecodeRemainExplicit(t *testing.T) {
	ids := map[string]bool{}
	for _, state := range []ldapWriteState{ldapWriteRejected, ldapWriteUncertain} {
		client, s := newCentralTestClient(t)
		s.failAt = 1
		s.failure = ldapWriteAttempt{State: state, Err: &LDAPError{Code: 50}}
		result, err := client.CreateCentralAccessPolicy(context.Background(), CreateCentralAccessPolicyRequest{Name: "unknown"})
		if err == nil || result.GeneratedPolicyID == nil || !validCentralAccessPolicyID(*result.GeneratedPolicyID) || len(s.writes) != 1 || ids[result.GeneratedPolicyID.String()] {
			t.Fatal(result, err)
		}
		ids[result.GeneratedPolicyID.String()] = true
	}
	object := ouTestObject("CN=policy,"+centralAccessParent(centralTestConfiguration, true), centralAccessClass(true), 88)
	decoded, err := decodeCentralAccessPolicy(object)
	if err != nil || decoded.PolicyID != nil {
		t.Fatal(decoded, err)
	}
	object.Attributes[strings.ToLower(centralPolicyID)] = [][]byte{{1, 4, 0}}
	decoded, err = decodeCentralAccessPolicy(object)
	if err == nil || decoded.PolicyID != nil || len(decoded.Raw.Attributes[strings.ToLower(centralPolicyID)]) != 1 {
		t.Fatal(decoded, err)
	}
}

func TestCentralAccessClearPermissionsKeepsHistoryButOmissionIsUnverified(t *testing.T) {
	client, s := newCentralTestClient(t)
	rule, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "clear"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UpdateCentralAccessRule(context.Background(), UpdateCentralAccessRuleRequest{Identity: objectGUIDIdentity(*rule.Rule.GUID), ClearCurrentACL: true})
	if !errors.Is(err, ErrObjectVerification) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || result.Rule.CurrentACL != nil || *result.Rule.PreviousACL != DefaultCentralAccessRuleACL || len(s.writes) != 2 {
		t.Fatal(result, err)
	}
}

func TestCentralAccessRangeBudgetsAndCancellationRetainBatch(t *testing.T) {
	client, s := newCentralTestClient(t)
	policy, err := client.CreateCentralAccessPolicy(context.Background(), CreateCentralAccessPolicyRequest{Name: "budget"})
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string][][]byte{"objectguid": policy.Mutation.After.Attributes["objectguid"], "usnchanged": {[]byte("7")}, centralMembers: {[]byte("CN=one," + centralAccessParent(centralTestConfiguration, false)), []byte("CN=two," + centralAccessParent(centralTestConfiguration, false))}}
	for _, kind := range []string{"bytes", "count", "cancel", "complete"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				if kind == "cancel" {
					cancel()
				}
				return attrs, nil
			}
			limits, _ := normalizeCentralAccessLimits(CentralAccessReferenceLimits{})
			if kind == "bytes" {
				limits.MaxBytes = 1
			}
			if kind == "count" {
				limits.MaxReferences = 1
			}
			result, err := readCentralAccessReferences(ctx, s, *policy.Mutation.After, centralMembers, limits)
			if len(result.Ranges) != 1 || len(result.Ranges[0].Attributes[centralMembers]) != 2 {
				t.Fatal(result)
			}
			if kind == "complete" {
				if err != nil || !result.Complete || len(result.References) != 2 {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || result.Complete {
				t.Fatal(result, err)
			}
			if kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
	limits, err := normalizeCentralAccessLimits(CentralAccessReferenceLimits{MaxReferences: 100001, MaxRanges: 1001, MaxBytes: (64 << 20) + 1})
	if err != nil || limits.MaxReferences != 100001 || limits.MaxRanges != 1001 || limits.MaxBytes != (64<<20)+1 {
		t.Fatal(limits, err)
	}
}
