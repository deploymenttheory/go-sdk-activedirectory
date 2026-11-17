package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_central_access "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

const InternalCentralTestConfiguration = "CN=Configuration,DC=example"

func InternalCentralPointer[T any](value T) *T { return &value }
func InternalCentralIdentity(dn string) admodel.Identity {
	identity, _ := admodel.IdentityByDN(dn)
	return identity
}

type InternalCentralTestSession struct {
	*InternalOuTestSession
	InternalNextID      byte
	InternalRangeRead   func(context.Context, string, []string) (map[string][][]byte, error)
	InternalBeforeWrite func()
}

func (s *InternalCentralTestSession) InternalValidateCentralAccessDescriptor(text string) error {
	if text == "" || text == "BAD" {
		return conditions.ErrInvalidExpression
	}
	return nil
}

func (s *InternalCentralTestSession) InternalValidateCentralAccessCondition(text string) error {
	if text == "BAD" {
		return conditions.ErrInvalidExpression
	}
	return nil
}

func (s *InternalCentralTestSession) InternalRangedBaseObject(
	ctx context.Context,
	dn string,
	properties []string,
) (map[string][][]byte, error) {
	if s.InternalRangeRead != nil {
		return s.InternalRangeRead(ctx, dn, properties)
	}
	object, ok := s.InternalLookup(dn)
	if !ok {
		return nil, &admodel.LDAPError{Code: 32}
	}
	attribute, _, _ := strings.Cut(strings.ToLower(properties[0]), ";")
	result := map[string][][]byte{
		"objectguid": object.Attributes["objectguid"],
		"usnchanged": object.Attributes["usnchanged"],
	}
	if values, ok := object.Attributes[attribute]; ok {
		result[attribute] = values
	}
	return result, nil
}

func (s *InternalCentralTestSession) InternalLdapWrite(
	_ context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	if s.InternalBeforeWrite != nil {
		s.InternalBeforeWrite()
	}
	s.InternalWrites = append(s.InternalWrites, request)
	if s.InternalFailAt == len(s.InternalWrites) {
		return s.InternalFailure
	}
	reject := func(code uint32) admodel.InternalLdapWriteAttempt {
		return admodel.InternalLdapWriteAttempt{
			State: admodel.InternalLdapWriteRejected,
			Err:   &admodel.LDAPError{Code: code, Diagnostic: "directory rejected request"},
		}
	}
	if request.InternalOperation == admodel.InternalLdapWriteAdd {
		if _, exists := s.InternalLookup(request.InternalDn); exists {
			return reject(68)
		}
		s.InternalNextID++
		object := InternalOuTestObject(request.InternalDn, "top", s.InternalNextID)
		for _, mod := range request.InternalModifications {
			object.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
		}
		object.Attributes["name"] = object.Attributes["cn"]
		s.InternalObjects[strings.ToLower(request.InternalDn)] = object
		return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
	}
	object, ok := s.InternalLookup(request.InternalDn)
	if !ok {
		return reject(32)
	}
	if request.InternalOperation == admodel.InternalLdapWriteDelete {
		for _, child := range s.InternalObjects {
			parent, _ := admodel.InternalParentDirectoryDN(child.DistinguishedName)
			if admodel.InternalCentralSameDN(parent, object.DistinguishedName) {
				return reject(66)
			}
		}
		delete(s.InternalObjects, strings.ToLower(object.DistinguishedName))
		return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
	}
	attrs := map[string][][]byte{}
	for name, values := range object.Attributes {
		attrs[name] = slices.Clone(values)
	}
	for _, mod := range request.InternalModifications {
		key := strings.ToLower(mod.InternalAttribute)
		values := attrs[key]
		switch mod.InternalOperation {
		case 2:
			attrs[key] = slices.Clone(mod.InternalValues)
		case 0:
			for _, value := range mod.InternalValues {
				if slices.ContainsFunc(
					values,
					func(prior []byte) bool { return bytes.Equal(prior, value) },
				) {
					return reject(20)
				}
				values = append(values, value)
			}
			attrs[key] = values
		case 1:
			if len(values) == 0 {
				return reject(16)
			}
			if len(mod.InternalValues) == 0 {
				delete(attrs, key)
				continue
			}
			for _, value := range mod.InternalValues {
				i := slices.IndexFunc(
					values,
					func(prior []byte) bool { return bytes.Equal(prior, value) },
				)
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
	s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
	return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
}

func InternalNewCentralTestClient(t *testing.T) (*adengine.Client, *InternalCentralTestSession) {
	t.Helper()
	client, base := InternalNewOUTestClient(t)
	session := &InternalCentralTestSession{InternalOuTestSession: base, InternalNextID: 10}
	(*adengine.InternalClientSessionPointer(client)) = session
	for i, policy := range []bool{false, true} {
		dn := admodel.InternalCentralAccessParent(InternalCentralTestConfiguration, policy)
		class := "msAuthz-CentralAccessRules"
		if policy {
			class = "msAuthz-CentralAccessPolicies"
		}
		session.InternalObjects[strings.ToLower(dn)] = InternalOuTestObject(dn, class, byte(i+5))
	}
	base.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
		root := InternalIdentityTestRoot(admodel.CapabilityActiveDirectory)
		root["configurationnamingcontext"] = [][]byte{[]byte(InternalCentralTestConfiguration)}
		root["schemanamingcontext"] = [][]byte{
			[]byte("CN=Schema," + InternalCentralTestConfiguration),
		}
		root["supportedcontrol"] = [][]byte{
			[]byte(admodel.InternalObjectAssertionControl),
			[]byte(admodel.InternalOuSDFlagsControl),
		}
		return root, nil
	}
	base.InternalSearch = func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if query.Base == "CN=Schema,"+InternalCentralTestConfiguration {
			return InternalObjectTestCursor(
				admodel.Object{
					Attributes: map[string][][]byte{
						"rdnattid":            {[]byte("cn")},
						"objectclasscategory": {[]byte("1")},
					},
				},
			), nil
		}
		if strings.Contains(query.Filter, "objectGUID=") {
			for _, object := range session.InternalObjects {
				guid, _ := admodel.InternalCentralAccessGUID(object)
				if strings.Contains(
					query.Filter,
					admodel.InternalIdentityBinaryLiteral(guid.Bytes()),
				) {
					return InternalObjectTestCursor(object), nil
				}
			}
			return InternalObjectTestCursor(), nil
		}
		var rows []admodel.Object
		for _, object := range session.InternalObjects {
			within := admodel.InternalCentralSameDN(object.DistinguishedName, query.Base)
			if query.Scope == admodel.ScopeOneLevel {
				parent, _ := admodel.InternalParentDirectoryDN(object.DistinguishedName)
				within = admodel.InternalCentralSameDN(parent, query.Base)
			}
			if !within {
				continue
			}
			if _, rest, ok := strings.Cut(query.Filter, "(objectClass="); ok {
				class, _, _ := strings.Cut(rest, ")")
				if class != "*" && admodel.InternalCentralAccessClassCheck(object, class) != nil {
					continue
				}
			}
			rows = append(rows, object)
		}
		return InternalObjectTestCursor(rows...), nil
	}
	return client, session
}

func TestCentralAccessLifecycleSeparatesPermissionsConditionsAndIDs(t *testing.T) {
	client, session := InternalNewCentralTestClient(t)
	condition := conditions.Compare(
		conditions.Claim{Scope: conditions.Resource, Name: "Department"},
		conditions.Equal,
		conditions.Text("Finance"),
	)
	proposed := "D:(A;;FR;;;WD)"
	rule, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "Finance", ProposedACL: &proposed, ResourceCondition: &condition})
	if err != nil || !rule.Mutation.Verified ||
		*rule.Rule.CurrentACL != admodel.DefaultCentralAccessRuleACL ||
		*rule.Rule.ProposedACL != proposed ||
		rule.Rule.PreviousACL != nil ||
		len(session.InternalWrites) != 1 {
		t.Fatal(rule, err)
	}
	identity := admodel.InternalObjectGUIDIdentity(*rule.Rule.GUID)
	current := "O:SYG:SYD:(XA;;FR;;;WD;(@Resource.Department == \"Finance\"))"
	updated, err := adservice_central_access.New(client).
		UpdateCentralAccessRule(context.Background(), admodel.UpdateCentralAccessRuleRequest{Identity: identity, CurrentACL: &current})
	if err != nil || !updated.Mutation.Verified || *updated.Rule.CurrentACL != current ||
		*updated.Rule.PreviousACL != admodel.DefaultCentralAccessRuleACL ||
		*updated.Rule.ProposedACL != proposed ||
		*updated.Rule.ResourceCondition != *rule.Rule.ResourceCondition {
		t.Fatal(updated, err)
	}
	mods := session.InternalWrites[1].InternalModifications
	if len(mods) != 3 || mods[0].InternalOperation != 1 || mods[1].InternalOperation != 0 ||
		mods[2].InternalAttribute != admodel.InternalCentralPrevious ||
		string(mods[2].InternalValues[0]) != admodel.DefaultCentralAccessRuleACL {
		t.Fatal(mods)
	}
	policy, err := adservice_central_access.New(client).
		CreateCentralAccessPolicy(context.Background(), admodel.CreateCentralAccessPolicyRequest{Name: "Policy"})
	if err != nil || !policy.Mutation.Verified ||
		!admodel.InternalValidCentralAccessPolicyID(*policy.Policy.PolicyID) ||
		policy.GeneratedPolicyID.String() != policy.Policy.PolicyID.String() {
		t.Fatal(policy, err)
	}
	policyIdentity := admodel.InternalObjectGUIDIdentity(*policy.Policy.GUID)
	members, err := adservice_central_access.New(client).
		AddCentralAccessPolicyMembers(context.Background(), admodel.CentralAccessPolicyMembersRequest{Identity: policyIdentity, Members: []admodel.Identity{identity}})
	if err != nil || !members.Mutation.Verified || len(members.After.References) != 1 {
		t.Fatal(members, err)
	}
	read, err := adservice_central_access.New(client).
		CentralAccessPolicy(context.Background(), policyIdentity, admodel.CentralAccessReadOptions{})
	if err != nil || !read.Members.Complete || len(read.Members.References) != 1 {
		t.Fatal(read, err)
	}
	policies, err := adservice_central_access.New(client).
		CentralAccessPolicies(context.Background(), admodel.SearchOptions{}, admodel.CentralAccessReferenceLimits{})
	if err != nil || len(policies.Policies) != 1 || !policies.Observation.Complete {
		t.Fatal(policies, err)
	}
	removed, err := adservice_central_access.New(client).
		RemoveCentralAccessPolicyMembers(context.Background(), admodel.CentralAccessPolicyMembersRequest{Identity: policyIdentity, Members: []admodel.Identity{identity}})
	if !errors.Is(err, admodel.ErrObjectVerification) ||
		removed.Mutation.State != admodel.ObjectWriteAccepted ||
		removed.Mutation.Verified ||
		removed.After.AttributeReturned {
		t.Fatal(removed, err)
	}
	for _, policy := range []bool{true, false} {
		var deleted admodel.ObjectMutationResult
		if policy {
			deleted, err = adservice_central_access.New(client).
				DeleteCentralAccessPolicy(context.Background(), policyIdentity, admodel.ObjectMutationOptions{})
		} else {
			deleted, err = adservice_central_access.New(client).
				DeleteCentralAccessRule(context.Background(), identity, admodel.ObjectMutationOptions{})
		}
		if err != nil || !deleted.Verified || !deleted.AbsentAfter {
			t.Fatal(deleted, err)
		}
	}
}

func TestCentralAccessMembershipLimitDuplicatesAndReferenceClass(t *testing.T) {
	client, s := InternalNewCentralTestClient(t)
	rule, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "rule"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := adservice_central_access.New(client).
		CreateCentralAccessPolicy(context.Background(), admodel.CreateCentralAccessPolicyRequest{Name: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	identity := admodel.InternalObjectGUIDIdentity(*policy.Policy.GUID)
	member := admodel.InternalObjectGUIDIdentity(*rule.Rule.GUID)
	for _, members := range [][]admodel.Identity{{member, member}, {identity}, {InternalCentralIdentity("CN=outside,DC=elsewhere")}} {
		before := len(s.InternalWrites)
		_, err = adservice_central_access.New(client).
			AddCentralAccessPolicyMembers(context.Background(), admodel.CentralAccessPolicyMembersRequest{Identity: identity, Members: members})
		if err == nil || len(s.InternalWrites) != before {
			t.Fatal(members, err)
		}
	}
	_, err = adservice_central_access.New(client).
		AddCentralAccessPolicyMembers(context.Background(), admodel.CentralAccessPolicyMembersRequest{Identity: identity, Members: []admodel.Identity{member}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := adservice_central_access.New(client).
		AddCentralAccessPolicyMembers(context.Background(), admodel.CentralAccessPolicyMembersRequest{Identity: identity, Members: []admodel.Identity{member}})
	var native *admodel.LDAPError
	if !errors.As(err, &native) || native.Code != 20 ||
		result.Mutation.State != admodel.ObjectWriteRejected {
		t.Fatal(result, err)
	}
	row := s.InternalObjects[strings.ToLower(policy.Mutation.TargetDN)]
	values := make([][]byte, 127)
	for i := range values {
		values[i] = []byte(
			fmt.Sprintf(
				"CN=rule%d,%s",
				i,
				admodel.InternalCentralAccessParent(InternalCentralTestConfiguration, false),
			),
		)
	}
	row.Attributes[strings.ToLower(admodel.InternalCentralMembers)] = values
	s.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
	before := len(s.InternalWrites)
	_, err = adservice_central_access.New(client).
		AddCentralAccessPolicyMembers(context.Background(), admodel.CentralAccessPolicyMembersRequest{Identity: identity, Members: []admodel.Identity{member}})
	if !errors.Is(err, admodel.ErrCentralAccessMemberLimit) || len(s.InternalWrites) != before {
		t.Fatal(err, len(s.InternalWrites))
	}
	row.Attributes[strings.ToLower(admodel.InternalCentralMembers)] = values[:126]
	s.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
	boundary, err := adservice_central_access.New(client).
		AddCentralAccessPolicyMembers(context.Background(), admodel.CentralAccessPolicyMembersRequest{Identity: identity, Members: []admodel.Identity{member}})
	if err != nil || !boundary.Mutation.Verified || len(boundary.After.References) != 127 ||
		len(s.InternalWrites) != before+1 {
		t.Fatal("the 127th distinct rule was rejected", boundary, err)
	}
}

func TestCentralAccessCurrentACLStaleSnapshotRejectsAtomically(t *testing.T) {
	client, s := InternalNewCentralTestClient(t)
	rule, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "rule"})
	if err != nil {
		t.Fatal(err)
	}
	s.InternalBeforeWrite = func() {
		row := s.InternalObjects[strings.ToLower(rule.Mutation.TargetDN)]
		attrs := map[string][][]byte{}
		for name, values := range row.Attributes {
			attrs[name] = values
		}
		row.Attributes = attrs
		row.Attributes[strings.ToLower(admodel.InternalCentralCurrent)] = [][]byte{
			[]byte("D:(A;;GA;;;SY)"),
		}
		s.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
	}
	result, err := adservice_central_access.New(client).
		UpdateCentralAccessRule(context.Background(), admodel.UpdateCentralAccessRuleRequest{Identity: admodel.InternalObjectGUIDIdentity(*rule.Rule.GUID), CurrentACL: InternalCentralPointer("D:(A;;FR;;;WD)")})
	if err == nil || result.Mutation.State != admodel.ObjectWriteRejected ||
		len(s.InternalWrites) != 2 {
		t.Fatal(result, err)
	}
	row := s.InternalObjects[strings.ToLower(rule.Mutation.TargetDN)]
	if _, found := row.Attributes[strings.ToLower(admodel.InternalCentralPrevious)]; found {
		t.Fatal("partial atomic update")
	}
}

func TestCentralAccessProtectionPartialAndUnknownWrite(t *testing.T) {
	for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			client, s := InternalNewCentralTestClient(t)
			s.InternalFailAt = 3
			s.InternalFailure = admodel.InternalLdapWriteAttempt{
				State: state,
				Err:   &admodel.LDAPError{Code: 50},
			}
			result, err := adservice_central_access.New(client).
				CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "partial", ProtectedFromAccidentalDeletion: InternalCentralPointer(true)})
			if err == nil || result.Mutation.State != admodel.ObjectWriteAccepted ||
				len(s.InternalWrites) != 3 ||
				len(result.Protection.Steps) != 2 ||
				result.Protection.Steps[0].State != admodel.ObjectWriteAccepted ||
				result.Protection.Steps[1].Verified {
				t.Fatal(result, err)
			}
		})
	}
}

func TestCentralAccessInvalidExpressionsAndManagedRawChangesNoWrite(t *testing.T) {
	client, s := InternalNewCentralTestClient(t)
	bad := conditions.Raw("BAD")
	for _, request := range []admodel.CreateCentralAccessRuleRequest{{Name: "bad", CurrentACL: InternalCentralPointer("BAD")}, {Name: "bad", ProposedACL: InternalCentralPointer("BAD")}, {Name: "bad", ResourceCondition: &bad}} {
		_, err := adservice_central_access.New(client).
			CreateCentralAccessRule(context.Background(), request)
		if !errors.Is(err, conditions.ErrInvalidExpression) || len(s.InternalWrites) != 0 {
			t.Fatal(err, s.InternalWrites)
		}
	}
	_, err := adservice_central_access.New(client).
		UpdateCentralAccessRule(context.Background(), admodel.UpdateCentralAccessRuleRequest{Identity: InternalCentralIdentity("CN=rule," + admodel.InternalCentralAccessParent(InternalCentralTestConfiguration, false)), Changes: []admodel.AttributeChange{{Attribute: admodel.InternalCentralCurrent, Kind: admodel.AttributeClear}}})
	if !errors.Is(err, admodel.ErrCentralAccess) || len(s.InternalWrites) != 0 {
		t.Fatal(err)
	}
}

func TestCentralAccessMissingLDSAndDeletionFailures(t *testing.T) {
	client, s := InternalNewCentralTestClient(t)
	_, err := adservice_central_access.New(client).
		DeleteCentralAccessRule(context.Background(), InternalCentralIdentity("CN=missing,"+admodel.InternalCentralAccessParent(InternalCentralTestConfiguration, false)), admodel.ObjectMutationOptions{})
	if err == nil || len(s.InternalWrites) != 0 {
		t.Fatal(err)
	}
	rule, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "protected"})
	if err != nil {
		t.Fatal(err)
	}
	s.InternalFailAt = 2
	s.InternalFailure = admodel.InternalLdapWriteAttempt{
		State: admodel.InternalLdapWriteRejected,
		Err:   &admodel.LDAPError{Code: 50, Diagnostic: "protected rule"},
	}
	deleted, err := adservice_central_access.New(client).
		DeleteCentralAccessRule(context.Background(), admodel.InternalObjectGUIDIdentity(*rule.Rule.GUID), admodel.ObjectMutationOptions{})
	var native *admodel.LDAPError
	if !errors.As(err, &native) || native.Code != 50 || native.Diagnostic != "protected rule" ||
		deleted.State != admodel.ObjectWriteRejected ||
		deleted.AbsentAfter ||
		len(s.InternalWrites) != 2 {
		t.Fatal(deleted, err)
	}
	original := s.InternalRead
	s.InternalRead = func(ctx context.Context, attrs []string) (map[string][][]byte, error) {
		root, e := original(ctx, attrs)
		root["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
		return root, e
	}
	_, err = adservice_central_access.New(client).
		CreateCentralAccessPolicy(context.Background(), admodel.CreateCentralAccessPolicyRequest{Name: "LDS"})
	if !errors.Is(err, admodel.ErrUnsupported) || len(s.InternalWrites) != 2 {
		t.Fatal(err)
	}
}

func TestCentralAccessRangeFailuresRetainRaw(t *testing.T) {
	for _, kind := range []string{"permission", "gap", "changed", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			client, s := InternalNewCentralTestClient(t)
			policy, err := adservice_central_access.New(client).
				CreateCentralAccessPolicy(context.Background(), admodel.CreateCentralAccessPolicyRequest{Name: "policy"})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			s.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				calls++
				attrs := map[string][][]byte{
					"objectguid": policy.Mutation.After.Attributes["objectguid"],
					"usnchanged": {[]byte("7")},
				}
				if calls == 1 {
					attrs[admodel.InternalCentralMembers+";range=0-0"] = [][]byte{
						[]byte(
							"CN=one," + admodel.InternalCentralAccessParent(
								InternalCentralTestConfiguration,
								false,
							),
						),
					}
					return attrs, nil
				}
				attrs[admodel.InternalCentralMembers+";range=1-*"] = [][]byte{
					[]byte(
						"CN=two," + admodel.InternalCentralAccessParent(
							InternalCentralTestConfiguration,
							false,
						),
					),
				}
				switch kind {
				case "permission":
					return attrs, &admodel.LDAPError{Code: 50}
				case "gap":
					delete(attrs, admodel.InternalCentralMembers+";range=1-*")
					attrs[admodel.InternalCentralMembers+";range=2-*"] = [][]byte{
						[]byte(
							"CN=two," + admodel.InternalCentralAccessParent(
								InternalCentralTestConfiguration,
								false,
							),
						),
					}
				case "changed":
					attrs["usnchanged"] = [][]byte{[]byte("8")}
				case "duplicate":
					attrs[admodel.InternalCentralMembers+";range=1-*"] = [][]byte{
						[]byte(
							"CN=ONE," + admodel.InternalCentralAccessParent(
								InternalCentralTestConfiguration,
								false,
							),
						),
					}
				}
				return attrs, nil
			}
			result, err := adservice_central_access.New(client).
				CentralAccessPolicy(context.Background(), admodel.InternalObjectGUIDIdentity(*policy.Policy.GUID), admodel.CentralAccessReadOptions{})
			if err == nil || result.Members.Complete || len(result.Members.Ranges) != 2 ||
				len(result.Members.References) != 2 {
				t.Fatal(result, err)
			}
		})
	}
}

func TestCentralAccessNoOpPropertiesAndVersionPreconditions(t *testing.T) {
	client, s := InternalNewCentralTestClient(t)
	created, err := adservice_central_access.New(client).
		CreateCentralAccessPolicy(context.Background(), admodel.CreateCentralAccessPolicyRequest{Name: "properties"})
	if err != nil {
		t.Fatal(err)
	}
	row := s.InternalObjects[strings.ToLower(created.Mutation.TargetDN)]
	row.Attributes["displayname"] = [][]byte{[]byte("retained")}
	s.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
	search := s.InternalSearch
	selected := false
	s.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		selected = slices.Contains(query.Properties, "displayName")
		return search(ctx, query)
	}
	identity := admodel.InternalObjectGUIDIdentity(*created.Policy.GUID)
	result, err := adservice_central_access.New(client).
		UpdateCentralAccessPolicy(context.Background(), admodel.UpdateCentralAccessPolicyRequest{Identity: identity, Options: admodel.ObjectMutationOptions{Properties: []string{"displayName"}}})
	if err != nil || !selected || !result.Mutation.Verified ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted ||
		len(result.Policy.Raw.Attributes["displayname"]) != 1 ||
		len(s.InternalWrites) != 1 {
		t.Fatal(result, err, selected)
	}
	for _, protect := range []*bool{nil, InternalCentralPointer(false), InternalCentralPointer(true)} {
		result, err := adservice_central_access.New(client).
			UpdateCentralAccessPolicy(context.Background(), admodel.UpdateCentralAccessPolicyRequest{Identity: identity, ProtectedFromAccidentalDeletion: protect, Options: admodel.ObjectMutationOptions{ExpectedVersion: &admodel.ObjectVersion{Source: (*adengine.InternalClientConfigPointer(client)).Endpoint, GUID: *created.Policy.GUID, USNChanged: 7}}})
		if !errors.Is(err, admodel.ErrObjectControlUnsupported) ||
			result.Mutation.State != admodel.ObjectWriteNotAttempted ||
			len(s.InternalWrites) != 1 {
			t.Fatal(result, err)
		}
	}
}

func TestCentralAccessMembershipPreservesOthersAndAcceptedReadbackFailure(t *testing.T) {
	client, s := InternalNewCentralTestClient(t)
	first, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "second"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := adservice_central_access.New(client).
		CreateCentralAccessPolicy(context.Background(), admodel.CreateCentralAccessPolicyRequest{Name: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	request := admodel.CentralAccessPolicyMembersRequest{
		Identity: admodel.InternalObjectGUIDIdentity(*policy.Policy.GUID),
		Members: []admodel.Identity{
			admodel.InternalObjectGUIDIdentity(*first.Rule.GUID),
			admodel.InternalObjectGUIDIdentity(*second.Rule.GUID),
		},
	}
	added, err := adservice_central_access.New(client).
		AddCentralAccessPolicyMembers(context.Background(), request)
	if err != nil || !added.Mutation.Verified {
		t.Fatal(added, err)
	}
	request.Members = request.Members[:1]
	removed, err := adservice_central_access.New(client).
		RemoveCentralAccessPolicyMembers(context.Background(), request)
	if err != nil || !removed.Mutation.Verified || len(removed.After.References) != 1 ||
		!admodel.InternalCentralSameDN(
			removed.After.References[0].DistinguishedName,
			second.Mutation.TargetDN,
		) {
		t.Fatal(removed, err)
	}
	reads := 0
	s.InternalRangeRead = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
		reads++
		fn := s.InternalRangeRead
		s.InternalRangeRead = nil
		attrs, e := s.InternalRangedBaseObject(ctx, dn, properties)
		s.InternalRangeRead = fn
		if reads == 2 {
			e = &admodel.LDAPError{Code: 50}
		}
		return attrs, e
	}
	before := len(s.InternalWrites)
	result, err := adservice_central_access.New(client).
		AddCentralAccessPolicyMembers(context.Background(), request)
	if !errors.Is(err, admodel.ErrObjectReadback) ||
		result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.Mutation.Verified ||
		len(result.After.References) != 2 ||
		result.After.Complete ||
		len(s.InternalWrites) != before+1 {
		t.Fatal(result, err)
	}
}

func TestCentralAccessGeneratedIDAndAbsentDecodeRemainExplicit(t *testing.T) {
	ids := map[string]bool{}
	for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain} {
		client, s := InternalNewCentralTestClient(t)
		s.InternalFailAt = 1
		s.InternalFailure = admodel.InternalLdapWriteAttempt{
			State: state,
			Err:   &admodel.LDAPError{Code: 50},
		}
		result, err := adservice_central_access.New(client).
			CreateCentralAccessPolicy(context.Background(), admodel.CreateCentralAccessPolicyRequest{Name: "unknown"})
		if err == nil || result.GeneratedPolicyID == nil ||
			!admodel.InternalValidCentralAccessPolicyID(*result.GeneratedPolicyID) ||
			len(s.InternalWrites) != 1 ||
			ids[result.GeneratedPolicyID.String()] {
			t.Fatal(result, err)
		}
		ids[result.GeneratedPolicyID.String()] = true
	}
	object := InternalOuTestObject(
		"CN=policy,"+admodel.InternalCentralAccessParent(InternalCentralTestConfiguration, true),
		admodel.InternalCentralAccessClass(true),
		88,
	)
	decoded, err := admodel.InternalDecodeCentralAccessPolicy(object)
	if err != nil || decoded.PolicyID != nil {
		t.Fatal(decoded, err)
	}
	object.Attributes[strings.ToLower(admodel.InternalCentralPolicyID)] = [][]byte{{1, 4, 0}}
	decoded, err = admodel.InternalDecodeCentralAccessPolicy(object)
	if err == nil || decoded.PolicyID != nil ||
		len(decoded.Raw.Attributes[strings.ToLower(admodel.InternalCentralPolicyID)]) != 1 {
		t.Fatal(decoded, err)
	}
}

func TestCentralAccessClearPermissionsKeepsHistoryButOmissionIsUnverified(t *testing.T) {
	client, s := InternalNewCentralTestClient(t)
	rule, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "clear"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := adservice_central_access.New(client).
		UpdateCentralAccessRule(context.Background(), admodel.UpdateCentralAccessRuleRequest{Identity: admodel.InternalObjectGUIDIdentity(*rule.Rule.GUID), ClearCurrentACL: true})
	if !errors.Is(err, admodel.ErrObjectUnverifiable) ||
		result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.Mutation.Verified ||
		result.Rule.CurrentACL != nil ||
		*result.Rule.PreviousACL != admodel.DefaultCentralAccessRuleACL ||
		len(s.InternalWrites) != 2 {
		t.Fatal(result, err)
	}
}

func TestCentralAccessRangeBudgetsAndCancellationRetainBatch(t *testing.T) {
	client, s := InternalNewCentralTestClient(t)
	policy, err := adservice_central_access.New(client).
		CreateCentralAccessPolicy(context.Background(), admodel.CreateCentralAccessPolicyRequest{Name: "budget"})
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string][][]byte{
		"objectguid": policy.Mutation.After.Attributes["objectguid"],
		"usnchanged": {[]byte("7")},
		admodel.InternalCentralMembers: {
			[]byte(
				"CN=one," + admodel.InternalCentralAccessParent(
					InternalCentralTestConfiguration,
					false,
				),
			),
			[]byte(
				"CN=two," + admodel.InternalCentralAccessParent(
					InternalCentralTestConfiguration,
					false,
				),
			),
		},
	}
	for _, kind := range []string{"bytes", "count", "cancel", "complete"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				if kind == "cancel" {
					cancel()
				}
				return attrs, nil
			}
			limits, _ := admodel.InternalNormalizeCentralAccessLimits(
				admodel.CentralAccessReferenceLimits{},
			)
			if kind == "bytes" {
				limits.MaxBytes = 1
			}
			if kind == "count" {
				limits.MaxReferences = 1
			}
			result, err := admodel.InternalReadCentralAccessReferences(
				ctx,
				s,
				*policy.Mutation.After,
				admodel.InternalCentralMembers,
				limits,
			)
			if len(result.Ranges) != 1 ||
				len(result.Ranges[0].Attributes[admodel.InternalCentralMembers]) != 2 {
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
	limits, err := admodel.InternalNormalizeCentralAccessLimits(
		admodel.CentralAccessReferenceLimits{
			MaxReferences: 100001,
			MaxRanges:     1001,
			MaxBytes:      (64 << 20) + 1,
		},
	)
	if err != nil || limits.MaxReferences != 100001 || limits.MaxRanges != 1001 ||
		limits.MaxBytes != (64<<20)+1 {
		t.Fatal(limits, err)
	}
}
