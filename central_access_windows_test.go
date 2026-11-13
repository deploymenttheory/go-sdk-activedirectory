//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

type centralNativeSession struct {
	*centralTestSession
	native *ldapSession
	calls  int
}

func (s *centralNativeSession) validateCentralAccessDescriptor(value string) error {
	return (*ldapSession)(nil).validateCentralAccessDescriptor(value)
}
func (s *centralNativeSession) validateCentralAccessCondition(value string) error {
	return (*ldapSession)(nil).validateCentralAccessCondition(value)
}
func (s *centralNativeSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	s.calls++
	if s.native == nil {
		return s.centralTestSession.ldapWrite(ctx, request)
	}
	result := s.native.ldapWrite(ctx, request)
	if result.State == ldapWriteAccepted {
		if applied := s.centralTestSession.ldapWrite(ctx, request); applied.Err != nil {
			return applied
		}
	}
	return result
}
func TestNativeCentralAccessRuleAddUsesSDDLTextNotBinary(t *testing.T) {
	for _, code := range []byte{0, 50, 68} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			client, observed := newCentralTestClient(t)
			name := "Finance-新"
			dn := "cn=" + name + "," + centralAccessParent(centralTestConfiguration, false)
			current := `O:SYG:SYD:(XA;;FR;;;WD;(@Resource.Department == "Finance"))`
			attribute := func(name string, value []byte) []byte {
				return searchBER(0x30, searchBER(4, []byte(name)), searchBER(0x31, searchBER(4, value)))
			}
			want := append(searchBER(4, []byte(dn)), searchBER(0x30, attribute(centralCurrent, []byte(current)), attribute("objectClass", []byte("msAuthz-CentralAccessRule")), attribute("cn", []byte(name)))...)
			fixture := newWriteWireFixture(t, 0x68, 0x69, want, nil, code)
			var owners searchNativeCounts
			wire := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			session := &centralNativeSession{centralTestSession: observed, native: wire.session.(*ldapSession)}
			client.session = session
			result, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: name, CurrentACL: &current})
			if session.calls != 1 {
				t.Fatal("replayed", session.calls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified || *result.Rule.CurrentACL != current {
					t.Fatal(result, err)
				}
			} else {
				var status *LDAPError
				if !errors.As(err, &status) || status.Code != uint32(code) || status.Diagnostic != "private wire diagnostic" || result.Mutation.State != ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err := wire.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (searchNativeCounts{}) {
				t.Fatal("native owners leaked", owners)
			}
		})
	}
}
func TestNativeCentralAccessHistoryModifyUsesStrictOldValueAndText(t *testing.T) {
	client, observed := newCentralTestClient(t)
	rule, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "history"})
	if err != nil {
		t.Fatal(err)
	}
	newACL := "D:(A;;FR;;;WD)"
	mod := func(operation byte, name, value string) []byte {
		return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte(name)), searchBER(0x31, searchBER(4, []byte(value)))))
	}
	want := append(searchBER(4, []byte(objectGUIDTarget(*rule.Rule.GUID))), searchBER(0x30, mod(1, centralCurrent, DefaultCentralAccessRuleACL), mod(0, centralCurrent, newACL), mod(2, centralPrevious, DefaultCentralAccessRuleACL))...)
	fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, 0)
	var owners searchNativeCounts
	wire := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
	session := &centralNativeSession{centralTestSession: observed, native: wire.session.(*ldapSession)}
	client.session = session
	result, err := client.UpdateCentralAccessRule(context.Background(), UpdateCentralAccessRuleRequest{Identity: objectGUIDIdentity(*rule.Rule.GUID), CurrentACL: &newACL})
	if err != nil || !result.Mutation.Verified || session.calls != 1 || *result.Rule.PreviousACL != DefaultCentralAccessRuleACL {
		t.Fatal(result, err)
	}
	if err := wire.Close(); err != nil {
		t.Fatal(err)
	}
	if owners != (searchNativeCounts{}) {
		t.Fatal(owners)
	}
}
func TestNativeCentralAccessMalformedExpressionsNeverDispatch(t *testing.T) {
	for _, request := range []CreateCentralAccessRuleRequest{{Name: "bad", CurrentACL: centralPointer("not SDDL")}, {Name: "bad", ProposedACL: centralPointer("D:(XA;;GA;;;WD;(broken)")}, {Name: "bad", ResourceCondition: centralPointer(conditions.Raw(`@Resource.Department ==`))}, {Name: "bad", ResourceCondition: centralPointer(conditions.Raw(`TRUE))(A;;GA;;;WD`))}} {
		client, observed := newCentralTestClient(t)
		session := &centralNativeSession{centralTestSession: observed}
		client.session = session
		result, err := client.CreateCentralAccessRule(context.Background(), request)
		if err == nil || result.Mutation.State != ObjectWriteNotAttempted || session.calls != 0 {
			t.Fatal(result, err, session.calls)
		}
	}
	client, observed := newCentralTestClient(t)
	session := &centralNativeSession{centralTestSession: observed}
	client.session = session
	expression := conditions.All(conditions.Exists(conditions.Claim{Scope: conditions.Resource, Name: "Department"}), conditions.Compare(conditions.Claim{Scope: conditions.Resource, Name: "Department"}, conditions.Equal, conditions.Text("Finance")))
	result, err := client.CreateCentralAccessRule(context.Background(), CreateCentralAccessRuleRequest{Name: "valid", ResourceCondition: &expression})
	text, _ := expression.Render()
	if err != nil || !result.Mutation.Verified || *result.Rule.ResourceCondition != text || session.calls != 1 {
		t.Fatal(result, err)
	}
	for _, update := range []UpdateCentralAccessRuleRequest{
		{ProposedACL: centralPointer("D:(XA;;GA;;;WD;(broken)")},
		{ResourceCondition: centralPointer(conditions.Raw(`@Resource.Department ==`))},
		{CurrentACL: centralPointer("invalid")},
	} {
		update.Identity = objectGUIDIdentity(*result.Rule.GUID)
		changed, err := client.UpdateCentralAccessRule(context.Background(), update)
		if err == nil || changed.Mutation.State != ObjectWriteNotAttempted || session.calls != 1 {
			t.Fatal("invalid update dispatched", changed, err, session.calls)
		}
	}
}
func TestNativeCentralAccessReferenceRangesAndServerError(t *testing.T) {
	object := ouTestObject("CN=policy,"+centralAccessParent(centralTestConfiguration, true), centralAccessClass(true), 24)
	attrs := func(name, dn string) map[string][][]byte {
		return map[string][][]byte{"objectGUID": object.Attributes["objectguid"], "uSNChanged": {[]byte("7")}, name: {[]byte(dn)}}
	}
	fixture := newSearchWireFixture(t, []searchWirePage{{count: 1, baseRead: true, dn: object.DistinguishedName, attributes: attrs(centralMembers+";range=0-0", "CN=one,"+centralAccessParent(centralTestConfiguration, false))}, {count: 1, baseRead: true, dn: object.DistinguishedName, code: 50, attributes: attrs(centralMembers+";range=1-*", "CN=two,"+centralAccessParent(centralTestConfiguration, false))}})
	var owners searchNativeCounts
	client := searchWireClient(t, fixture, countedSearchAPI(&owners))
	limits, _ := normalizeCentralAccessLimits(CentralAccessReferenceLimits{})
	result, err := readCentralAccessReferences(context.Background(), client.session, object, centralMembers, limits)
	var status *LDAPError
	if !errors.As(err, &status) || status.Code != 50 || result.Complete || len(result.Ranges) != 2 || len(result.References) != 2 {
		t.Fatal(result, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if owners != (searchNativeCounts{}) {
		t.Fatal(owners)
	}
}
