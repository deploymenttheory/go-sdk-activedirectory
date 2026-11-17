//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_central_access "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

type InternalCentralNativeSession struct {
	*InternalCentralTestSession
	InternalNative *adengine.InternalLdapSession
	InternalCalls  int
}

func (s *InternalCentralNativeSession) InternalValidateCentralAccessDescriptor(value string) error {
	return (*adengine.InternalLdapSession)(nil).InternalValidateCentralAccessDescriptor(value)
}

func (s *InternalCentralNativeSession) InternalValidateCentralAccessCondition(value string) error {
	return (*adengine.InternalLdapSession)(nil).InternalValidateCentralAccessCondition(value)
}

func (s *InternalCentralNativeSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	s.InternalCalls++
	if s.InternalNative == nil {
		return s.InternalCentralTestSession.InternalLdapWrite(ctx, request)
	}
	result := s.InternalNative.InternalLdapWrite(ctx, request)
	if result.State == admodel.InternalLdapWriteAccepted {
		if applied := s.InternalCentralTestSession.InternalLdapWrite(
			ctx,
			request,
		); applied.Err != nil {
			return applied
		}
	}
	return result
}

func TestNativeCentralAccessRuleAddUsesSDDLTextNotBinary(t *testing.T) {
	for _, code := range []byte{0, 50, 68} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			client, observed := InternalNewCentralTestClient(t)
			name := "Finance-新"
			dn := "cn=" + name + "," + admodel.InternalCentralAccessParent(
				InternalCentralTestConfiguration,
				false,
			)
			current := `O:SYG:SYD:(XA;;FR;;;WD;(@Resource.Department == "Finance"))`
			attribute := func(name string, value []byte) []byte {
				return InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte(name)),
					InternalSearchBER(0x31, InternalSearchBER(4, value)),
				)
			}
			want := append(
				InternalSearchBER(4, []byte(dn)),
				InternalSearchBER(
					0x30,
					attribute(admodel.InternalCentralCurrent, []byte(current)),
					attribute("objectClass", []byte("msAuthz-CentralAccessRule")),
					attribute("cn", []byte(name)),
				)...)
			fixture := InternalNewWriteWireFixture(t, 0x68, 0x69, want, nil, code)
			var owners InternalSearchNativeCounts
			wire := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&owners),
			)
			session := &InternalCentralNativeSession{
				InternalCentralTestSession: observed,
				InternalNative:             (*adengine.InternalClientSessionPointer(wire)).(*adengine.InternalLdapSession),
			}
			(*adengine.InternalClientSessionPointer(client)) = session
			result, err := adservice_central_access.New(client).
				CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: name, CurrentACL: &current})
			if session.InternalCalls != 1 {
				t.Fatal("replayed", session.InternalCalls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified || *result.Rule.CurrentACL != current {
					t.Fatal(result, err)
				}
			} else {
				var status *admodel.LDAPError
				if !errors.As(err, &status) || status.Code != uint32(code) ||
					status.Diagnostic != "private wire diagnostic" ||
					result.Mutation.State != admodel.ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err := wire.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal("native owners leaked", owners)
			}
		})
	}
}

func TestNativeCentralAccessHistoryModifyUsesStrictOldValueAndText(t *testing.T) {
	client, observed := InternalNewCentralTestClient(t)
	rule, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "history"})
	if err != nil {
		t.Fatal(err)
	}
	newACL := "D:(A;;FR;;;WD)"
	mod := func(operation byte, name, value string) []byte {
		return InternalSearchBER(
			0x30,
			[]byte{10, 1, operation},
			InternalSearchBER(
				0x30,
				InternalSearchBER(4, []byte(name)),
				InternalSearchBER(0x31, InternalSearchBER(4, []byte(value))),
			),
		)
	}
	want := append(
		InternalSearchBER(4, []byte(admodel.InternalObjectGUIDTarget(*rule.Rule.GUID))),
		InternalSearchBER(
			0x30,
			mod(1, admodel.InternalCentralCurrent, admodel.DefaultCentralAccessRuleACL),
			mod(0, admodel.InternalCentralCurrent, newACL),
			mod(2, admodel.InternalCentralPrevious, admodel.DefaultCentralAccessRuleACL),
		)...)
	fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, nil, 0)
	var owners InternalSearchNativeCounts
	wire := InternalSearchWireClient(
		t,
		&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
		InternalCountedSearchAPI(&owners),
	)
	session := &InternalCentralNativeSession{
		InternalCentralTestSession: observed,
		InternalNative:             (*adengine.InternalClientSessionPointer(wire)).(*adengine.InternalLdapSession),
	}
	(*adengine.InternalClientSessionPointer(client)) = session
	result, err := adservice_central_access.New(client).
		UpdateCentralAccessRule(context.Background(), admodel.UpdateCentralAccessRuleRequest{Identity: admodel.InternalObjectGUIDIdentity(*rule.Rule.GUID), CurrentACL: &newACL})
	if err != nil || !result.Mutation.Verified || session.InternalCalls != 1 ||
		*result.Rule.PreviousACL != admodel.DefaultCentralAccessRuleACL {
		t.Fatal(result, err)
	}
	if err := wire.Close(); err != nil {
		t.Fatal(err)
	}
	if owners != (InternalSearchNativeCounts{}) {
		t.Fatal(owners)
	}
}

func TestNativeCentralAccessMalformedExpressionsNeverDispatch(t *testing.T) {
	for _, request := range []admodel.CreateCentralAccessRuleRequest{{Name: "bad", CurrentACL: InternalCentralPointer("not SDDL")}, {Name: "bad", ProposedACL: InternalCentralPointer("D:(XA;;GA;;;WD;(broken)")}, {Name: "bad", ResourceCondition: InternalCentralPointer(conditions.Raw(`@Resource.Department ==`))}, {Name: "bad", ResourceCondition: InternalCentralPointer(conditions.Raw(`TRUE))(A;;GA;;;WD`))}} {
		client, observed := InternalNewCentralTestClient(t)
		session := &InternalCentralNativeSession{InternalCentralTestSession: observed}
		(*adengine.InternalClientSessionPointer(client)) = session
		result, err := adservice_central_access.New(client).
			CreateCentralAccessRule(context.Background(), request)
		if err == nil || result.Mutation.State != admodel.ObjectWriteNotAttempted ||
			session.InternalCalls != 0 {
			t.Fatal(result, err, session.InternalCalls)
		}
	}
	client, observed := InternalNewCentralTestClient(t)
	session := &InternalCentralNativeSession{InternalCentralTestSession: observed}
	(*adengine.InternalClientSessionPointer(client)) = session
	expression := conditions.All(
		conditions.Exists(conditions.Claim{Scope: conditions.Resource, Name: "Department"}),
		conditions.Compare(
			conditions.Claim{Scope: conditions.Resource, Name: "Department"},
			conditions.Equal,
			conditions.Text("Finance"),
		),
	)
	result, err := adservice_central_access.New(client).
		CreateCentralAccessRule(context.Background(), admodel.CreateCentralAccessRuleRequest{Name: "valid", ResourceCondition: &expression})
	text, _ := expression.Render()
	if err != nil || !result.Mutation.Verified || *result.Rule.ResourceCondition != text ||
		session.InternalCalls != 1 {
		t.Fatal(result, err)
	}
	for _, update := range []admodel.UpdateCentralAccessRuleRequest{
		{ProposedACL: InternalCentralPointer("D:(XA;;GA;;;WD;(broken)")},
		{ResourceCondition: InternalCentralPointer(conditions.Raw(`@Resource.Department ==`))},
		{CurrentACL: InternalCentralPointer("invalid")},
	} {
		update.Identity = admodel.InternalObjectGUIDIdentity(*result.Rule.GUID)
		changed, err := adservice_central_access.New(client).
			UpdateCentralAccessRule(context.Background(), update)
		if err == nil || changed.Mutation.State != admodel.ObjectWriteNotAttempted ||
			session.InternalCalls != 1 {
			t.Fatal("invalid update dispatched", changed, err, session.InternalCalls)
		}
	}
}

func TestNativeCentralAccessReferenceRangesAndServerError(t *testing.T) {
	object := InternalOuTestObject(
		"CN=policy,"+admodel.InternalCentralAccessParent(InternalCentralTestConfiguration, true),
		admodel.InternalCentralAccessClass(true),
		24,
	)
	attrs := func(name, dn string) map[string][][]byte {
		return map[string][][]byte{
			"objectGUID": object.Attributes["objectguid"],
			"uSNChanged": {[]byte("7")},
			name:         {[]byte(dn)},
		}
	}
	fixture := InternalNewSearchWireFixture(
		t,
		[]InternalSearchWirePage{
			{
				InternalCount:    1,
				InternalBaseRead: true,
				InternalDn:       object.DistinguishedName,
				InternalAttributes: attrs(
					admodel.InternalCentralMembers+";range=0-0",
					"CN=one,"+admodel.InternalCentralAccessParent(
						InternalCentralTestConfiguration,
						false,
					),
				),
			},
			{
				InternalCount:    1,
				InternalBaseRead: true,
				InternalDn:       object.DistinguishedName,
				InternalCode:     50,
				InternalAttributes: attrs(
					admodel.InternalCentralMembers+";range=1-*",
					"CN=two,"+admodel.InternalCentralAccessParent(
						InternalCentralTestConfiguration,
						false,
					),
				),
			},
		},
	)
	var owners InternalSearchNativeCounts
	client := InternalSearchWireClient(t, fixture, InternalCountedSearchAPI(&owners))
	limits, _ := admodel.InternalNormalizeCentralAccessLimits(
		admodel.CentralAccessReferenceLimits{},
	)
	result, err := admodel.InternalReadCentralAccessReferences(
		context.Background(),
		adengine.InternalClientSession(client),
		object,
		admodel.InternalCentralMembers,
		limits,
	)
	var status *admodel.LDAPError
	if !errors.As(err, &status) || status.Code != 50 || result.Complete ||
		len(result.Ranges) != 2 ||
		len(result.References) != 2 {
		t.Fatal(result, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if owners != (InternalSearchNativeCounts{}) {
		t.Fatal(owners)
	}
}
