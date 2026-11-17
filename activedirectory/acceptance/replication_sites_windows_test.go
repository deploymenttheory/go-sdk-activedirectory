//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

type InternalTopologyWireSession struct {
	*InternalTopologyTestSession
	InternalNative *adengine.InternalLdapSession
	InternalCalls  int
}

func (s *InternalTopologyWireSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	s.InternalCalls++
	attempt := s.InternalNative.InternalLdapWrite(ctx, request)
	if attempt.State == admodel.InternalLdapWriteAccepted {
		if observed := s.InternalTopologyTestSession.InternalLdapWrite(
			ctx,
			request,
		); observed.Err != nil {
			return observed
		}
	}
	return attempt
}

func TestNativeDirectoryServerMoveNewParentAndAssertionWire(t *testing.T) {
	for _, code := range []byte{0, 32, 50, 68} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			client, observations := InternalNewTopologyTestClient(t, false)
			destination := "CN=Zürich-新,CN=Sites," + InternalTopologyTestConfiguration
			// A Unicode destination exercises NewParent's binding conversion separately
			// from the existing RDN input; no live directory is involved.
			var moved []admodel.Object
			for key, object := range observations.InternalObjects {
				if strings.HasSuffix(object.DistinguishedName, InternalTopologyTestSiteB) {
					delete(observations.InternalObjects, key)
					object.DistinguishedName = strings.TrimSuffix(
						object.DistinguishedName,
						InternalTopologyTestSiteB,
					) + destination
					moved = append(moved, object)
				}
			}
			for _, object := range moved {
				observations.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
			}
			guid, _ := admodel.GUIDFromBytes(append([]byte{12}, make([]byte, 15)...))
			version := admodel.ObjectVersion{
				Source:     adengine.InternalClientConfig(client).Endpoint,
				GUID:       guid,
				USNChanged: 7,
			}
			want := append(
				InternalSearchBER(4, []byte("<GUID=0c000000000000000000000000000000>")),
				InternalSearchBER(4, []byte("cn=DC1"))...)
			want = append(want, 1, 1, 255)
			want = append(want, InternalSearchBER(0x80, []byte("CN=Servers,"+destination))...)
			controls := InternalSearchBER(
				0xa0,
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte(admodel.InternalObjectAssertionControl)),
					[]byte{1, 1, 255},
					InternalSearchBER(4, admodel.InternalObjectVersionAssertion(version)),
				),
			)
			fixture := InternalNewWriteWireFixture(t, 0x6c, 0x6d, want, controls, code)
			var owners InternalSearchNativeCounts
			wireClient := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&owners),
			)
			session := &InternalTopologyWireSession{
				InternalTopologyTestSession: observations,
				InternalNative:              (*adengine.InternalClientSessionPointer(wireClient)).(*adengine.InternalLdapSession),
			}
			(*adengine.InternalClientSessionPointer(client)) = session
			result, err := adservice_replication.New(client).
				MoveDirectoryServer(context.Background(), admodel.MoveDirectoryServerRequest{Server: InternalTopologyTestIdentity(InternalTopologyTestServer), Site: InternalTopologyTestIdentity(destination), Options: admodel.ObjectMutationOptions{ExpectedVersion: &version}})
			if session.InternalCalls != 1 {
				t.Fatal("native write replay", session.InternalCalls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified ||
					result.Mutation.State != admodel.ObjectWriteAccepted {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *admodel.LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) ||
					ldapErr.Diagnostic != "private wire diagnostic" ||
					result.Mutation.State != admodel.ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err := wireClient.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal("native owners leaked", owners)
			}
		})
	}
}

func TestNativeReplicationSiteBinaryScheduleWire(t *testing.T) {
	client, observations := InternalNewTopologyTestClient(t, false)
	var schedule admodel.ReplicationSchedule
	schedule[0][0][0] = true
	schedule[6][23][3] = true
	wire := make([]byte, 188)
	wire[0] = 188
	wire[8] = 1
	wire[16] = 20
	wire[20] = 1
	wire[187] = 8
	mod := InternalSearchBER(
		0x30,
		[]byte{10, 1, 2},
		InternalSearchBER(
			0x30,
			InternalSearchBER(4, []byte("schedule")),
			InternalSearchBER(0x31, InternalSearchBER(4, wire)),
		),
	)
	want := append(
		InternalSearchBER(4, []byte("<GUID=09000000000000000000000000000000>")),
		InternalSearchBER(0x30, mod)...)
	fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, nil, 0)
	var owners InternalSearchNativeCounts
	wireClient := InternalSearchWireClient(
		t,
		&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
		InternalCountedSearchAPI(&owners),
	)
	session := &InternalTopologyWireSession{
		InternalTopologyTestSession: observations,
		InternalNative:              (*adengine.InternalClientSessionPointer(wireClient)).(*adengine.InternalLdapSession),
	}
	(*adengine.InternalClientSessionPointer(client)) = session
	result, err := adservice_replication.New(client).
		UpdateReplicationSite(context.Background(), admodel.UpdateReplicationSiteRequest{Identity: InternalTopologyTestIdentity(InternalTopologyTestSiteB), Settings: &admodel.ReplicationSiteSettingsPatch{Schedule: &schedule}})
	if err != nil || !result.Complete || session.InternalCalls != 1 ||
		*result.After.Site.Settings.Schedule != schedule {
		t.Fatal(result, err)
	}
	if err := wireClient.Close(); err != nil {
		t.Fatal(err)
	}
	if owners != (InternalSearchNativeCounts{}) {
		t.Fatal(owners)
	}
}

func TestNativeWriteParentValidationDoesNotDispatch(t *testing.T) {
	for _, request := range []admodel.InternalLdapWriteRequest{
		{InternalOperation: admodel.InternalLdapWriteRename, InternalDn: "CN=a", InternalNewRDN: "CN=b", InternalNewParent: "CN=bad\x00"},
		{InternalOperation: admodel.InternalLdapWriteRename, InternalDn: "CN=a", InternalNewRDN: "CN=b", InternalNewParent: string([]byte{255})},
		{InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "CN=a", InternalNewParent: "CN=b"},
	} {
		// Invalid input must fail before session access, retaining its validation
		// error rather than returning the closed-session error.
		session := &adengine.InternalLdapSession{}
		attempt := session.InternalLdapWriteWith(
			context.Background(),
			request,
			adengine.InternalLdapWriteAPI{},
		)
		if !errors.Is(attempt.Err, admodel.ErrInvalidResult) ||
			attempt.State != admodel.InternalLdapWriteNotAttempted {
			t.Fatal(attempt)
		}
	}
}
