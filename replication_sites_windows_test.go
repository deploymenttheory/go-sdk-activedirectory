//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type topologyWireSession struct {
	*topologyTestSession
	native *ldapSession
	calls  int
}

func (s *topologyWireSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	s.calls++
	attempt := s.native.ldapWrite(ctx, request)
	if attempt.State == ldapWriteAccepted {
		if observed := s.topologyTestSession.ldapWrite(ctx, request); observed.Err != nil {
			return observed
		}
	}
	return attempt
}

func TestNativeDirectoryServerMoveNewParentAndAssertionWire(t *testing.T) {
	for _, code := range []byte{0, 32, 50, 68} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			client, observations := newTopologyTestClient(t, false)
			destination := "CN=Zürich-新,CN=Sites," + topologyTestConfiguration
			// A Unicode destination exercises NewParent's binding conversion separately
			// from the existing RDN input; no live directory is involved.
			var moved []Object
			for key, object := range observations.objects {
				if strings.HasSuffix(object.DistinguishedName, topologyTestSiteB) {
					delete(observations.objects, key)
					object.DistinguishedName = strings.TrimSuffix(object.DistinguishedName, topologyTestSiteB) + destination
					moved = append(moved, object)
				}
			}
			for _, object := range moved {
				observations.objects[strings.ToLower(object.DistinguishedName)] = object
			}
			guid, _ := GUIDFromBytes(append([]byte{12}, make([]byte, 15)...))
			version := ObjectVersion{Source: client.config.Endpoint, GUID: guid, USNChanged: 7}
			want := append(searchBER(4, []byte("<GUID=0c000000000000000000000000000000>")), searchBER(4, []byte("cn=DC1"))...)
			want = append(want, 1, 1, 255)
			want = append(want, searchBER(0x80, []byte("CN=Servers,"+destination))...)
			controls := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte(objectAssertionControl)), []byte{1, 1, 255}, searchBER(4, objectVersionAssertion(version))))
			fixture := newWriteWireFixture(t, 0x6c, 0x6d, want, controls, code)
			var owners searchNativeCounts
			wireClient := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			session := &topologyWireSession{topologyTestSession: observations, native: wireClient.session.(*ldapSession)}
			client.session = session
			result, err := client.MoveDirectoryServer(context.Background(), MoveDirectoryServerRequest{Server: topologyTestIdentity(topologyTestServer), Site: topologyTestIdentity(destination), Options: ObjectMutationOptions{ExpectedVersion: &version}})
			if session.calls != 1 {
				t.Fatal("native write replay", session.calls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) || ldapErr.Diagnostic != "private wire diagnostic" || result.Mutation.State != ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err := wireClient.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (searchNativeCounts{}) {
				t.Fatal("native owners leaked", owners)
			}
		})
	}
}

func TestNativeReplicationSiteBinaryScheduleWire(t *testing.T) {
	client, observations := newTopologyTestClient(t, false)
	var schedule ReplicationSchedule
	schedule[0][0][0] = true
	schedule[6][23][3] = true
	wire := make([]byte, 188)
	wire[0] = 188
	wire[8] = 1
	wire[16] = 20
	wire[20] = 1
	wire[187] = 8
	mod := searchBER(0x30, []byte{10, 1, 2}, searchBER(0x30, searchBER(4, []byte("schedule")), searchBER(0x31, searchBER(4, wire))))
	want := append(searchBER(4, []byte("<GUID=09000000000000000000000000000000>")), searchBER(0x30, mod)...)
	fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, 0)
	var owners searchNativeCounts
	wireClient := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
	session := &topologyWireSession{topologyTestSession: observations, native: wireClient.session.(*ldapSession)}
	client.session = session
	result, err := client.UpdateReplicationSite(context.Background(), UpdateReplicationSiteRequest{Identity: topologyTestIdentity(topologyTestSiteB), Settings: &ReplicationSiteSettingsPatch{Schedule: &schedule}})
	if err != nil || !result.Complete || session.calls != 1 || *result.After.Site.Settings.Schedule != schedule {
		t.Fatal(result, err)
	}
	if err := wireClient.Close(); err != nil {
		t.Fatal(err)
	}
	if owners != (searchNativeCounts{}) {
		t.Fatal(owners)
	}
}

func TestNativeWriteParentValidationDoesNotDispatch(t *testing.T) {
	for _, request := range []ldapWriteRequest{
		{operation: ldapWriteRename, dn: "CN=a", newRDN: "CN=b", newParent: "CN=bad\x00"},
		{operation: ldapWriteRename, dn: "CN=a", newRDN: "CN=b", newParent: string([]byte{255})},
		{operation: ldapWriteDelete, dn: "CN=a", newParent: "CN=b"},
	} {
		// Invalid input must fail before session access, retaining its validation
		// error rather than returning the closed-session error.
		session := &ldapSession{}
		attempt := session.ldapWriteWith(context.Background(), request, ldapWriteAPI{})
		if !errors.Is(attempt.Err, ErrInvalidResult) || attempt.State != ldapWriteNotAttempted {
			t.Fatal(attempt)
		}
	}
}
