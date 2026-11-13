//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type linkWireSession struct {
	*linkTestSession
	native *ldapSession
	calls  int
}

func (s *linkWireSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	s.calls++
	attempt := s.native.ldapWrite(ctx, request)
	if attempt.State == ldapWriteAccepted {
		if applied := s.topologyTestSession.ldapWrite(ctx, request); applied.Err != nil {
			return applied
		}
	}
	return attempt
}
func TestNativeReplicationLinkAtomicReferencesAndAssertion(t *testing.T) {
	for _, code := range []byte{0, 20, 50} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			client, observed := newLinkTestClient(t, false)
			third := "CN=Zürich-新,CN=Sites," + topologyTestConfiguration
			row := topologyTestObject(third, "site", 46)
			observed.objects[strings.ToLower(third)] = row
			object, _ := observed.lookup(linkTestDN)
			guid, _ := topologyGUID(object)
			version := ObjectVersion{Source: client.config.Endpoint, GUID: guid, USNChanged: 7}
			remove := searchBER(0x30, []byte{10, 1, 1}, searchBER(0x30, searchBER(4, []byte("siteList")), searchBER(0x31, searchBER(4, []byte(topologyTestSiteA)))))
			add := searchBER(0x30, []byte{10, 1, 0}, searchBER(0x30, searchBER(4, []byte("siteList")), searchBER(0x31, searchBER(4, []byte(third)))))
			want := append(searchBER(4, []byte(objectGUIDTarget(guid))), searchBER(0x30, remove, add)...)
			controls := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte(objectAssertionControl)), []byte{1, 1, 255}, searchBER(4, objectVersionAssertion(version))))
			fixture := newWriteWireFixture(t, 0x66, 0x67, want, controls, code)
			var owners searchNativeCounts
			wire := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			session := &linkWireSession{linkTestSession: observed, native: wire.session.(*ldapSession)}
			client.session = session
			result, err := client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(linkTestDN), Sites: ReplicationReferenceChanges{Remove: []Identity{topologyTestIdentity(topologyTestSiteA)}, Add: []Identity{topologyTestIdentity(third)}}, Options: ObjectMutationOptions{ExpectedVersion: &version}})
			if session.calls != 1 {
				t.Fatal("replayed", session.calls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified || len(result.AfterReferences.References) != 2 {
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
				t.Fatal("native ownership", owners)
			}
		})
	}
}
func TestNativeReplicationReferencesRangeTerminalAndPartialError(t *testing.T) {
	for _, code := range []byte{0, 50} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			object := topologyTestObject(linkTestDN, "siteLink", 42)
			attrs := func(name, dn string) map[string][][]byte {
				return map[string][][]byte{"objectGUID": object.Attributes["objectguid"], "uSNChanged": {[]byte("7")}, name: {[]byte(dn)}}
			}
			fixture := newSearchWireFixture(t, []searchWirePage{{count: 1, baseRead: true, dn: linkTestDN, attributes: attrs("siteList;range=0-0", topologyTestSiteA)}, {count: 1, baseRead: true, dn: linkTestDN, code: code, attributes: attrs("siteList;range=1-*", topologyTestSiteB)}})
			var owners searchNativeCounts
			client := searchWireClient(t, fixture, countedSearchAPI(&owners))
			limits, _ := normalizeReplicationReferenceLimits(ReplicationReferenceLimits{})
			result, err := collectReplicationReferences(context.Background(), client.session, object, "siteList", limits)
			if len(result.Ranges) != 2 || len(result.References) != 2 || !result.AttributeReturned {
				t.Fatal(result, err)
			}
			if code == 0 {
				if err != nil || !result.Complete {
					t.Fatal(result, err)
				}
			} else {
				var status *LDAPError
				if !errors.As(err, &status) || status.Code != 50 || result.Complete {
					t.Fatal(result, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (searchNativeCounts{}) {
				t.Fatal("native ownership", owners)
			}
		})
	}
}
