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

type InternalLinkWireSession struct {
	*InternalLinkTestSession
	InternalNative *adengine.InternalLdapSession
	InternalCalls  int
}

func (s *InternalLinkWireSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	s.InternalCalls++
	attempt := s.InternalNative.InternalLdapWrite(ctx, request)
	if attempt.State == admodel.InternalLdapWriteAccepted {
		if applied := s.InternalTopologyTestSession.InternalLdapWrite(
			ctx,
			request,
		); applied.Err != nil {
			return applied
		}
	}
	return attempt
}

func TestNativeReplicationLinkAtomicReferencesAndAssertion(t *testing.T) {
	for _, code := range []byte{0, 20, 50} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			client, observed := InternalNewLinkTestClient(t, false)
			third := "CN=Zürich-新,CN=Sites," + InternalTopologyTestConfiguration
			row := InternalTopologyTestObject(third, "site", 46)
			observed.InternalObjects[strings.ToLower(third)] = row
			object, _ := observed.InternalLookup(InternalLinkTestDN)
			guid, _ := admodel.InternalTopologyGUID(object)
			version := admodel.ObjectVersion{
				Source:     adengine.InternalClientConfig(client).Endpoint,
				GUID:       guid,
				USNChanged: 7,
			}
			remove := InternalSearchBER(
				0x30,
				[]byte{10, 1, 1},
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte("siteList")),
					InternalSearchBER(
						0x31,
						InternalSearchBER(4, []byte(InternalTopologyTestSiteA)),
					),
				),
			)
			add := InternalSearchBER(
				0x30,
				[]byte{10, 1, 0},
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte("siteList")),
					InternalSearchBER(0x31, InternalSearchBER(4, []byte(third))),
				),
			)
			want := append(
				InternalSearchBER(4, []byte(admodel.InternalObjectGUIDTarget(guid))),
				InternalSearchBER(0x30, remove, add)...)
			controls := InternalSearchBER(
				0xa0,
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte(admodel.InternalObjectAssertionControl)),
					[]byte{1, 1, 255},
					InternalSearchBER(4, admodel.InternalObjectVersionAssertion(version)),
				),
			)
			fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, controls, code)
			var owners InternalSearchNativeCounts
			wire := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&owners),
			)
			session := &InternalLinkWireSession{
				InternalLinkTestSession: observed,
				InternalNative:          (*adengine.InternalClientSessionPointer(wire)).(*adengine.InternalLdapSession),
			}
			(*adengine.InternalClientSessionPointer(client)) = session
			result, err := adservice_replication.New(client).
				UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestDN), Sites: admodel.ReplicationReferenceChanges{Remove: []admodel.Identity{InternalTopologyTestIdentity(InternalTopologyTestSiteA)}, Add: []admodel.Identity{InternalTopologyTestIdentity(third)}}, Options: admodel.ObjectMutationOptions{ExpectedVersion: &version}})
			if session.InternalCalls != 1 {
				t.Fatal("replayed", session.InternalCalls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified ||
					len(result.AfterReferences.References) != 2 {
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
				t.Fatal("native ownership", owners)
			}
		})
	}
}

func TestNativeReplicationReferencesRangeTerminalAndPartialError(t *testing.T) {
	for _, code := range []byte{0, 50} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			object := InternalTopologyTestObject(InternalLinkTestDN, "siteLink", 42)
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
						InternalCount:      1,
						InternalBaseRead:   true,
						InternalDn:         InternalLinkTestDN,
						InternalAttributes: attrs("siteList;range=0-0", InternalTopologyTestSiteA),
					},
					{
						InternalCount:      1,
						InternalBaseRead:   true,
						InternalDn:         InternalLinkTestDN,
						InternalCode:       code,
						InternalAttributes: attrs("siteList;range=1-*", InternalTopologyTestSiteB),
					},
				},
			)
			var owners InternalSearchNativeCounts
			client := InternalSearchWireClient(t, fixture, InternalCountedSearchAPI(&owners))
			limits, _ := admodel.InternalNormalizeReplicationReferenceLimits(
				admodel.ReplicationReferenceLimits{},
			)
			result, err := admodel.InternalCollectReplicationReferences(
				context.Background(),
				adengine.InternalClientSession(client),
				object,
				"siteList",
				limits,
			)
			if len(result.Ranges) != 2 || len(result.References) != 2 || !result.AttributeReturned {
				t.Fatal(result, err)
			}
			if code == 0 {
				if err != nil || !result.Complete {
					t.Fatal(result, err)
				}
			} else {
				var status *admodel.LDAPError
				if !errors.As(err, &status) || status.Code != 50 || result.Complete {
					t.Fatal(result, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal("native ownership", owners)
			}
		})
	}
}
