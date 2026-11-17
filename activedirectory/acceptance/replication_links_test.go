package acceptance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

const (
	InternalLinkTestIP         = "CN=IP,CN=Inter-Site Transports,CN=Sites," + InternalTopologyTestConfiguration
	InternalLinkTestSMTP       = "CN=SMTP,CN=Inter-Site Transports,CN=Sites," + InternalTopologyTestConfiguration
	InternalLinkTestDN         = "CN=AB," + InternalLinkTestIP
	InternalLinkTestConnection = "CN=Connection,CN=NTDS Settings," + InternalTopologyTestServer
)

type InternalLinkTestSession struct {
	*InternalTopologyTestSession
	InternalRangeRead func(context.Context, string, []string) (map[string][][]byte, error)
}

func (s *InternalLinkTestSession) InternalRangedBaseObject(
	ctx context.Context,
	dn string,
	attrs []string,
) (map[string][][]byte, error) {
	if s.InternalRangeRead != nil {
		return s.InternalRangeRead(ctx, dn, attrs)
	}
	object, ok := s.InternalLookup(dn)
	if !ok {
		return nil, &admodel.LDAPError{Code: 32}
	}
	attribute, _, _ := strings.Cut(attrs[0], ";")
	values, exists := object.Attributes[strings.ToLower(attribute)]
	result := map[string][][]byte{
		"objectguid": object.Attributes["objectguid"],
		"usnchanged": object.Attributes["usnchanged"],
	}
	if exists {
		result[strings.ToLower(attribute)] = values
	}
	return result, nil
}

func InternalNewLinkTestClient(
	t *testing.T,
	lds bool,
) (*adengine.Client, *InternalLinkTestSession) {
	t.Helper()
	client, base := InternalNewTopologyTestClient(t, lds)
	s := &InternalLinkTestSession{InternalTopologyTestSession: base}
	(*adengine.InternalClientSessionPointer(client)) = s
	rows := []admodel.Object{
		InternalTopologyTestObject(InternalLinkTestIP, "interSiteTransport", 40),
		InternalTopologyTestObject(InternalLinkTestSMTP, "interSiteTransport", 41),
		InternalTopologyTestObject(InternalLinkTestDN, "siteLink", 42),
		InternalTopologyTestObject(InternalLinkTestConnection, "nTDSConnection", 43),
		InternalTopologyTestObject("CN=DC2,CN=Servers,"+InternalTopologyTestSiteB, "server", 44),
		InternalTopologyTestObject(
			"CN=NTDS Settings,CN=DC2,CN=Servers,"+InternalTopologyTestSiteB,
			"nTDSDSA",
			45,
		),
	}
	for _, row := range rows {
		switch {
		case admodel.InternalTopologyClass(row, "siteLink") == nil:
			row.Attributes["options"] = [][]byte{[]byte("-2147483648")}
			row.Attributes["sitelist"] = [][]byte{
				[]byte(InternalTopologyTestSiteA),
				[]byte(InternalTopologyTestSiteB),
			}
			row.Attributes["cost"] = [][]byte{[]byte("100")}
			row.Attributes["replinterval"] = [][]byte{[]byte("180")}
		case admodel.InternalTopologyClass(row, "nTDSConnection") == nil:
			row.Attributes["options"] = [][]byte{[]byte("257")}
			row.Attributes["enabledconnection"] = [][]byte{[]byte("TRUE")}
			row.Attributes["fromserver"] = [][]byte{
				[]byte("CN=NTDS Settings,CN=DC2,CN=Servers," + InternalTopologyTestSiteB),
			}
		}
		s.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
	}
	return client, s
}

func TestReplicationLinksLifecycleAndNativeAtomicMembership(t *testing.T) {
	for _, lds := range []bool{false, true} {
		t.Run(fmt.Sprint(lds), func(t *testing.T) {
			client, s := InternalNewLinkTestClient(t, lds)
			siteA, siteB := InternalTopologyTestIdentity(
				InternalTopologyTestSiteA,
			), InternalTopologyTestIdentity(
				InternalTopologyTestSiteB,
			)
			var schedule admodel.ReplicationSchedule
			schedule[2][15][3] = true
			created, err := adservice_replication.New(client).
				CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "Unicode-新", Sites: []admodel.Identity{siteA, siteB}, Schedule: &schedule})
			if err != nil || !created.Mutation.Verified || created.Link == nil ||
				*created.Link.Cost != 100 ||
				*created.Link.ReplicationFrequencyInMinutes != 180 ||
				len(created.AfterReferences.References) != 2 ||
				*created.Link.Schedule != schedule {
				t.Fatal(created, err)
			}
			if len(s.InternalWrites) != 1 ||
				s.InternalWrites[0].InternalOperation != admodel.InternalLdapWriteAdd {
				t.Fatal(s.InternalWrites)
			}
			third := InternalTopologyTestObject(
				"CN=C,CN=Sites,"+InternalTopologyTestConfiguration,
				"site",
				46,
			)
			s.InternalObjects[strings.ToLower(third.DistinguishedName)] = third
			updated, err := adservice_replication.New(client).
				UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestDN), Sites: admodel.ReplicationReferenceChanges{Remove: []admodel.Identity{siteA}, Add: []admodel.Identity{InternalTopologyTestIdentity(third.DistinguishedName)}}, SetOptions: admodel.ReplicationSiteLinkUseNotify})
			if err != nil || !updated.Mutation.Verified ||
				uint32(*updated.Link.Options) != 0x80000001 ||
				len(updated.AfterReferences.References) != 2 {
				t.Fatal(updated, err)
			}
			mods := s.InternalWrites[1].InternalModifications
			if len(mods) != 4 || mods[0].InternalOperation != 1 ||
				string(mods[0].InternalValues[0]) != "-2147483648" ||
				mods[1].InternalOperation != 0 ||
				string(mods[1].InternalValues[0]) != "-2147483647" ||
				mods[2].InternalAttribute != "siteList" ||
				mods[2].InternalOperation != 1 ||
				mods[3].InternalOperation != 0 {
				t.Fatal(mods)
			}
			bridge, err := adservice_replication.New(client).
				CreateReplicationSiteLinkBridge(context.Background(), admodel.CreateReplicationSiteLinkBridgeRequest{Name: "bridge", SiteLinks: []admodel.Identity{InternalTopologyTestIdentity(InternalLinkTestDN), admodel.InternalObjectGUIDIdentity(*created.Link.GUID)}})
			if err != nil || !bridge.Mutation.Verified ||
				len(bridge.AfterReferences.References) != 2 {
				t.Fatal(bridge, err)
			}
			read, err := adservice_replication.New(client).
				ReplicationSiteLinkBridge(context.Background(), admodel.InternalObjectGUIDIdentity(*bridge.Bridge.GUID), admodel.ReplicationLinkReadOptions{})
			if err != nil || !read.SiteLinks.Complete || len(read.SiteLinks.References) != 2 {
				t.Fatal(read, err)
			}
			bridges, err := adservice_replication.New(client).
				ReplicationSiteLinkBridges(context.Background(), admodel.ReplicationTransportIP, admodel.SearchOptions{}, admodel.ReplicationReferenceLimits{})
			if err != nil || len(bridges.Bridges) != 1 || !bridges.Observation.Complete {
				t.Fatal(bridges, err)
			}
			for _, identity := range []admodel.Identity{admodel.InternalObjectGUIDIdentity(*bridge.Bridge.GUID), admodel.InternalObjectGUIDIdentity(*created.Link.GUID)} {
				var result admodel.ObjectMutationResult
				if identity.String() == bridge.Bridge.GUID.String() {
					result, err = adservice_replication.New(client).
						DeleteReplicationSiteLinkBridge(context.Background(), identity, admodel.ObjectMutationOptions{})
				} else {
					result, err = adservice_replication.New(client).
						DeleteReplicationSiteLink(context.Background(), identity, admodel.ObjectMutationOptions{})
				}
				if err != nil || !result.AbsentAfter || !result.Verified {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestReplicationLinkInvalidReferenceAndInputsDoNotWrite(t *testing.T) {
	for _, kind := range []string{"cost", "interval", "foreign", "class", "mixed-transport", "overlap", "raw", "lds-smtp"} {
		t.Run(kind, func(t *testing.T) {
			client, s := InternalNewLinkTestClient(t, kind == "lds-smtp")
			var err error
			switch kind {
			case "cost":
				_, err = adservice_replication.New(client).
					UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestDN), Cost: InternalTopologyPointer(int32(-1))})
			case "interval":
				_, err = adservice_replication.New(client).
					CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "bad", ReplicationFrequencyInMinutes: InternalTopologyPointer(int32(16))})
			case "foreign":
				_, err = adservice_replication.New(client).
					CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "bad", Sites: []admodel.Identity{InternalTopologyTestIdentity("CN=X,DC=elsewhere")}})
			case "class":
				_, err = adservice_replication.New(client).
					CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "bad", Sites: []admodel.Identity{InternalTopologyTestIdentity(InternalTopologyTestServer)}})
			case "mixed-transport":
				_, err = adservice_replication.New(client).
					CreateReplicationSiteLinkBridge(context.Background(), admodel.CreateReplicationSiteLinkBridgeRequest{Name: "bad", Transport: admodel.ReplicationTransportSMTP, SiteLinks: []admodel.Identity{InternalTopologyTestIdentity(InternalLinkTestDN)}})
			case "overlap":
				_, err = adservice_replication.New(client).
					UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestDN), Sites: admodel.ReplicationReferenceChanges{Add: []admodel.Identity{InternalTopologyTestIdentity(InternalTopologyTestSiteA)}, Remove: []admodel.Identity{InternalTopologyTestIdentity(InternalTopologyTestSiteA)}}})
			case "raw":
				_, err = adservice_replication.New(client).
					UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestDN), Changes: []admodel.AttributeChange{{Attribute: "siteList", Kind: admodel.AttributeClear}}})
			case "lds-smtp":
				_, err = adservice_replication.New(client).
					CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "bad", Transport: admodel.ReplicationTransportSMTP})
			}
			if err == nil || len(s.InternalWrites) != 0 {
				t.Fatal(err, s.InternalWrites)
			}
		})
	}
}

func TestReplicationLinkWriteStatesAndNoReplay(t *testing.T) {
	for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			client, s := InternalNewLinkTestClient(t, false)
			s.InternalFailAt = 1
			s.InternalFailure = admodel.InternalLdapWriteAttempt{
				State: state,
				Err:   &admodel.LDAPError{Code: 50},
			}
			result, err := adservice_replication.New(client).
				UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestDN), Cost: InternalTopologyPointer(int32(200))})
			if err == nil || len(s.InternalWrites) != 1 || result.Mutation.Verified ||
				result.Mutation.State == admodel.ObjectWriteAccepted {
				t.Fatal(result, err, s.InternalWrites)
			}
		})
	}
}

func TestReplicationLinkClearOmissionIsAcceptedUnverified(t *testing.T) {
	client, s := InternalNewLinkTestClient(t, false)
	result, err := adservice_replication.New(client).
		UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestDN), Sites: admodel.ReplicationReferenceChanges{Replace: []admodel.Identity{}}})
	if !errors.Is(err, admodel.ErrObjectVerification) ||
		result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.Mutation.Verified ||
		result.AfterReferences.AttributeReturned ||
		!result.AfterReferences.Complete ||
		len(s.InternalWrites) != 1 {
		t.Fatal(result, err)
	}
}

func TestReplicationConnectionUpdatePreservesFlagsAndScheduleOwnership(t *testing.T) {
	client, s := InternalNewLinkTestClient(t, false)
	var schedule admodel.ReplicationSchedule
	schedule[3][1][2] = true
	result, err := adservice_replication.New(client).
		UpdateReplicationConnection(context.Background(), admodel.UpdateReplicationConnectionRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestConnection), Schedule: &schedule, Enabled: InternalTopologyPointer(false), SetOptions: admodel.ReplicationConnectionUserOwnedSchedule})
	if err != nil || !result.Mutation.Verified || *result.Connection.Enabled ||
		uint32(*result.Connection.Options) != 289 ||
		*result.Connection.Schedule != schedule ||
		len(s.InternalWrites) != 1 {
		t.Fatal(result, err)
	}
	read, err := adservice_replication.New(client).
		ReplicationConnections(context.Background(), admodel.SearchOptions{})
	if err != nil || len(read.Connections) != 1 {
		t.Fatal(read, err)
	}
	for _, source := range []admodel.Identity{InternalTopologyTestIdentity(InternalTopologyTestServer), InternalTopologyTestIdentity(InternalTopologyTestSiteA)} {
		before := len(s.InternalWrites)
		_, err = adservice_replication.New(client).
			UpdateReplicationConnection(context.Background(), admodel.UpdateReplicationConnectionRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestConnection), ReplicateFromDirectoryServer: &source})
		if err == nil || len(s.InternalWrites) != before {
			t.Fatal(err, s.InternalWrites)
		}
	}
	guid, _ := admodel.InternalTopologyGUID(*result.Mutation.After)
	_, err = adservice_replication.New(client).
		UpdateReplicationConnection(context.Background(), admodel.UpdateReplicationConnectionRequest{Identity: admodel.InternalObjectGUIDIdentity(guid), Options: admodel.ObjectMutationOptions{ExpectedVersion: &admodel.ObjectVersion{Source: (*adengine.InternalClientConfigPointer(client)).Endpoint, GUID: guid, USNChanged: 7}}})
	if !errors.Is(err, admodel.ErrObjectControlUnsupported) || len(s.InternalWrites) != 1 {
		t.Fatal(err, s.InternalWrites)
	}
}

func TestReplicationReferenceRangesRetainRawFailures(t *testing.T) {
	for _, failure := range []string{"none", "gap", "duplicate", "version", "guid", "permission", "missing-tail", "count", "limit", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			client, s := InternalNewLinkTestClient(t, false)
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.InternalRangeRead = func(_ context.Context, _ string, properties []string) (map[string][][]byte, error) {
				calls++
				row, _ := s.InternalLookup(InternalLinkTestDN)
				attrs := map[string][][]byte{
					"objectguid": row.Attributes["objectguid"],
					"usnchanged": {[]byte("7")},
				}
				if calls == 1 {
					attrs["siteList;range=0-0"] = [][]byte{[]byte(InternalTopologyTestSiteA)}
					if failure == "cancel" {
						cancel()
					}
					return attrs, nil
				}
				if !strings.Contains(properties[0], "range=1-") {
					t.Fatal(properties)
				}
				attrs["siteList;range=1-*"] = [][]byte{[]byte(InternalTopologyTestSiteB)}
				switch failure {
				case "gap":
					delete(attrs, "siteList;range=1-*")
					attrs["siteList;range=2-*"] = [][]byte{[]byte(InternalTopologyTestSiteB)}
				case "duplicate":
					attrs["siteList;range=1-*"] = [][]byte{
						[]byte(strings.ToLower(InternalTopologyTestSiteA)),
					}
				case "version":
					attrs["usnchanged"] = [][]byte{[]byte("8")}
				case "guid":
					attrs["objectguid"] = [][]byte{make([]byte, 16)}
				case "permission":
					return attrs, &admodel.LDAPError{Code: 50}
				case "missing-tail":
					delete(attrs, "siteList;range=1-*")
				case "count":
					delete(attrs, "siteList;range=1-*")
					attrs["siteList;range=1-3"] = [][]byte{[]byte(InternalTopologyTestSiteB)}
				}
				return attrs, nil
			}
			limits := admodel.ReplicationReferenceLimits{}
			if failure == "limit" {
				limits.MaxRanges = 1
			}
			result, err := adservice_replication.New(client).
				ReplicationSiteLink(ctx, InternalTopologyTestIdentity(InternalLinkTestDN), admodel.ReplicationLinkReadOptions{References: limits})
			if failure == "none" {
				if err != nil || !result.Sites.Complete || len(result.Sites.References) != 2 {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || result.Sites.Complete || len(result.Sites.Ranges) == 0 ||
				(len(result.Sites.References) == 0 && failure != "cancel") ||
				result.Sites.Error == nil {
				t.Fatal(result, err)
			}
			if failure == "permission" {
				var ldapErr *admodel.LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != 50 ||
					len(result.Sites.References) != 2 {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestReplicationReferenceDNKeyMatchesStructuralEquality(t *testing.T) {
	values := []string{
		`CN=a\,b+OU=K,DC=example`,
		`ou=\4b+cn=A\2Cb,dc=EXAMPLE`,
		`CN=a\,b+OU=K,DC=example`,
		`CN=Σ,DC=example`,
		`CN=ς,DC=example`,
		`CN=σ,DC=example`,
		`CN=#0041,DC=example`,
		`CN=#0061,DC=example`,
		`CN=K,DC=example`,
		`CN=K,DC=example`,
		`CN=ß,DC=example`,
		`CN=ss,DC=example`,
		`CN=x+CN=x,DC=example`,
		`CN=x,DC=example`,
		`CN=x+OU=y,DC=example`,
		`OU=y+CN=x,DC=example`,
	}
	for _, left := range values {
		a, err := admodel.InternalParseIdentityDN(left)
		if err != nil {
			t.Fatal(err)
		}
		for _, right := range values {
			b, err := admodel.InternalParseIdentityDN(right)
			if err != nil {
				t.Fatal(err)
			}
			if (admodel.InternalIdentityDNKey(a) == admodel.InternalIdentityDNKey(b)) != admodel.InternalSameIdentityDN(
				a,
				b,
			) {
				t.Fatalf("key mismatch: %q / %q", left, right)
			}
		}
	}
}

func TestReplicationReferencesLargeTerminalRange(t *testing.T) {
	_, session := InternalNewLinkTestClient(t, false)
	object, _ := session.InternalLookup(InternalLinkTestDN)
	values := make([][]byte, 100000)
	for i := range values {
		values[i] = []byte(
			fmt.Sprintf("CN=site-%d,CN=Sites,%s", i, InternalTopologyTestConfiguration),
		)
	}
	session.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
		return map[string][][]byte{
			"siteList;range=0-*": values,
			"objectguid":         object.Attributes["objectguid"],
			"usnchanged":         object.Attributes["usnchanged"],
		}, nil
	}
	limits, _ := admodel.InternalNormalizeReplicationReferenceLimits(
		admodel.ReplicationReferenceLimits{},
	)
	result, err := admodel.InternalCollectReplicationReferences(
		context.Background(),
		session,
		object,
		"siteList",
		limits,
	)
	if err != nil || !result.Complete || len(result.References) != len(values) {
		t.Fatal(len(result.References), err)
	}
	// Cancellation after receiving a large batch must retain the raw batch and
	// stop before decoding all its references.
	ctx, cancel := context.WithCancel(context.Background())
	session.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
		cancel()
		return map[string][][]byte{
			"siteList;range=0-*": values,
			"objectguid":         object.Attributes["objectguid"],
			"usnchanged":         object.Attributes["usnchanged"],
		}, nil
	}
	result, err = admodel.InternalCollectReplicationReferences(
		ctx,
		session,
		object,
		"siteList",
		limits,
	)
	if !errors.Is(err, context.Canceled) || len(result.Ranges) != 1 ||
		len(result.References) != 0 ||
		len(result.Ranges[0].Attributes["siteList;range=0-*"]) != 100000 {
		t.Fatal(result.Complete, len(result.References), err)
	}
}

func TestReplicationLinkAndConnectionNoOpRequestedProperties(t *testing.T) {
	for _, connection := range []bool{false, true} {
		t.Run(fmt.Sprint(connection), func(t *testing.T) {
			client, s := InternalNewLinkTestClient(t, false)
			target := InternalLinkTestDN
			if connection {
				target = InternalLinkTestConnection
			}
			original := s.InternalSearch
			selected := false
			s.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				if admodel.InternalTopologySameDN(query.Base, target) {
					selected = slices.Contains(query.Properties, "customProperty")
				}
				return original(ctx, query)
			}
			row := s.InternalObjects[strings.ToLower(target)]
			row.Attributes["customproperty"] = [][]byte{[]byte("retained")}
			s.InternalObjects[strings.ToLower(target)] = row
			options := admodel.ObjectMutationOptions{Properties: []string{"customProperty"}}
			var mutation admodel.ObjectMutationResult
			var err error
			if connection {
				result, e := adservice_replication.New(client).
					UpdateReplicationConnection(context.Background(), admodel.UpdateReplicationConnectionRequest{Identity: InternalTopologyTestIdentity(target), Options: options})
				mutation, err = result.Mutation, e
			} else {
				result, e := adservice_replication.New(client).
					UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(target), Options: options})
				mutation, err = result.Mutation, e
			}
			if err != nil || !selected || !mutation.Verified || !mutation.ReadbackComplete ||
				mutation.After == nil ||
				string(mutation.After.Attributes["customproperty"][0]) != "retained" ||
				len(s.InternalWrites) != 0 {
				t.Fatal(selected, mutation, err)
			}
		})
	}
}

func TestReplicationReferenceParserBoundaries(t *testing.T) {
	for _, test := range []struct {
		InternalName    string
		InternalAttrs   map[string][][]byte
		InternalStart   uint64
		InternalWantErr bool
		InternalPresent bool
	}{{"omitted", nil, 0, false, false}, {"empty", map[string][][]byte{"siteList": {}}, 0, false, true}, {"empty-plus-range", map[string][][]byte{"siteList": {}, "siteList;range=0-*": {[]byte(InternalTopologyTestSiteA)}}, 0, false, true}, {"ambiguous", map[string][][]byte{"siteList": {[]byte(InternalTopologyTestSiteA)}, "siteList;range=0-*": {[]byte(InternalTopologyTestSiteB)}}, 0, true, true}, {"duplicate-descriptor", map[string][][]byte{"siteList;range=0-*": {}, "SITELIST;range=0-*": {}}, 0, true, true}, {"overflow", map[string][][]byte{"siteList;range=0-18446744073709551615": {}}, 0, true, true}, {"missing-continuation", nil, 1, true, false}} {
		t.Run(test.InternalName, func(t *testing.T) {
			_, _, _, present, err := admodel.InternalDirectoryReferenceRange(
				test.InternalAttrs,
				"siteList",
				test.InternalStart,
			)
			if (err != nil) != test.InternalWantErr || present != test.InternalPresent {
				t.Fatal(present, err)
			}
		})
	}
}

func TestReplicationLinkReadbackFailureRetainsAccepted(t *testing.T) {
	client, s := InternalNewLinkTestClient(t, false)
	s.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
		return map[string][][]byte{
				"siteList;range=0-*": {[]byte(InternalTopologyTestSiteA)},
			}, &admodel.LDAPError{
				Code: 50,
			}
	}
	result, err := adservice_replication.New(client).
		CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "partial", Sites: []admodel.Identity{InternalTopologyTestIdentity(InternalTopologyTestSiteA)}})
	if err == nil || result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.Mutation.Verified ||
		len(result.AfterReferences.Ranges) != 1 ||
		len(result.AfterReferences.References) != 1 ||
		len(s.InternalWrites) != 1 {
		t.Fatal(result, err)
	}
}

func TestReplicationLinkUnknownAttributeValuesPreserved(t *testing.T) {
	client, s := InternalNewLinkTestClient(t, false)
	row := s.InternalObjects[strings.ToLower(InternalLinkTestDN)]
	row.Attributes["unknown"] = [][]byte{{0, 255, 1}}
	s.InternalObjects[strings.ToLower(InternalLinkTestDN)] = row
	result, err := adservice_replication.New(client).
		UpdateReplicationSiteLink(context.Background(), admodel.UpdateReplicationSiteLinkRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestDN), Cost: InternalTopologyPointer(int32(500)), Options: admodel.ObjectMutationOptions{Properties: []string{"unknown"}}})
	if err != nil || !result.Mutation.Verified ||
		!slices.Equal(result.Link.Raw.Attributes["unknown"][0], []byte{0, 255, 1}) {
		t.Fatal(result, err)
	}
}

func TestReplicationBridgeMembershipUpdateAndConnectionSourceTransport(t *testing.T) {
	client, s := InternalNewLinkTestClient(t, false)
	bridge, err := adservice_replication.New(client).
		CreateReplicationSiteLinkBridge(context.Background(), admodel.CreateReplicationSiteLinkBridgeRequest{Name: "mutable", SiteLinks: []admodel.Identity{InternalTopologyTestIdentity(InternalLinkTestDN)}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := adservice_replication.New(client).
		CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "second"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := adservice_replication.New(client).
		UpdateReplicationSiteLinkBridge(context.Background(), admodel.UpdateReplicationSiteLinkBridgeRequest{Identity: admodel.InternalObjectGUIDIdentity(*bridge.Bridge.GUID), Description: InternalTopologyPointer("preserved metadata"), SiteLinks: admodel.ReplicationReferenceChanges{Remove: []admodel.Identity{InternalTopologyTestIdentity(InternalLinkTestDN)}, Add: []admodel.Identity{admodel.InternalObjectGUIDIdentity(*second.Link.GUID)}}})
	if err != nil || !updated.Mutation.Verified || len(updated.AfterReferences.References) != 1 ||
		!admodel.InternalTopologySameDN(
			updated.AfterReferences.References[0].DistinguishedName,
			second.Link.Raw.DistinguishedName,
		) {
		t.Fatal(updated, err)
	}
	source := InternalTopologyTestIdentity("CN=DC2,CN=Servers," + InternalTopologyTestSiteB)
	connection, err := adservice_replication.New(client).
		UpdateReplicationConnection(context.Background(), admodel.UpdateReplicationConnectionRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestConnection), ReplicateFromDirectoryServer: &source, Transport: InternalTopologyPointer(admodel.ReplicationTransportSMTP), SetOptions: admodel.ReplicationConnectionIgnoreSchedule})
	if err != nil || !connection.Mutation.Verified || connection.SourceSettings.Object == nil ||
		*connection.Connection.FromServerDN != "CN=NTDS Settings,"+source.String() ||
		*connection.Connection.TransportDN != InternalLinkTestSMTP ||
		uint32(*connection.Connection.Options) != 0x80000101 {
		t.Fatal(connection, err)
	}
	if len(s.InternalWrites) != 4 {
		t.Fatal("unexpected replay", len(s.InternalWrites))
	}
	lds, observed := InternalNewLinkTestClient(t, true)
	_, err = adservice_replication.New(lds).
		UpdateReplicationConnection(context.Background(), admodel.UpdateReplicationConnectionRequest{Identity: InternalTopologyTestIdentity(InternalLinkTestConnection), Transport: InternalTopologyPointer(admodel.ReplicationTransportSMTP)})
	if !errors.Is(err, admodel.ErrUnsupported) || len(observed.InternalWrites) != 0 {
		t.Fatal(err, observed.InternalWrites)
	}
}

func TestReplicationLinkCreationRejectsTypedRawDescriptionConflictBeforeIO(t *testing.T) {
	for _, bridge := range []bool{false, true} {
		for _, attribute := range []string{"description", "DeScRiPtIoN"} {
			t.Run(fmt.Sprintf("bridge=%v/%s", bridge, attribute), func(t *testing.T) {
				client, session := InternalNewLinkTestClient(t, false)
				reads := 0
				original := session.InternalRead
				session.InternalRead = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
					reads++
					return original(ctx, properties)
				}
				attributes := map[string][]admodel.RawValue{
					attribute: {admodel.NewRawValue([]byte("raw"))},
				}
				var err error
				if bridge {
					_, err = adservice_replication.New(client).
						CreateReplicationSiteLinkBridge(context.Background(), admodel.CreateReplicationSiteLinkBridgeRequest{Name: "conflict", Description: InternalTopologyPointer("typed"), Attributes: attributes})
				} else {
					_, err = adservice_replication.New(client).
						CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "conflict", Description: InternalTopologyPointer("typed"), Attributes: attributes})
				}
				if !errors.Is(err, admodel.ErrInvalidObjectMutation) || reads != 0 ||
					len(session.InternalWrites) != 0 {
					t.Fatal(reads, session.InternalWrites, err)
				}
				var result admodel.ReplicationLinkMutationResult
				if bridge {
					result, err = adservice_replication.New(client).
						CreateReplicationSiteLinkBridge(context.Background(), admodel.CreateReplicationSiteLinkBridgeRequest{Name: "raw-only", Attributes: attributes})
				} else {
					result, err = adservice_replication.New(client).
						CreateReplicationSiteLink(context.Background(), admodel.CreateReplicationSiteLinkRequest{Name: "raw-only", Attributes: attributes})
				}
				if err != nil || !result.Mutation.Verified ||
					string(result.Mutation.After.Attributes["description"][0]) != "raw" {
					t.Fatal(result, err)
				}
			})
		}
	}
}
