package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const linkTestIP = "CN=IP,CN=Inter-Site Transports,CN=Sites," + topologyTestConfiguration
const linkTestSMTP = "CN=SMTP,CN=Inter-Site Transports,CN=Sites," + topologyTestConfiguration
const linkTestDN = "CN=AB," + linkTestIP
const linkTestConnection = "CN=Connection,CN=NTDS Settings," + topologyTestServer

type linkTestSession struct {
	*topologyTestSession
	rangeRead func(context.Context, string, []string) (map[string][][]byte, error)
}

func (s *linkTestSession) rangedBaseObject(ctx context.Context, dn string, attrs []string) (map[string][][]byte, error) {
	if s.rangeRead != nil {
		return s.rangeRead(ctx, dn, attrs)
	}
	object, ok := s.lookup(dn)
	if !ok {
		return nil, &LDAPError{Code: 32}
	}
	attribute, _, _ := strings.Cut(attrs[0], ";")
	values, exists := object.Attributes[strings.ToLower(attribute)]
	result := map[string][][]byte{"objectguid": object.Attributes["objectguid"], "usnchanged": object.Attributes["usnchanged"]}
	if exists {
		result[strings.ToLower(attribute)] = values
	}
	return result, nil
}
func newLinkTestClient(t *testing.T, lds bool) (*Client, *linkTestSession) {
	t.Helper()
	client, base := newTopologyTestClient(t, lds)
	s := &linkTestSession{topologyTestSession: base}
	client.session = s
	rows := []Object{topologyTestObject(linkTestIP, "interSiteTransport", 40), topologyTestObject(linkTestSMTP, "interSiteTransport", 41), topologyTestObject(linkTestDN, "siteLink", 42), topologyTestObject(linkTestConnection, "nTDSConnection", 43), topologyTestObject("CN=DC2,CN=Servers,"+topologyTestSiteB, "server", 44), topologyTestObject("CN=NTDS Settings,CN=DC2,CN=Servers,"+topologyTestSiteB, "nTDSDSA", 45)}
	for _, row := range rows {
		switch {
		case topologyClass(row, "siteLink") == nil:
			row.Attributes["options"] = [][]byte{[]byte("-2147483648")}
			row.Attributes["sitelist"] = [][]byte{[]byte(topologyTestSiteA), []byte(topologyTestSiteB)}
			row.Attributes["cost"] = [][]byte{[]byte("100")}
			row.Attributes["replinterval"] = [][]byte{[]byte("180")}
		case topologyClass(row, "nTDSConnection") == nil:
			row.Attributes["options"] = [][]byte{[]byte("257")}
			row.Attributes["enabledconnection"] = [][]byte{[]byte("TRUE")}
			row.Attributes["fromserver"] = [][]byte{[]byte("CN=NTDS Settings,CN=DC2,CN=Servers," + topologyTestSiteB)}
		}
		s.objects[strings.ToLower(row.DistinguishedName)] = row
	}
	return client, s
}
func TestReplicationLinksLifecycleAndNativeAtomicMembership(t *testing.T) {
	for _, lds := range []bool{false, true} {
		t.Run(fmt.Sprint(lds), func(t *testing.T) {
			client, s := newLinkTestClient(t, lds)
			siteA, siteB := topologyTestIdentity(topologyTestSiteA), topologyTestIdentity(topologyTestSiteB)
			var schedule ReplicationSchedule
			schedule[2][15][3] = true
			created, err := client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "Unicode-新", Sites: []Identity{siteA, siteB}, Schedule: &schedule})
			if err != nil || !created.Mutation.Verified || created.Link == nil || *created.Link.Cost != 100 || *created.Link.ReplicationFrequencyInMinutes != 180 || len(created.AfterReferences.References) != 2 || *created.Link.Schedule != schedule {
				t.Fatal(created, err)
			}
			if len(s.writes) != 1 || s.writes[0].operation != ldapWriteAdd {
				t.Fatal(s.writes)
			}
			third := topologyTestObject("CN=C,CN=Sites,"+topologyTestConfiguration, "site", 46)
			s.objects[strings.ToLower(third.DistinguishedName)] = third
			updated, err := client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(linkTestDN), Sites: ReplicationReferenceChanges{Remove: []Identity{siteA}, Add: []Identity{topologyTestIdentity(third.DistinguishedName)}}, SetOptions: ReplicationSiteLinkUseNotify})
			if err != nil || !updated.Mutation.Verified || uint32(*updated.Link.Options) != 0x80000001 || len(updated.AfterReferences.References) != 2 {
				t.Fatal(updated, err)
			}
			mods := s.writes[1].modifications
			if len(mods) != 4 || mods[0].operation != 1 || string(mods[0].values[0]) != "-2147483648" || mods[1].operation != 0 || string(mods[1].values[0]) != "-2147483647" || mods[2].attribute != "siteList" || mods[2].operation != 1 || mods[3].operation != 0 {
				t.Fatal(mods)
			}
			bridge, err := client.CreateReplicationSiteLinkBridge(context.Background(), CreateReplicationSiteLinkBridgeRequest{Name: "bridge", SiteLinks: []Identity{topologyTestIdentity(linkTestDN), objectGUIDIdentity(*created.Link.GUID)}})
			if err != nil || !bridge.Mutation.Verified || len(bridge.AfterReferences.References) != 2 {
				t.Fatal(bridge, err)
			}
			read, err := client.ReplicationSiteLinkBridge(context.Background(), objectGUIDIdentity(*bridge.Bridge.GUID), ReplicationLinkReadOptions{})
			if err != nil || !read.SiteLinks.Complete || len(read.SiteLinks.References) != 2 {
				t.Fatal(read, err)
			}
			bridges, err := client.ReplicationSiteLinkBridges(context.Background(), ReplicationTransportIP, SearchOptions{}, ReplicationReferenceLimits{})
			if err != nil || len(bridges.Bridges) != 1 || !bridges.Observation.Complete {
				t.Fatal(bridges, err)
			}
			for _, identity := range []Identity{objectGUIDIdentity(*bridge.Bridge.GUID), objectGUIDIdentity(*created.Link.GUID)} {
				var result ObjectMutationResult
				if identity.String() == bridge.Bridge.GUID.String() {
					result, err = client.DeleteReplicationSiteLinkBridge(context.Background(), identity, ObjectMutationOptions{})
				} else {
					result, err = client.DeleteReplicationSiteLink(context.Background(), identity, ObjectMutationOptions{})
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
			client, s := newLinkTestClient(t, kind == "lds-smtp")
			var err error
			switch kind {
			case "cost":
				_, err = client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(linkTestDN), Cost: topologyPointer(int32(-1))})
			case "interval":
				_, err = client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "bad", ReplicationFrequencyInMinutes: topologyPointer(int32(16))})
			case "foreign":
				_, err = client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "bad", Sites: []Identity{topologyTestIdentity("CN=X,DC=elsewhere")}})
			case "class":
				_, err = client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "bad", Sites: []Identity{topologyTestIdentity(topologyTestServer)}})
			case "mixed-transport":
				_, err = client.CreateReplicationSiteLinkBridge(context.Background(), CreateReplicationSiteLinkBridgeRequest{Name: "bad", Transport: ReplicationTransportSMTP, SiteLinks: []Identity{topologyTestIdentity(linkTestDN)}})
			case "overlap":
				_, err = client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(linkTestDN), Sites: ReplicationReferenceChanges{Add: []Identity{topologyTestIdentity(topologyTestSiteA)}, Remove: []Identity{topologyTestIdentity(topologyTestSiteA)}}})
			case "raw":
				_, err = client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(linkTestDN), Changes: []AttributeChange{{Attribute: "siteList", Kind: AttributeClear}}})
			case "lds-smtp":
				_, err = client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "bad", Transport: ReplicationTransportSMTP})
			}
			if err == nil || len(s.writes) != 0 {
				t.Fatal(err, s.writes)
			}
		})
	}
}
func TestReplicationLinkWriteStatesAndNoReplay(t *testing.T) {
	for _, state := range []ldapWriteState{ldapWriteRejected, ldapWriteUncertain} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			client, s := newLinkTestClient(t, false)
			s.failAt = 1
			s.failure = ldapWriteAttempt{State: state, Err: &LDAPError{Code: 50}}
			result, err := client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(linkTestDN), Cost: topologyPointer(int32(200))})
			if err == nil || len(s.writes) != 1 || result.Mutation.Verified || result.Mutation.State == ObjectWriteAccepted {
				t.Fatal(result, err, s.writes)
			}
		})
	}
}
func TestReplicationLinkClearOmissionIsAcceptedUnverified(t *testing.T) {
	client, s := newLinkTestClient(t, false)
	result, err := client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(linkTestDN), Sites: ReplicationReferenceChanges{Replace: []Identity{}}})
	if !errors.Is(err, ErrObjectVerification) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || result.AfterReferences.AttributeReturned || !result.AfterReferences.Complete || len(s.writes) != 1 {
		t.Fatal(result, err)
	}
}
func TestReplicationConnectionUpdatePreservesFlagsAndScheduleOwnership(t *testing.T) {
	client, s := newLinkTestClient(t, false)
	var schedule ReplicationSchedule
	schedule[3][1][2] = true
	result, err := client.UpdateReplicationConnection(context.Background(), UpdateReplicationConnectionRequest{Identity: topologyTestIdentity(linkTestConnection), Schedule: &schedule, Enabled: topologyPointer(false), SetOptions: ReplicationConnectionUserOwnedSchedule})
	if err != nil || !result.Mutation.Verified || *result.Connection.Enabled || uint32(*result.Connection.Options) != 289 || *result.Connection.Schedule != schedule || len(s.writes) != 1 {
		t.Fatal(result, err)
	}
	read, err := client.ReplicationConnections(context.Background(), SearchOptions{})
	if err != nil || len(read.Connections) != 1 {
		t.Fatal(read, err)
	}
	for _, source := range []Identity{topologyTestIdentity(topologyTestServer), topologyTestIdentity(topologyTestSiteA)} {
		before := len(s.writes)
		_, err = client.UpdateReplicationConnection(context.Background(), UpdateReplicationConnectionRequest{Identity: topologyTestIdentity(linkTestConnection), ReplicateFromDirectoryServer: &source})
		if err == nil || len(s.writes) != before {
			t.Fatal(err, s.writes)
		}
	}
	guid, _ := topologyGUID(*result.Mutation.After)
	_, err = client.UpdateReplicationConnection(context.Background(), UpdateReplicationConnectionRequest{Identity: objectGUIDIdentity(guid), Options: ObjectMutationOptions{ExpectedVersion: &ObjectVersion{Source: client.config.Endpoint, GUID: guid, USNChanged: 7}}})
	if !errors.Is(err, ErrObjectControlUnsupported) || len(s.writes) != 1 {
		t.Fatal(err, s.writes)
	}
}
func TestReplicationReferenceRangesRetainRawFailures(t *testing.T) {
	for _, failure := range []string{"none", "gap", "duplicate", "version", "guid", "permission", "missing-tail", "count", "limit", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			client, s := newLinkTestClient(t, false)
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.rangeRead = func(_ context.Context, _ string, properties []string) (map[string][][]byte, error) {
				calls++
				row, _ := s.lookup(linkTestDN)
				attrs := map[string][][]byte{"objectguid": row.Attributes["objectguid"], "usnchanged": {[]byte("7")}}
				if calls == 1 {
					attrs["siteList;range=0-0"] = [][]byte{[]byte(topologyTestSiteA)}
					if failure == "cancel" {
						cancel()
					}
					return attrs, nil
				}
				if !strings.Contains(properties[0], "range=1-") {
					t.Fatal(properties)
				}
				attrs["siteList;range=1-*"] = [][]byte{[]byte(topologyTestSiteB)}
				switch failure {
				case "gap":
					delete(attrs, "siteList;range=1-*")
					attrs["siteList;range=2-*"] = [][]byte{[]byte(topologyTestSiteB)}
				case "duplicate":
					attrs["siteList;range=1-*"] = [][]byte{[]byte(strings.ToLower(topologyTestSiteA))}
				case "version":
					attrs["usnchanged"] = [][]byte{[]byte("8")}
				case "guid":
					attrs["objectguid"] = [][]byte{make([]byte, 16)}
				case "permission":
					return attrs, &LDAPError{Code: 50}
				case "missing-tail":
					delete(attrs, "siteList;range=1-*")
				case "count":
					delete(attrs, "siteList;range=1-*")
					attrs["siteList;range=1-3"] = [][]byte{[]byte(topologyTestSiteB)}
				}
				return attrs, nil
			}
			limits := ReplicationReferenceLimits{}
			if failure == "limit" {
				limits.MaxRanges = 1
			}
			result, err := client.ReplicationSiteLink(ctx, topologyTestIdentity(linkTestDN), ReplicationLinkReadOptions{References: limits})
			if failure == "none" {
				if err != nil || !result.Sites.Complete || len(result.Sites.References) != 2 {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || result.Sites.Complete || len(result.Sites.Ranges) == 0 || (len(result.Sites.References) == 0 && failure != "cancel") || result.Sites.Error == nil {
				t.Fatal(result, err)
			}
			if failure == "permission" {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != 50 || len(result.Sites.References) != 2 {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestReplicationReferenceDNKeyMatchesStructuralEquality(t *testing.T) {
	values := []string{`CN=a\,b+OU=K,DC=example`, `ou=\4b+cn=A\2Cb,dc=EXAMPLE`, `CN=a\,b+OU=K,DC=example`, `CN=Σ,DC=example`, `CN=ς,DC=example`, `CN=σ,DC=example`, `CN=#0041,DC=example`, `CN=#0061,DC=example`, `CN=K,DC=example`, `CN=K,DC=example`, `CN=ß,DC=example`, `CN=ss,DC=example`, `CN=x+CN=x,DC=example`, `CN=x,DC=example`, `CN=x+OU=y,DC=example`, `OU=y+CN=x,DC=example`}
	for _, left := range values {
		a, err := parseIdentityDN(left)
		if err != nil {
			t.Fatal(err)
		}
		for _, right := range values {
			b, err := parseIdentityDN(right)
			if err != nil {
				t.Fatal(err)
			}
			if (identityDNKey(a) == identityDNKey(b)) != sameIdentityDN(a, b) {
				t.Fatalf("key mismatch: %q / %q", left, right)
			}
		}
	}
}
func TestReplicationReferencesLargeTerminalRange(t *testing.T) {
	_, session := newLinkTestClient(t, false)
	object, _ := session.lookup(linkTestDN)
	values := make([][]byte, 100000)
	for i := range values {
		values[i] = []byte(fmt.Sprintf("CN=site-%d,CN=Sites,%s", i, topologyTestConfiguration))
	}
	session.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
		return map[string][][]byte{"siteList;range=0-*": values, "objectguid": object.Attributes["objectguid"], "usnchanged": object.Attributes["usnchanged"]}, nil
	}
	limits, _ := normalizeReplicationReferenceLimits(ReplicationReferenceLimits{})
	result, err := collectReplicationReferences(context.Background(), session, object, "siteList", limits)
	if err != nil || !result.Complete || len(result.References) != len(values) {
		t.Fatal(len(result.References), err)
	}
	// Cancellation after receiving a large batch must retain the raw batch and
	// stop before decoding all its references.
	ctx, cancel := context.WithCancel(context.Background())
	session.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
		cancel()
		return map[string][][]byte{"siteList;range=0-*": values, "objectguid": object.Attributes["objectguid"], "usnchanged": object.Attributes["usnchanged"]}, nil
	}
	result, err = collectReplicationReferences(ctx, session, object, "siteList", limits)
	if !errors.Is(err, context.Canceled) || len(result.Ranges) != 1 || len(result.References) != 0 || len(result.Ranges[0].Attributes["siteList;range=0-*"]) != 100000 {
		t.Fatal(result.Complete, len(result.References), err)
	}
}
func TestReplicationLinkAndConnectionNoOpRequestedProperties(t *testing.T) {
	for _, connection := range []bool{false, true} {
		t.Run(fmt.Sprint(connection), func(t *testing.T) {
			client, s := newLinkTestClient(t, false)
			target := linkTestDN
			if connection {
				target = linkTestConnection
			}
			original := s.search
			selected := false
			s.search = func(ctx context.Context, query SearchOptions) (searchCursor, error) {
				if topologySameDN(query.Base, target) {
					selected = slices.Contains(query.Properties, "customProperty")
				}
				return original(ctx, query)
			}
			row := s.objects[strings.ToLower(target)]
			row.Attributes["customproperty"] = [][]byte{[]byte("retained")}
			s.objects[strings.ToLower(target)] = row
			options := ObjectMutationOptions{Properties: []string{"customProperty"}}
			var mutation ObjectMutationResult
			var err error
			if connection {
				result, e := client.UpdateReplicationConnection(context.Background(), UpdateReplicationConnectionRequest{Identity: topologyTestIdentity(target), Options: options})
				mutation, err = result.Mutation, e
			} else {
				result, e := client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(target), Options: options})
				mutation, err = result.Mutation, e
			}
			if err != nil || !selected || !mutation.Verified || !mutation.ReadbackComplete || mutation.After == nil || string(mutation.After.Attributes["customproperty"][0]) != "retained" || len(s.writes) != 0 {
				t.Fatal(selected, mutation, err)
			}
		})
	}
}
func TestReplicationReferenceParserBoundaries(t *testing.T) {
	for _, test := range []struct {
		name    string
		attrs   map[string][][]byte
		start   uint64
		wantErr bool
		present bool
	}{{"omitted", nil, 0, false, false}, {"empty", map[string][][]byte{"siteList": {}}, 0, false, true}, {"empty-plus-range", map[string][][]byte{"siteList": {}, "siteList;range=0-*": {[]byte(topologyTestSiteA)}}, 0, false, true}, {"ambiguous", map[string][][]byte{"siteList": {[]byte(topologyTestSiteA)}, "siteList;range=0-*": {[]byte(topologyTestSiteB)}}, 0, true, true}, {"duplicate-descriptor", map[string][][]byte{"siteList;range=0-*": {}, "SITELIST;range=0-*": {}}, 0, true, true}, {"overflow", map[string][][]byte{"siteList;range=0-18446744073709551615": {}}, 0, true, true}, {"missing-continuation", nil, 1, true, false}} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, present, err := directoryReferenceRange(test.attrs, "siteList", test.start)
			if (err != nil) != test.wantErr || present != test.present {
				t.Fatal(present, err)
			}
		})
	}
}
func TestReplicationLinkReadbackFailureRetainsAccepted(t *testing.T) {
	client, s := newLinkTestClient(t, false)
	s.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
		return map[string][][]byte{"siteList;range=0-*": {[]byte(topologyTestSiteA)}}, &LDAPError{Code: 50}
	}
	result, err := client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "partial", Sites: []Identity{topologyTestIdentity(topologyTestSiteA)}})
	if err == nil || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || len(result.AfterReferences.Ranges) != 1 || len(result.AfterReferences.References) != 1 || len(s.writes) != 1 {
		t.Fatal(result, err)
	}
}
func TestReplicationLinkUnknownAttributeValuesPreserved(t *testing.T) {
	client, s := newLinkTestClient(t, false)
	row := s.objects[strings.ToLower(linkTestDN)]
	row.Attributes["unknown"] = [][]byte{{0, 255, 1}}
	s.objects[strings.ToLower(linkTestDN)] = row
	result, err := client.UpdateReplicationSiteLink(context.Background(), UpdateReplicationSiteLinkRequest{Identity: topologyTestIdentity(linkTestDN), Cost: topologyPointer(int32(500)), Options: ObjectMutationOptions{Properties: []string{"unknown"}}})
	if err != nil || !result.Mutation.Verified || !slices.Equal(result.Link.Raw.Attributes["unknown"][0], []byte{0, 255, 1}) {
		t.Fatal(result, err)
	}
}

func TestReplicationBridgeMembershipUpdateAndConnectionSourceTransport(t *testing.T) {
	client, s := newLinkTestClient(t, false)
	bridge, err := client.CreateReplicationSiteLinkBridge(context.Background(), CreateReplicationSiteLinkBridgeRequest{Name: "mutable", SiteLinks: []Identity{topologyTestIdentity(linkTestDN)}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "second"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := client.UpdateReplicationSiteLinkBridge(context.Background(), UpdateReplicationSiteLinkBridgeRequest{Identity: objectGUIDIdentity(*bridge.Bridge.GUID), Description: topologyPointer("preserved metadata"), SiteLinks: ReplicationReferenceChanges{Remove: []Identity{topologyTestIdentity(linkTestDN)}, Add: []Identity{objectGUIDIdentity(*second.Link.GUID)}}})
	if err != nil || !updated.Mutation.Verified || len(updated.AfterReferences.References) != 1 || !topologySameDN(updated.AfterReferences.References[0].DistinguishedName, second.Link.Raw.DistinguishedName) {
		t.Fatal(updated, err)
	}
	source := topologyTestIdentity("CN=DC2,CN=Servers," + topologyTestSiteB)
	connection, err := client.UpdateReplicationConnection(context.Background(), UpdateReplicationConnectionRequest{Identity: topologyTestIdentity(linkTestConnection), ReplicateFromDirectoryServer: &source, Transport: topologyPointer(ReplicationTransportSMTP), SetOptions: ReplicationConnectionIgnoreSchedule})
	if err != nil || !connection.Mutation.Verified || connection.SourceSettings.Object == nil || *connection.Connection.FromServerDN != "CN=NTDS Settings,"+source.String() || *connection.Connection.TransportDN != linkTestSMTP || uint32(*connection.Connection.Options) != 0x80000101 {
		t.Fatal(connection, err)
	}
	if len(s.writes) != 4 {
		t.Fatal("unexpected replay", len(s.writes))
	}
	lds, observed := newLinkTestClient(t, true)
	_, err = lds.UpdateReplicationConnection(context.Background(), UpdateReplicationConnectionRequest{Identity: topologyTestIdentity(linkTestConnection), Transport: topologyPointer(ReplicationTransportSMTP)})
	if !errors.Is(err, ErrUnsupported) || len(observed.writes) != 0 {
		t.Fatal(err, observed.writes)
	}
}

func TestReplicationLinkCreationRejectsTypedRawDescriptionConflictBeforeIO(t *testing.T) {
	for _, bridge := range []bool{false, true} {
		for _, attribute := range []string{"description", "DeScRiPtIoN"} {
			t.Run(fmt.Sprintf("bridge=%v/%s", bridge, attribute), func(t *testing.T) {
				client, session := newLinkTestClient(t, false)
				reads := 0
				original := session.read
				session.read = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
					reads++
					return original(ctx, properties)
				}
				attributes := map[string][]RawValue{attribute: {NewRawValue([]byte("raw"))}}
				var err error
				if bridge {
					_, err = client.CreateReplicationSiteLinkBridge(context.Background(), CreateReplicationSiteLinkBridgeRequest{Name: "conflict", Description: topologyPointer("typed"), Attributes: attributes})
				} else {
					_, err = client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "conflict", Description: topologyPointer("typed"), Attributes: attributes})
				}
				if !errors.Is(err, ErrInvalidObjectMutation) || reads != 0 || len(session.writes) != 0 {
					t.Fatal(reads, session.writes, err)
				}
				var result ReplicationLinkMutationResult
				if bridge {
					result, err = client.CreateReplicationSiteLinkBridge(context.Background(), CreateReplicationSiteLinkBridgeRequest{Name: "raw-only", Attributes: attributes})
				} else {
					result, err = client.CreateReplicationSiteLink(context.Background(), CreateReplicationSiteLinkRequest{Name: "raw-only", Attributes: attributes})
				}
				if err != nil || !result.Mutation.Verified || string(result.Mutation.After.Attributes["description"][0]) != "raw" {
					t.Fatal(result, err)
				}
			})
		}
	}
}
