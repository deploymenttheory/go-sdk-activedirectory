package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

const topologyTestConfiguration = "CN=Configuration,DC=example"
const topologyTestSiteA = "CN=A,CN=Sites," + topologyTestConfiguration
const topologyTestSiteB = "CN=B,CN=Sites," + topologyTestConfiguration
const topologyTestServer = "CN=DC1,CN=Servers," + topologyTestSiteA

func topologyPointer[T any](value T) *T       { return &value }
func topologyTestIdentity(dn string) Identity { identity, _ := IdentityByDN(dn); return identity }
func topologyTestObject(dn, class string, id byte) Object {
	guid := make([]byte, 16)
	guid[0] = id
	parsed, _ := parseIdentityDN(dn)
	name := parsed[0][0].value
	return Object{DistinguishedName: dn, Attributes: map[string][][]byte{"objectguid": {guid}, "objectclass": {[]byte("top"), []byte(class)}, "name": {[]byte(name)}, "cn": {[]byte(name)}, "usnchanged": {[]byte("7")}}}
}

type topologyTestSession struct {
	testSession
	objects    map[string]Object
	writes     []ldapWriteRequest
	nextID     byte
	failAt     int
	failure    ldapWriteAttempt
	afterWrite func()
}

func (s *topologyTestSession) lookup(target string) (Object, bool) {
	if object, ok := s.objects[strings.ToLower(target)]; ok {
		return object, true
	}
	for _, object := range s.objects {
		guid, _ := topologyGUID(object)
		if objectGUIDTarget(guid) == target {
			return object, true
		}
	}
	return Object{}, false
}
func (s *topologyTestSession) ldapWrite(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
	s.writes = append(s.writes, request)
	if s.failAt == len(s.writes) {
		return s.failure
	}
	if request.operation == ldapWriteAdd {
		if _, ok := s.lookup(request.dn); ok {
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 68}}
		}
		s.nextID++
		object := topologyTestObject(request.dn, "top", s.nextID)
		for _, mod := range request.modifications {
			object.Attributes[strings.ToLower(mod.attribute)] = mod.values
		}
		object.Attributes["name"] = object.Attributes["cn"]
		s.objects[strings.ToLower(request.dn)] = object
	} else {
		object, ok := s.lookup(request.dn)
		if !ok {
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 32}}
		}
		switch request.operation {
		case ldapWriteDelete:
			for _, child := range s.objects {
				parent, _ := parentDirectoryDN(child.DistinguishedName)
				if topologySameDN(parent, object.DistinguishedName) {
					return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 66}}
				}
			}
			delete(s.objects, strings.ToLower(object.DistinguishedName))
		case ldapWriteRename:
			parent := request.newParent
			if parent == "" {
				parent, _ = parentDirectoryDN(object.DistinguishedName)
			}
			newDN := request.newRDN + "," + parent
			if _, ok := s.lookup(newDN); ok {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 68}}
			}
			oldDN := object.DistinguishedName
			var moved []Object
			var deleted []string
			for key, row := range s.objects {
				if topologySameDN(row.DistinguishedName, oldDN) || strings.HasSuffix(strings.ToLower(row.DistinguishedName), ","+strings.ToLower(oldDN)) {
					row.DistinguishedName = row.DistinguishedName[:len(row.DistinguishedName)-len(oldDN)] + newDN
					moved = append(moved, row)
					deleted = append(deleted, key)
				}
			}
			for _, key := range deleted {
				delete(s.objects, key)
			}
			for _, row := range moved {
				s.objects[strings.ToLower(row.DistinguishedName)] = row
			}
		case ldapWriteModify:
			attrs := map[string][][]byte{}
			for key, values := range object.Attributes {
				attrs[key] = slices.Clone(values)
			}
			for _, mod := range request.modifications {
				key := strings.ToLower(mod.attribute)
				values := attrs[key]
				switch mod.operation {
				case 2:
					attrs[key] = mod.values
				case 0:
					for _, value := range mod.values {
						if slices.ContainsFunc(values, func(old []byte) bool { return bytes.Equal(old, value) }) {
							return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 20}}
						}
						values = append(values, value)
					}
					attrs[key] = values
				case 1:
					if len(mod.values) == 0 {
						delete(attrs, key)
						continue
					}
					for _, value := range mod.values {
						at := slices.IndexFunc(values, func(old []byte) bool { return bytes.Equal(old, value) })
						if at < 0 {
							return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 16}}
						}
						values = slices.Delete(values, at, at+1)
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
		}
	}
	if s.afterWrite != nil {
		s.afterWrite()
	}
	return ldapWriteAttempt{State: ldapWriteAccepted}
}
func newTopologyTestClient(t *testing.T, lds bool) (*Client, *topologyTestSession) {
	t.Helper()
	s := &topologyTestSession{objects: map[string]Object{}, nextID: 20}
	rows := []Object{topologyTestObject(topologyTestConfiguration, "configuration", 1), topologyTestObject("CN=Sites,"+topologyTestConfiguration, "sitesContainer", 2), topologyTestObject("CN=Subnets,CN=Sites,"+topologyTestConfiguration, "subnetContainer", 3), topologyTestObject(topologyTestSiteA, "site", 4), topologyTestObject("CN=NTDS Site Settings,"+topologyTestSiteA, "nTDSSiteSettings", 5), topologyTestObject("CN=Servers,"+topologyTestSiteA, "serversContainer", 6), topologyTestObject("CN=Licensing Site Settings,"+topologyTestSiteA, "licensingSiteSettings", 7), topologyTestObject(topologyTestSiteB, "site", 8), topologyTestObject("CN=NTDS Site Settings,"+topologyTestSiteB, "nTDSSiteSettings", 9), topologyTestObject("CN=Servers,"+topologyTestSiteB, "serversContainer", 10), topologyTestObject("CN=Licensing Site Settings,"+topologyTestSiteB, "licensingSiteSettings", 11), topologyTestObject(topologyTestServer, "server", 12), topologyTestObject("CN=NTDS Settings,"+topologyTestServer, "nTDSDSA", 13)}
	for _, row := range rows {
		if topologyClass(row, "nTDSSiteSettings") == nil {
			row.Attributes["options"] = [][]byte{[]byte("1073741824")}
		}
		if topologyClass(row, "server") == nil && !lds {
			row.Attributes["serverreference"] = [][]byte{[]byte("CN=DC1,OU=Domain Controllers,DC=example")}
		}
		s.objects[strings.ToLower(row.DistinguishedName)] = row
	}
	s.read = func(context.Context, []string) (map[string][][]byte, error) {
		kind := CapabilityActiveDirectory
		if lds {
			kind = CapabilityADLDS
		}
		root := identityTestRoot(kind)
		root["configurationnamingcontext"] = [][]byte{[]byte(topologyTestConfiguration)}
		root["schemanamingcontext"] = [][]byte{[]byte("CN=Schema," + topologyTestConfiguration)}
		root["supportedcontrol"] = [][]byte{[]byte(objectAssertionControl)}
		return root, nil
	}
	s.search = func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if query.Base == "CN=Schema,"+topologyTestConfiguration {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		if strings.Contains(query.Filter, "objectGUID=") {
			for _, row := range s.objects {
				guid, _ := topologyGUID(row)
				if strings.Contains(query.Filter, identityBinaryLiteral(guid.Bytes())) {
					return objectTestCursor(row), nil
				}
			}
			return objectTestCursor(), nil
		}
		var rows []Object
		for _, row := range s.objects {
			parent, _ := parentDirectoryDN(row.DistinguishedName)
			within := topologySameDN(row.DistinguishedName, query.Base)
			if query.Scope == ScopeOneLevel {
				within = topologySameDN(parent, query.Base)
			} else if query.Scope == ScopeSubtree {
				within = within || strings.HasSuffix(strings.ToLower(row.DistinguishedName), ","+strings.ToLower(query.Base))
			}
			if !within {
				continue
			}
			if _, rest, ok := strings.Cut(query.Filter, "(objectClass="); ok {
				class, _, _ := strings.Cut(rest, ")")
				if class != "*" && topologyClass(row, class) != nil {
					continue
				}
			}
			if _, rest, ok := strings.Cut(query.Filter, "(siteObject="); ok {
				dn, _, _ := strings.Cut(rest, ")")
				value, err := row.Values("siteObject").Single()
				if err != nil || !topologySameDN(string(value.Bytes()), dn) {
					continue
				}
			}
			rows = append(rows, row)
		}
		return objectTestCursor(rows...), nil
	}
	s.finish = func() error { return nil }
	client := newClient(Config{Endpoint: Endpoint{Host: "dc.example", Port: 389}, Timeout: time.Second}, s)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client, s
}

func TestReplicationScheduleWireAndInvalidHeaders(t *testing.T) {
	for day := range 7 {
		for hour := range 24 {
			for quarter := range 4 {
				var schedule ReplicationSchedule
				if err := schedule.Set(time.Weekday(day), hour, quarter, true); err != nil {
					t.Fatal(err)
				}
				wire := schedule.Bytes()
				if wire[20+day*24+hour] != 1<<quarter || len(wire) != 188 || wire[0] != 188 || wire[8] != 1 || wire[16] != 20 {
					t.Fatal(wire)
				}
				decoded, err := ReplicationScheduleFromBytes(wire)
				if err != nil || decoded != schedule {
					t.Fatal(decoded, err)
				}
			}
		}
	}
	for _, offset := range []int{0, 4, 8, 12, 16, 20} {
		wire := (ReplicationSchedule{}).Bytes()
		wire[offset] = 255
		if _, err := ReplicationScheduleFromBytes(wire); !errors.Is(err, ErrInvalidReplicationSchedule) {
			t.Fatal(offset, err)
		}
	}
	if _, err := ReplicationScheduleFromBytes(nil); !errors.Is(err, ErrInvalidReplicationSchedule) {
		t.Fatal(err)
	}
}
func TestReplicationSiteLifecycleStagesAndSettingsPreserveUnknownFlags(t *testing.T) {
	for _, lds := range []bool{false, true} {
		client, session := newTopologyTestClient(t, lds)
		var schedule ReplicationSchedule
		schedule[1][12][2] = true
		created, err := client.CreateReplicationSite(context.Background(), CreateReplicationSiteRequest{Name: "New-Site", Description: topologyPointer("branch"), Settings: ReplicationSiteSettingsPatch{Schedule: &schedule}})
		count := 4
		if lds {
			count = 3
		}
		if err != nil || !created.Complete || len(created.Steps) != count || len(session.writes) != count || created.After.Site.Settings.Schedule == nil || *created.After.Site.Settings.Schedule != schedule {
			t.Fatal(created, err)
		}
		updated, err := client.UpdateReplicationSite(context.Background(), UpdateReplicationSiteRequest{Identity: topologyTestIdentity(topologyTestSiteB), Description: topologyPointer("updated"), Settings: &ReplicationSiteSettingsPatch{SetOptions: SiteEnableScheduleHashing, Schedule: &schedule}})
		if err != nil || !updated.Complete || len(updated.Steps) != 2 || *updated.After.Site.Settings.Options != ReplicationSiteOptions(0x40000200) {
			t.Fatal(updated, err)
		}
		mods := session.writes[len(session.writes)-1].modifications
		if len(mods) != 3 || mods[0].operation != 1 || string(mods[0].values[0]) != "1073741824" || mods[1].operation != 0 {
			t.Fatal(mods)
		}
		deleted, err := client.DeleteReplicationSite(context.Background(), topologyTestIdentity("CN=New-Site,CN=Sites,"+topologyTestConfiguration), ObjectMutationOptions{})
		if err != nil || !deleted.Complete || len(deleted.Steps) != count || !deleted.Steps[count-1].Mutation.AbsentAfter {
			t.Fatal(deleted, err)
		}
	}
}
func TestReplicationSitePartialCreationAndNonemptyDeletion(t *testing.T) {
	for _, state := range []ldapWriteState{ldapWriteRejected, ldapWriteUncertain} {
		client, session := newTopologyTestClient(t, false)
		session.failAt = 3
		session.failure = ldapWriteAttempt{State: state, Err: &LDAPError{Code: 50}}
		result, err := client.CreateReplicationSite(context.Background(), CreateReplicationSiteRequest{Name: "Partial"})
		if err == nil || result.Complete || len(result.Steps) != 3 || len(session.writes) != 3 || result.Steps[0].Mutation.State != ObjectWriteAccepted || result.Steps[1].Mutation.State != ObjectWriteAccepted {
			t.Fatal(result, err)
		}
	}
	for _, mode := range []string{"server", "subnet", "unknown-child"} {
		client, session := newTopologyTestClient(t, false)
		identity := topologyTestIdentity(topologyTestSiteA)
		if mode != "server" {
			identity = topologyTestIdentity(topologyTestSiteB)
		}
		if mode == "subnet" {
			row := topologyTestObject("CN=192.0.2.0/24,CN=Subnets,CN=Sites,"+topologyTestConfiguration, "subnet", 19)
			row.Attributes["siteobject"] = [][]byte{[]byte(topologyTestSiteB)}
			session.objects[strings.ToLower(row.DistinguishedName)] = row
		}
		if mode == "unknown-child" {
			row := topologyTestObject("CN=Unknown,"+topologyTestSiteB, "container", 19)
			session.objects[strings.ToLower(row.DistinguishedName)] = row
		}
		result, err := client.DeleteReplicationSite(context.Background(), identity, ObjectMutationOptions{})
		if !errors.Is(err, ErrReplicationSiteNotEmpty) || len(session.writes) != 0 || result.Preflight.Object == nil {
			t.Fatal(result, err)
		}
	}
}
func TestReplicationSubnetLifecycleAndInputValidation(t *testing.T) {
	for _, prefix := range []string{"192.0.2.0/24", "2001:db8::/32"} {
		client, session := newTopologyTestClient(t, false)
		site := topologyTestIdentity(topologyTestSiteA)
		created, err := client.CreateReplicationSubnet(context.Background(), CreateReplicationSubnetRequest{Prefix: netip.MustParsePrefix(prefix), Site: &site, Location: topologyPointer("Rack 2")})
		if err != nil || !created.Mutation.Verified || created.Subnet.Prefix == nil || created.Subnet.SiteDN == nil {
			t.Fatal(created, err)
		}
		identity := objectGUIDIdentity(*created.Mutation.TargetGUID)
		site = topologyTestIdentity(topologyTestSiteB)
		updated, err := client.UpdateReplicationSubnet(context.Background(), UpdateReplicationSubnetRequest{Identity: identity, Site: &site})
		if err != nil || !updated.Mutation.Verified || *updated.Subnet.SiteDN != topologyTestSiteB {
			t.Fatal(updated, err)
		}
		_, err = client.CreateReplicationSubnet(context.Background(), CreateReplicationSubnetRequest{Prefix: netip.MustParsePrefix(prefix)})
		if !errors.Is(err, ErrObjectAlreadyExists) {
			t.Fatal(err)
		}
		deleted, err := client.DeleteReplicationSubnet(context.Background(), identity, ObjectMutationOptions{})
		if err != nil || !deleted.Verified || len(session.writes) != 4 {
			t.Fatal(deleted, err)
		}
	}
	for _, prefix := range []netip.Prefix{{}, netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("2001:db8::1/64"), netip.MustParsePrefix("::ffff:192.0.2.0/120")} {
		client, session := newTopologyTestClient(t, false)
		_, err := client.CreateReplicationSubnet(context.Background(), CreateReplicationSubnetRequest{Prefix: prefix})
		if !errors.Is(err, ErrInvalidReplicationSubnet) || len(session.writes) != 0 {
			t.Fatal(prefix, err)
		}
	}
}
func TestDirectoryServerMovePreservesIdentityAndSubtree(t *testing.T) {
	for _, lds := range []bool{false, true} {
		for _, input := range []string{topologyTestServer, "CN=NTDS Settings," + topologyTestServer} {
			client, session := newTopologyTestClient(t, lds)
			request := MoveDirectoryServerRequest{Server: topologyTestIdentity(input), Site: topologyTestIdentity(topologyTestSiteB)}
			result, err := client.MoveDirectoryServer(context.Background(), request)
			if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted || len(session.writes) != 1 || !topologySameDN(result.After.Server.DistinguishedName, "CN=DC1,CN=Servers,"+topologyTestSiteB) || !topologySameDN(result.After.Settings.DistinguishedName, "CN=NTDS Settings,CN=DC1,CN=Servers,"+topologyTestSiteB) {
				t.Fatal(result, err)
			}
			if session.writes[0].operation != ldapWriteRename || session.writes[0].newParent != "CN=Servers,"+topologyTestSiteB || !strings.HasPrefix(session.writes[0].dn, "<GUID=") {
				t.Fatal(session.writes)
			}
			request.Server = objectGUIDIdentity(*result.Mutation.TargetGUID)
			noop, err := client.MoveDirectoryServer(context.Background(), request)
			if err != nil || !noop.NoChange || !noop.Mutation.Verified || noop.Mutation.State != ObjectWriteNotAttempted || len(session.writes) != 1 {
				t.Fatal(noop, err)
			}
			request.Options.ExpectedVersion = &ObjectVersion{Source: client.config.Endpoint, GUID: *result.Mutation.TargetGUID, USNChanged: 7}
			_, err = client.MoveDirectoryServer(context.Background(), request)
			if !errors.Is(err, ErrObjectControlUnsupported) || len(session.writes) != 1 {
				t.Fatal(err)
			}
		}
	}
}
func TestDirectoryServerMoveRejectsWrongTargetsAndRetainsAcceptedReadbackFailure(t *testing.T) {
	for _, mode := range []string{"account", "missing-site", "missing-settings", "uncertain", "denied", "readback-missing-settings", "changed-computer-link"} {
		client, session := newTopologyTestClient(t, false)
		request := MoveDirectoryServerRequest{Server: topologyTestIdentity(topologyTestServer), Site: topologyTestIdentity(topologyTestSiteB)}
		switch mode {
		case "account":
			row := topologyTestObject("CN=DC1,DC=example", "computer", 20)
			session.objects[strings.ToLower(row.DistinguishedName)] = row
			request.Server = topologyTestIdentity(row.DistinguishedName)
		case "missing-site":
			request.Site = topologyTestIdentity("CN=Missing,CN=Sites," + topologyTestConfiguration)
		case "missing-settings":
			delete(session.objects, strings.ToLower("CN=NTDS Settings,"+topologyTestServer))
		case "uncertain", "denied":
			session.failAt = 1
			session.failure = ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50}}
			if mode == "uncertain" {
				session.failure.State = ldapWriteUncertain
			}
		case "readback-missing-settings":
			session.afterWrite = func() {
				delete(session.objects, strings.ToLower("CN=NTDS Settings,CN=DC1,CN=Servers,"+topologyTestSiteB))
			}
		case "changed-computer-link":
			session.afterWrite = func() {
				key := strings.ToLower("CN=DC1,CN=Servers," + topologyTestSiteB)
				row := session.objects[key]
				attrs := map[string][][]byte{}
				for name, values := range row.Attributes {
					attrs[name] = values
				}
				attrs["serverreference"] = [][]byte{[]byte("CN=Wrong,DC=example")}
				row.Attributes = attrs
				session.objects[key] = row
			}
		}
		result, err := client.MoveDirectoryServer(context.Background(), request)
		if err == nil || result.Mutation.Verified {
			t.Fatal(mode, result, err)
		}
		if strings.HasPrefix(mode, "readback") || mode == "changed-computer-link" {
			if result.Mutation.State != ObjectWriteAccepted || result.Mutation.After == nil || len(session.writes) != 1 {
				t.Fatal(result, err)
			}
		} else if mode == "uncertain" {
			if !errors.Is(err, ErrObjectWriteUncertain) || len(session.writes) != 1 {
				t.Fatal(result, err)
			}
		} else if mode == "denied" {
			if !errors.Is(err, ErrObjectWritePermission) || len(session.writes) != 1 {
				t.Fatal(result, err)
			}
		} else if len(session.writes) != 0 {
			t.Fatal("invalid preflight wrote", session.writes)
		}
	}
}

func TestDirectoryServerMoveValidatesRelatedReadbackGUIDs(t *testing.T) {
	for _, target := range []string{"settings", "site"} {
		for _, mode := range []string{"missing", "malformed", "mismatched", "wrong-class", "wrong-placement"} {
			t.Run(target+"/"+mode, func(t *testing.T) {
				client, session := newTopologyTestClient(t, false)
				id := byte(13)
				if target == "site" {
					id = 8
				}
				wanted, _ := GUIDFromBytes(append([]byte{id}, make([]byte, 15)...))
				search := session.search
				session.search = func(ctx context.Context, query SearchOptions) (searchCursor, error) {
					if len(session.writes) > 0 && strings.Contains(query.Filter, identityBinaryLiteral(wanted.Bytes())) {
						object, _ := session.lookup(objectGUIDTarget(wanted))
						attrs := map[string][][]byte{}
						for key, values := range object.Attributes {
							attrs[key] = values
						}
						object.Attributes = attrs
						switch mode {
						case "missing":
							delete(attrs, "objectguid")
						case "malformed":
							attrs["objectguid"] = [][]byte{[]byte{1, 2, 3}}
						case "mismatched":
							attrs["objectguid"] = [][]byte{append([]byte{99}, make([]byte, 15)...)}
						case "wrong-class":
							attrs["objectclass"] = [][]byte{[]byte("container")}
						case "wrong-placement":
							object.DistinguishedName = "CN=Wrong,CN=Services," + topologyTestConfiguration
						}
						return objectTestCursor(object), nil
					}
					return search(ctx, query)
				}
				result, err := client.MoveDirectoryServer(context.Background(), MoveDirectoryServerRequest{Server: topologyTestIdentity(topologyTestServer), Site: topologyTestIdentity(topologyTestSiteB)})
				if !errors.Is(err, ErrObjectVerification) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || result.Mutation.After == nil || result.SettingsAfter.Object == nil || result.DestinationSiteAfter.Object == nil || len(session.writes) != 1 {
					t.Fatalf("accepted write/raw related observations lost: state=%d verified=%t writes=%d err=%v", result.Mutation.State, result.Mutation.Verified, len(session.writes), err)
				}
			})
		}
	}
}

func TestReplicationSiteDeadlineNoopAndSignedOptionBits(t *testing.T) {
	client, session := newTopologyTestClient(t, false)
	read := session.read
	var first time.Time
	reads := 0
	session.read = func(ctx context.Context, props []string) (map[string][][]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("missing deadline")
		}
		reads++
		if first.IsZero() {
			first = deadline
		} else if !deadline.Equal(first) {
			t.Fatal("creation budget restarted", first, deadline)
		}
		return read(ctx, props)
	}
	created, err := client.CreateReplicationSite(context.Background(), CreateReplicationSiteRequest{Name: "Bounded"})
	if err != nil || !created.Complete || reads < 4 {
		t.Fatal(created, err)
	}
	client, session = newTopologyTestClient(t, false)
	key := strings.ToLower("CN=NTDS Site Settings," + topologyTestSiteB)
	object := session.objects[key]
	object.Attributes["options"] = [][]byte{[]byte("-2147483648")}
	result, err := client.UpdateReplicationSite(context.Background(), UpdateReplicationSiteRequest{Identity: topologyTestIdentity(topologyTestSiteB), Settings: &ReplicationSiteSettingsPatch{SetOptions: SiteEnableScheduleHashing}})
	if err != nil || !result.Complete || uint32(*result.After.Site.Settings.Options) != 0x80000200 || string(session.writes[0].modifications[0].values[0]) != "-2147483648" || string(session.writes[0].modifications[1].values[0]) != "-2147483136" {
		t.Fatal(result, err)
	}
	settingsGUID, _ := topologyGUID(object)
	_, err = client.UpdateReplicationSite(context.Background(), UpdateReplicationSiteRequest{Identity: topologyTestIdentity(topologyTestSiteB), Description: topologyPointer("must not write"), Settings: &ReplicationSiteSettingsPatch{SetOptions: SiteEnableScheduleHashing}, SettingsExpectedVersion: &ObjectVersion{Source: client.config.Endpoint, GUID: settingsGUID, USNChanged: 7}})
	if !errors.Is(err, ErrObjectControlUnsupported) || len(session.writes) != 1 {
		t.Fatal(err, session.writes)
	}
}

func TestReplicationSiteDeletionServerGuardPrecedesSettingsCleanup(t *testing.T) {
	client, session := newTopologyTestClient(t, false)
	search := session.search
	session.search = func(ctx context.Context, query SearchOptions) (searchCursor, error) {
		if query.Scope == ScopeSubtree && topologySameDN(query.Base, topologyTestSiteA) {
			var rows []Object
			for _, object := range session.objects {
				if topologySameDN(object.DistinguishedName, topologyTestSiteA) {
					rows = append(rows, object)
					continue
				}
				parent, _ := parentDirectoryDN(object.DistinguishedName)
				if topologySameDN(parent, topologyTestSiteA) {
					rows = append(rows, object)
				}
			}
			return objectTestCursor(rows...), nil // Descendant servers are hidden.
		}
		return search(ctx, query)
	}
	result, err := client.DeleteReplicationSite(context.Background(), topologyTestIdentity(topologyTestSiteA), ObjectMutationOptions{})
	if !errors.Is(err, ErrObjectNotLeaf) || len(result.Steps) != 1 || result.Steps[0].Mutation.State != ObjectWriteRejected || len(session.writes) != 1 || result.Steps[0].Name != "CN=Servers,"+topologyTestSiteA {
		t.Fatal(result, err)
	}
	if _, ok := session.lookup("CN=NTDS Site Settings," + topologyTestSiteA); !ok {
		t.Fatal("settings were removed before nonempty container rejection")
	}
}
