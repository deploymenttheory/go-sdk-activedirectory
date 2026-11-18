package acceptance

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

const (
	InternalTopologyTestConfiguration = "CN=Configuration,DC=example"
	InternalTopologyTestSiteA         = "CN=A,CN=Sites," + InternalTopologyTestConfiguration
	InternalTopologyTestSiteB         = "CN=B,CN=Sites," + InternalTopologyTestConfiguration
	InternalTopologyTestServer        = "CN=DC1,CN=Servers," + InternalTopologyTestSiteA
)

func InternalTopologyPointer[T any](value T) *T { return &value }
func InternalTopologyTestIdentity(dn string) admodel.Identity {
	identity, _ := admodel.IdentityByDN(dn)
	return identity
}

func InternalTopologyTestObject(dn, class string, id byte) admodel.Object {
	guid := make([]byte, 16)
	guid[0] = id
	parsed, _ := admodel.InternalParseIdentityDN(dn)
	name := parsed[0][0].InternalValue
	return admodel.Object{
		DistinguishedName: dn,
		Attributes: map[string][][]byte{
			"objectguid":  {guid},
			"objectclass": {[]byte("top"), []byte(class)},
			"name":        {[]byte(name)},
			"cn":          {[]byte(name)},
			"usnchanged":  {[]byte("7")},
		},
	}
}

type InternalTopologyTestSession struct {
	InternalTestSession
	InternalObjects    map[string]admodel.Object
	InternalDeleted    map[admodel.GUID]admodel.Object
	InternalWrites     []admodel.InternalLdapWriteRequest
	InternalNextID     byte
	InternalFailAt     int
	InternalFailure    admodel.InternalLdapWriteAttempt
	InternalAfterWrite func()
}

func (s *InternalTopologyTestSession) InternalLookup(target string) (admodel.Object, bool) {
	if object, ok := s.InternalObjects[strings.ToLower(target)]; ok {
		return object, true
	}
	for _, object := range s.InternalObjects {
		guid, _ := admodel.InternalTopologyGUID(object)
		if admodel.InternalObjectGUIDTarget(guid) == target {
			return object, true
		}
	}
	return admodel.Object{}, false
}

func (s *InternalTopologyTestSession) InternalLdapWrite(
	_ context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	s.InternalWrites = append(s.InternalWrites, request)
	if s.InternalFailAt == len(s.InternalWrites) {
		return s.InternalFailure
	}
	if request.InternalOperation == admodel.InternalLdapWriteAdd {
		if _, ok := s.InternalLookup(request.InternalDn); ok {
			return admodel.InternalLdapWriteAttempt{
				State: admodel.InternalLdapWriteRejected,
				Err:   &admodel.LDAPError{Code: 68},
			}
		}
		s.InternalNextID++
		object := InternalTopologyTestObject(request.InternalDn, "top", s.InternalNextID)
		for _, mod := range request.InternalModifications {
			object.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
		}
		object.Attributes["name"] = object.Attributes["cn"]
		s.InternalObjects[strings.ToLower(request.InternalDn)] = object
	} else {
		object, ok := s.InternalLookup(request.InternalDn)
		if !ok {
			return admodel.InternalLdapWriteAttempt{
				State: admodel.InternalLdapWriteRejected,
				Err:   &admodel.LDAPError{Code: 32},
			}
		}
		switch request.InternalOperation {
		case admodel.InternalLdapWriteDelete:
			for _, child := range s.InternalObjects {
				parent, _ := admodel.InternalParentDirectoryDN(child.DistinguishedName)
				if admodel.InternalTopologySameDN(parent, object.DistinguishedName) {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteRejected,
						Err:   &admodel.LDAPError{Code: 66},
					}
				}
			}
			delete(s.InternalObjects, strings.ToLower(object.DistinguishedName))
			guid, _ := admodel.InternalTopologyGUID(object)
			deleted := object
			deleted.Attributes = maps.Clone(object.Attributes)
			deleted.DistinguishedName = `CN=deleted\0ADEL:` + guid.String() + ",CN=Deleted Objects," + InternalTopologyTestConfiguration
			deleted.Attributes["isdeleted"] = [][]byte{[]byte("TRUE")}
			deleted.Attributes["distinguishedname"] = [][]byte{[]byte(deleted.DistinguishedName)}
			s.InternalDeleted[guid] = deleted
		case admodel.InternalLdapWriteRename:
			parent := request.InternalNewParent
			if parent == "" {
				parent, _ = admodel.InternalParentDirectoryDN(object.DistinguishedName)
			}
			newDN := request.InternalNewRDN + "," + parent
			if _, ok := s.InternalLookup(newDN); ok {
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: 68},
				}
			}
			oldDN := object.DistinguishedName
			var moved []admodel.Object
			var deleted []string
			for key, row := range s.InternalObjects {
				if admodel.InternalTopologySameDN(row.DistinguishedName, oldDN) ||
					strings.HasSuffix(
						strings.ToLower(row.DistinguishedName),
						","+strings.ToLower(oldDN),
					) {
					row.DistinguishedName = row.DistinguishedName[:len(row.DistinguishedName)-len(oldDN)] + newDN
					moved = append(moved, row)
					deleted = append(deleted, key)
				}
			}
			for _, key := range deleted {
				delete(s.InternalObjects, key)
			}
			for _, row := range moved {
				s.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
			}
		case admodel.InternalLdapWriteModify:
			attrs := map[string][][]byte{}
			for key, values := range object.Attributes {
				attrs[key] = slices.Clone(values)
			}
			for _, mod := range request.InternalModifications {
				key := strings.ToLower(mod.InternalAttribute)
				values := attrs[key]
				switch mod.InternalOperation {
				case 2:
					attrs[key] = mod.InternalValues
				case 0:
					for _, value := range mod.InternalValues {
						if slices.ContainsFunc(
							values,
							func(old []byte) bool { return bytes.Equal(old, value) },
						) {
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteRejected,
								Err:   &admodel.LDAPError{Code: 20},
							}
						}
						values = append(values, value)
					}
					attrs[key] = values
				case 1:
					if len(mod.InternalValues) == 0 {
						delete(attrs, key)
						continue
					}
					for _, value := range mod.InternalValues {
						at := slices.IndexFunc(
							values,
							func(old []byte) bool { return bytes.Equal(old, value) },
						)
						if at < 0 {
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteRejected,
								Err:   &admodel.LDAPError{Code: 16},
							}
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
			s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
		}
	}
	if s.InternalAfterWrite != nil {
		s.InternalAfterWrite()
	}
	return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
}

// Model the directory boundary's explicit deleted-object visibility, rather
// than manufacturing a positive observation from the live map's empty result.
func (s *InternalTopologyTestSession) InternalStartSearchControls(
	ctx context.Context, query admodel.SearchOptions, controls []admodel.InternalLdapWriteControl,
) (admodel.InternalSearchCursor, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if len(controls) != 1 || controls[0].InternalOid != admodel.InternalObjectShowDeletedControl || !controls[0].InternalCritical ||
		len(controls[0].InternalValue) != 0 || query.Base != InternalTopologyTestConfiguration || !strings.Contains(query.Filter, "(isDeleted=TRUE)") {
		return nil, admodel.ErrInvalidSearch
	}
	for guid, object := range s.InternalDeleted {
		if strings.Contains(query.Filter, "(objectGUID="+admodel.InternalIdentityBinaryLiteral(guid.Bytes())+")") {
			return InternalObjectTestCursor(object), nil
		}
	}
	return InternalObjectTestCursor(), nil
}

func InternalNewTopologyTestClient(
	t *testing.T,
	lds bool,
) (*adengine.Client, *InternalTopologyTestSession) {
	t.Helper()
	s := &InternalTopologyTestSession{
		InternalObjects: map[string]admodel.Object{},
		InternalDeleted: map[admodel.GUID]admodel.Object{},
		InternalNextID:  20,
	}
	rows := []admodel.Object{
		InternalTopologyTestObject(InternalTopologyTestConfiguration, "configuration", 1),
		InternalTopologyTestObject(
			"CN=Sites,"+InternalTopologyTestConfiguration,
			"sitesContainer",
			2,
		),
		InternalTopologyTestObject(
			"CN=Subnets,CN=Sites,"+InternalTopologyTestConfiguration,
			"subnetContainer",
			3,
		),
		InternalTopologyTestObject(InternalTopologyTestSiteA, "site", 4),
		InternalTopologyTestObject(
			"CN=NTDS Site Settings,"+InternalTopologyTestSiteA,
			"nTDSSiteSettings",
			5,
		),
		InternalTopologyTestObject("CN=Servers,"+InternalTopologyTestSiteA, "serversContainer", 6),
		InternalTopologyTestObject(
			"CN=Licensing Site Settings,"+InternalTopologyTestSiteA,
			"licensingSiteSettings",
			7,
		),
		InternalTopologyTestObject(InternalTopologyTestSiteB, "site", 8),
		InternalTopologyTestObject(
			"CN=NTDS Site Settings,"+InternalTopologyTestSiteB,
			"nTDSSiteSettings",
			9,
		),
		InternalTopologyTestObject("CN=Servers,"+InternalTopologyTestSiteB, "serversContainer", 10),
		InternalTopologyTestObject(
			"CN=Licensing Site Settings,"+InternalTopologyTestSiteB,
			"licensingSiteSettings",
			11,
		),
		InternalTopologyTestObject(InternalTopologyTestServer, "server", 12),
		InternalTopologyTestObject("CN=NTDS Settings,"+InternalTopologyTestServer, "nTDSDSA", 13),
	}
	for _, row := range rows {
		if admodel.InternalTopologyClass(row, "nTDSSiteSettings") == nil {
			row.Attributes["options"] = [][]byte{[]byte("1073741824")}
		}
		if admodel.InternalTopologyClass(row, "server") == nil && !lds {
			row.Attributes["serverreference"] = [][]byte{
				[]byte("CN=DC1,OU=Domain Controllers,DC=example"),
			}
		}
		s.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
	}
	s.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
		kind := admodel.CapabilityActiveDirectory
		if lds {
			kind = admodel.CapabilityADLDS
		}
		root := InternalIdentityTestRoot(kind)
		root["configurationnamingcontext"] = [][]byte{[]byte(InternalTopologyTestConfiguration)}
		root["schemanamingcontext"] = [][]byte{
			[]byte("CN=Schema," + InternalTopologyTestConfiguration),
		}
		root["supportedcontrol"] = [][]byte{[]byte(admodel.InternalObjectAssertionControl), []byte(admodel.InternalObjectShowDeletedControl)}
		return root, nil
	}
	s.InternalSearch = func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if query.Base == "CN=Schema,"+InternalTopologyTestConfiguration {
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
			for _, row := range s.InternalObjects {
				guid, _ := admodel.InternalTopologyGUID(row)
				if strings.Contains(
					query.Filter,
					admodel.InternalIdentityBinaryLiteral(guid.Bytes()),
				) {
					return InternalObjectTestCursor(row), nil
				}
			}
			return InternalObjectTestCursor(), nil
		}
		var rows []admodel.Object
		for _, row := range s.InternalObjects {
			parent, _ := admodel.InternalParentDirectoryDN(row.DistinguishedName)
			within := admodel.InternalTopologySameDN(row.DistinguishedName, query.Base)
			if query.Scope == admodel.ScopeOneLevel {
				within = admodel.InternalTopologySameDN(parent, query.Base)
			} else if query.Scope == admodel.ScopeSubtree {
				within = within ||
					strings.HasSuffix(
						strings.ToLower(row.DistinguishedName),
						","+strings.ToLower(query.Base),
					)
			}
			if !within {
				continue
			}
			if _, rest, ok := strings.Cut(query.Filter, "(objectClass="); ok {
				class, _, _ := strings.Cut(rest, ")")
				if class != "*" && admodel.InternalTopologyClass(row, class) != nil {
					continue
				}
			}
			if _, rest, ok := strings.Cut(query.Filter, "(siteObject="); ok {
				dn, _, _ := strings.Cut(rest, ")")
				value, err := row.Values("siteObject").Single()
				if err != nil || !admodel.InternalTopologySameDN(string(value.Bytes()), dn) {
					continue
				}
			}
			rows = append(rows, row)
		}
		return InternalObjectTestCursor(rows...), nil
	}
	s.InternalFinish = func() error { return nil }
	client := adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example", Port: 389},
			Timeout:  time.Second,
		},
		s,
	)
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
				var schedule admodel.ReplicationSchedule
				if err := schedule.Set(time.Weekday(day), hour, quarter, true); err != nil {
					t.Fatal(err)
				}
				wire := schedule.Bytes()
				if wire[20+day*24+hour] != 1<<quarter || len(wire) != 188 || wire[0] != 188 ||
					wire[8] != 1 ||
					wire[16] != 20 {
					t.Fatal(wire)
				}
				decoded, err := admodel.ReplicationScheduleFromBytes(wire)
				if err != nil || decoded != schedule {
					t.Fatal(decoded, err)
				}
			}
		}
	}
	for _, offset := range []int{0, 4, 8, 12, 16, 20} {
		wire := (admodel.ReplicationSchedule{}).Bytes()
		wire[offset] = 255
		if _, err := admodel.ReplicationScheduleFromBytes(
			wire,
		); !errors.Is(
			err,
			admodel.ErrInvalidReplicationSchedule,
		) {
			t.Fatal(offset, err)
		}
	}
	if _, err := admodel.ReplicationScheduleFromBytes(
		nil,
	); !errors.Is(
		err,
		admodel.ErrInvalidReplicationSchedule,
	) {
		t.Fatal(err)
	}
}

func TestReplicationSiteLifecycleStagesAndSettingsPreserveUnknownFlags(t *testing.T) {
	for _, lds := range []bool{false, true} {
		client, session := InternalNewTopologyTestClient(t, lds)
		var schedule admodel.ReplicationSchedule
		schedule[1][12][2] = true
		created, err := adservice_replication.New(client).
			CreateReplicationSite(context.Background(), admodel.CreateReplicationSiteRequest{Name: "New-Site", Description: InternalTopologyPointer("branch"), Settings: admodel.ReplicationSiteSettingsPatch{Schedule: &schedule}})
		count := 4
		if lds {
			count = 3
		}
		if err != nil || !created.Complete || len(created.Steps) != count ||
			len(session.InternalWrites) != count ||
			created.After.Site.Settings.Schedule == nil ||
			*created.After.Site.Settings.Schedule != schedule {
			t.Fatal(created, err)
		}
		updated, err := adservice_replication.New(client).
			UpdateReplicationSite(context.Background(), admodel.UpdateReplicationSiteRequest{Identity: InternalTopologyTestIdentity(InternalTopologyTestSiteB), Description: InternalTopologyPointer("updated"), Settings: &admodel.ReplicationSiteSettingsPatch{SetOptions: admodel.SiteEnableScheduleHashing, Schedule: &schedule}})
		if err != nil || !updated.Complete || len(updated.Steps) != 2 ||
			*updated.After.Site.Settings.Options != admodel.ReplicationSiteOptions(0x40000200) {
			t.Fatal(updated, err)
		}
		mods := session.InternalWrites[len(session.InternalWrites)-1].InternalModifications
		if len(mods) != 3 || mods[0].InternalOperation != 1 ||
			string(mods[0].InternalValues[0]) != "1073741824" ||
			mods[1].InternalOperation != 0 {
			t.Fatal(mods)
		}
		deleted, err := adservice_replication.New(client).
			DeleteReplicationSite(context.Background(), InternalTopologyTestIdentity("CN=New-Site,CN=Sites,"+InternalTopologyTestConfiguration), admodel.ObjectMutationOptions{})
		if err != nil || !deleted.Complete || len(deleted.Steps) != count ||
			!deleted.Steps[count-1].Mutation.AbsentAfter {
			t.Fatal(deleted, err)
		}
	}
}

func TestReplicationSitePartialCreationAndNonemptyDeletion(t *testing.T) {
	for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain} {
		client, session := InternalNewTopologyTestClient(t, false)
		session.InternalFailAt = 3
		session.InternalFailure = admodel.InternalLdapWriteAttempt{
			State: state,
			Err:   &admodel.LDAPError{Code: 50},
		}
		result, err := adservice_replication.New(client).
			CreateReplicationSite(context.Background(), admodel.CreateReplicationSiteRequest{Name: "Partial"})
		if err == nil || result.Complete || len(result.Steps) != 3 ||
			len(session.InternalWrites) != 3 ||
			result.Steps[0].Mutation.State != admodel.ObjectWriteAccepted ||
			result.Steps[1].Mutation.State != admodel.ObjectWriteAccepted {
			t.Fatal(result, err)
		}
	}
	for _, mode := range []string{"server", "subnet", "unknown-child"} {
		client, session := InternalNewTopologyTestClient(t, false)
		identity := InternalTopologyTestIdentity(InternalTopologyTestSiteA)
		if mode != "server" {
			identity = InternalTopologyTestIdentity(InternalTopologyTestSiteB)
		}
		if mode == "subnet" {
			row := InternalTopologyTestObject(
				"CN=192.0.2.0/24,CN=Subnets,CN=Sites,"+InternalTopologyTestConfiguration,
				"subnet",
				19,
			)
			row.Attributes["siteobject"] = [][]byte{[]byte(InternalTopologyTestSiteB)}
			session.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
		}
		if mode == "unknown-child" {
			row := InternalTopologyTestObject(
				"CN=Unknown,"+InternalTopologyTestSiteB,
				"container",
				19,
			)
			session.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
		}
		result, err := adservice_replication.New(client).
			DeleteReplicationSite(context.Background(), identity, admodel.ObjectMutationOptions{})
		if !errors.Is(err, admodel.ErrReplicationSiteNotEmpty) ||
			len(session.InternalWrites) != 0 ||
			result.Preflight.Object == nil {
			t.Fatal(result, err)
		}
	}
}

func TestReplicationSubnetLifecycleAndInputValidation(t *testing.T) {
	for _, prefix := range []string{"192.0.2.0/24", "2001:db8::/32"} {
		client, session := InternalNewTopologyTestClient(t, false)
		site := InternalTopologyTestIdentity(InternalTopologyTestSiteA)
		created, err := adservice_replication.New(client).
			CreateReplicationSubnet(context.Background(), admodel.CreateReplicationSubnetRequest{Prefix: netip.MustParsePrefix(prefix), Site: &site, Location: InternalTopologyPointer("Rack 2")})
		if err != nil || !created.Mutation.Verified || created.Subnet.Prefix == nil ||
			created.Subnet.SiteDN == nil {
			t.Fatal(created, err)
		}
		identity := admodel.InternalObjectGUIDIdentity(*created.Mutation.TargetGUID)
		site = InternalTopologyTestIdentity(InternalTopologyTestSiteB)
		updated, err := adservice_replication.New(client).
			UpdateReplicationSubnet(context.Background(), admodel.UpdateReplicationSubnetRequest{Identity: identity, Site: &site})
		if err != nil || !updated.Mutation.Verified ||
			*updated.Subnet.SiteDN != InternalTopologyTestSiteB {
			t.Fatal(updated, err)
		}
		_, err = adservice_replication.New(client).
			CreateReplicationSubnet(context.Background(), admodel.CreateReplicationSubnetRequest{Prefix: netip.MustParsePrefix(prefix)})
		if !errors.Is(err, admodel.ErrObjectAlreadyExists) {
			t.Fatal(err)
		}
		deleted, err := adservice_replication.New(client).
			DeleteReplicationSubnet(context.Background(), identity, admodel.ObjectMutationOptions{})
		if err != nil || !deleted.Verified || len(session.InternalWrites) != 4 {
			t.Fatal(deleted, err)
		}
	}
	for _, prefix := range []netip.Prefix{{}, netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("2001:db8::1/64"), netip.MustParsePrefix("::ffff:192.0.2.0/120")} {
		client, session := InternalNewTopologyTestClient(t, false)
		_, err := adservice_replication.New(client).
			CreateReplicationSubnet(context.Background(), admodel.CreateReplicationSubnetRequest{Prefix: prefix})
		if !errors.Is(err, admodel.ErrInvalidReplicationSubnet) ||
			len(session.InternalWrites) != 0 {
			t.Fatal(prefix, err)
		}
	}
}

func TestDirectoryServerMovePreservesIdentityAndSubtree(t *testing.T) {
	for _, lds := range []bool{false, true} {
		for _, input := range []string{InternalTopologyTestServer, "CN=NTDS Settings," + InternalTopologyTestServer} {
			client, session := InternalNewTopologyTestClient(t, lds)
			request := admodel.MoveDirectoryServerRequest{
				Server: InternalTopologyTestIdentity(input),
				Site:   InternalTopologyTestIdentity(InternalTopologyTestSiteB),
			}
			result, err := adservice_replication.New(client).
				MoveDirectoryServer(context.Background(), request)
			if err != nil || !result.Mutation.Verified ||
				result.Mutation.State != admodel.ObjectWriteAccepted ||
				len(session.InternalWrites) != 1 ||
				!admodel.InternalTopologySameDN(
					result.After.Server.DistinguishedName,
					"CN=DC1,CN=Servers,"+InternalTopologyTestSiteB,
				) ||
				!admodel.InternalTopologySameDN(
					result.After.Settings.DistinguishedName,
					"CN=NTDS Settings,CN=DC1,CN=Servers,"+InternalTopologyTestSiteB,
				) {
				t.Fatal(result, err)
			}
			if session.InternalWrites[0].InternalOperation != admodel.InternalLdapWriteRename ||
				session.InternalWrites[0].InternalNewParent != "CN=Servers,"+InternalTopologyTestSiteB ||
				!strings.HasPrefix(session.InternalWrites[0].InternalDn, "<GUID=") {
				t.Fatal(session.InternalWrites)
			}
			request.Server = admodel.InternalObjectGUIDIdentity(*result.Mutation.TargetGUID)
			noop, err := adservice_replication.New(client).
				MoveDirectoryServer(context.Background(), request)
			if err != nil || !noop.NoChange || !noop.Mutation.Verified ||
				noop.Mutation.State != admodel.ObjectWriteNotAttempted ||
				len(session.InternalWrites) != 1 {
				t.Fatal(noop, err)
			}
			request.Options.ExpectedVersion = &admodel.ObjectVersion{
				Source:     (*adengine.InternalClientConfigPointer(client)).Endpoint,
				GUID:       *result.Mutation.TargetGUID,
				USNChanged: 7,
			}
			_, err = adservice_replication.New(client).
				MoveDirectoryServer(context.Background(), request)
			if !errors.Is(err, admodel.ErrObjectControlUnsupported) ||
				len(session.InternalWrites) != 1 {
				t.Fatal(err)
			}
		}
	}
}

func TestDirectoryServerMoveRejectsWrongTargetsAndRetainsAcceptedReadbackFailure(t *testing.T) {
	for _, mode := range []string{"account", "missing-site", "missing-settings", "uncertain", "denied", "readback-missing-settings", "changed-computer-link"} {
		client, session := InternalNewTopologyTestClient(t, false)
		request := admodel.MoveDirectoryServerRequest{
			Server: InternalTopologyTestIdentity(InternalTopologyTestServer),
			Site:   InternalTopologyTestIdentity(InternalTopologyTestSiteB),
		}
		switch mode {
		case "account":
			row := InternalTopologyTestObject("CN=DC1,DC=example", "computer", 20)
			session.InternalObjects[strings.ToLower(row.DistinguishedName)] = row
			request.Server = InternalTopologyTestIdentity(row.DistinguishedName)
		case "missing-site":
			request.Site = InternalTopologyTestIdentity(
				"CN=Missing,CN=Sites," + InternalTopologyTestConfiguration,
			)
		case "missing-settings":
			delete(
				session.InternalObjects,
				strings.ToLower("CN=NTDS Settings,"+InternalTopologyTestServer),
			)
		case "uncertain", "denied":
			session.InternalFailAt = 1
			session.InternalFailure = admodel.InternalLdapWriteAttempt{
				State: admodel.InternalLdapWriteRejected,
				Err:   &admodel.LDAPError{Code: 50},
			}
			if mode == "uncertain" {
				session.InternalFailure.State = admodel.InternalLdapWriteUncertain
			}
		case "readback-missing-settings":
			session.InternalAfterWrite = func() {
				delete(
					session.InternalObjects,
					strings.ToLower(
						"CN=NTDS Settings,CN=DC1,CN=Servers,"+InternalTopologyTestSiteB,
					),
				)
			}
		case "changed-computer-link":
			session.InternalAfterWrite = func() {
				key := strings.ToLower("CN=DC1,CN=Servers," + InternalTopologyTestSiteB)
				row := session.InternalObjects[key]
				attrs := map[string][][]byte{}
				for name, values := range row.Attributes {
					attrs[name] = values
				}
				attrs["serverreference"] = [][]byte{[]byte("CN=Wrong,DC=example")}
				row.Attributes = attrs
				session.InternalObjects[key] = row
			}
		}
		result, err := adservice_replication.New(client).
			MoveDirectoryServer(context.Background(), request)
		if err == nil || result.Mutation.Verified {
			t.Fatal(mode, result, err)
		}
		if strings.HasPrefix(mode, "readback") || mode == "changed-computer-link" {
			if result.Mutation.State != admodel.ObjectWriteAccepted ||
				result.Mutation.After == nil ||
				len(session.InternalWrites) != 1 {
				t.Fatal(result, err)
			}
		} else if mode == "uncertain" {
			if !errors.Is(err, admodel.ErrObjectWriteUncertain) ||
				len(session.InternalWrites) != 1 {
				t.Fatal(result, err)
			}
		} else if mode == "denied" {
			if !errors.Is(err, admodel.ErrObjectWritePermission) ||
				len(session.InternalWrites) != 1 {
				t.Fatal(result, err)
			}
		} else if len(session.InternalWrites) != 0 {
			t.Fatal("invalid preflight wrote", session.InternalWrites)
		}
	}
}

func TestDirectoryServerMoveValidatesRelatedReadbackGUIDs(t *testing.T) {
	for _, target := range []string{"settings", "site"} {
		for _, mode := range []string{"missing", "malformed", "mismatched", "wrong-class", "wrong-placement"} {
			t.Run(target+"/"+mode, func(t *testing.T) {
				client, session := InternalNewTopologyTestClient(t, false)
				id := byte(13)
				if target == "site" {
					id = 8
				}
				wanted, _ := admodel.GUIDFromBytes(append([]byte{id}, make([]byte, 15)...))
				search := session.InternalSearch
				session.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if len(session.InternalWrites) > 0 &&
						strings.Contains(
							query.Filter,
							admodel.InternalIdentityBinaryLiteral(wanted.Bytes()),
						) {
						object, _ := session.InternalLookup(
							admodel.InternalObjectGUIDTarget(wanted),
						)
						attrs := map[string][][]byte{}
						for key, values := range object.Attributes {
							attrs[key] = values
						}
						object.Attributes = attrs
						switch mode {
						case "missing":
							delete(attrs, "objectguid")
						case "malformed":
							attrs["objectguid"] = [][]byte{{1, 2, 3}}
						case "mismatched":
							attrs["objectguid"] = [][]byte{append([]byte{99}, make([]byte, 15)...)}
						case "wrong-class":
							attrs["objectclass"] = [][]byte{[]byte("container")}
						case "wrong-placement":
							object.DistinguishedName = "CN=Wrong,CN=Services," + InternalTopologyTestConfiguration
						}
						return InternalObjectTestCursor(object), nil
					}
					return search(ctx, query)
				}
				result, err := adservice_replication.New(client).
					MoveDirectoryServer(context.Background(), admodel.MoveDirectoryServerRequest{Server: InternalTopologyTestIdentity(InternalTopologyTestServer), Site: InternalTopologyTestIdentity(InternalTopologyTestSiteB)})
				if !errors.Is(err, admodel.ErrObjectVerification) ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					result.Mutation.Verified ||
					result.Mutation.After == nil ||
					result.SettingsAfter.Object == nil ||
					result.DestinationSiteAfter.Object == nil ||
					len(session.InternalWrites) != 1 {
					t.Fatalf(
						"accepted write/raw related observations lost: state=%d verified=%t writes=%d err=%v",
						result.Mutation.State,
						result.Mutation.Verified,
						len(session.InternalWrites),
						err,
					)
				}
			})
		}
	}
}

func TestReplicationSiteDeadlineNoopAndSignedOptionBits(t *testing.T) {
	client, session := InternalNewTopologyTestClient(t, false)
	read := session.InternalRead
	var first time.Time
	reads := 0
	session.InternalRead = func(ctx context.Context, props []string) (map[string][][]byte, error) {
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
	created, err := adservice_replication.New(client).
		CreateReplicationSite(context.Background(), admodel.CreateReplicationSiteRequest{Name: "Bounded"})
	if err != nil || !created.Complete || reads < 4 {
		t.Fatal(created, err)
	}
	client, session = InternalNewTopologyTestClient(t, false)
	key := strings.ToLower("CN=NTDS Site Settings," + InternalTopologyTestSiteB)
	object := session.InternalObjects[key]
	object.Attributes["options"] = [][]byte{[]byte("-2147483648")}
	result, err := adservice_replication.New(client).
		UpdateReplicationSite(context.Background(), admodel.UpdateReplicationSiteRequest{Identity: InternalTopologyTestIdentity(InternalTopologyTestSiteB), Settings: &admodel.ReplicationSiteSettingsPatch{SetOptions: admodel.SiteEnableScheduleHashing}})
	if err != nil || !result.Complete ||
		uint32(*result.After.Site.Settings.Options) != 0x80000200 ||
		string(
			session.InternalWrites[0].InternalModifications[0].InternalValues[0],
		) != "-2147483648" ||
		string(
			session.InternalWrites[0].InternalModifications[1].InternalValues[0],
		) != "-2147483136" {
		t.Fatal(result, err)
	}
	settingsGUID, _ := admodel.InternalTopologyGUID(object)
	_, err = adservice_replication.New(client).
		UpdateReplicationSite(context.Background(), admodel.UpdateReplicationSiteRequest{Identity: InternalTopologyTestIdentity(InternalTopologyTestSiteB), Description: InternalTopologyPointer("must not write"), Settings: &admodel.ReplicationSiteSettingsPatch{SetOptions: admodel.SiteEnableScheduleHashing}, SettingsExpectedVersion: &admodel.ObjectVersion{Source: (*adengine.InternalClientConfigPointer(client)).Endpoint, GUID: settingsGUID, USNChanged: 7}})
	if !errors.Is(err, admodel.ErrObjectControlUnsupported) || len(session.InternalWrites) != 1 {
		t.Fatal(err, session.InternalWrites)
	}
}

func TestReplicationSiteDeletionServerGuardPrecedesSettingsCleanup(t *testing.T) {
	client, session := InternalNewTopologyTestClient(t, false)
	search := session.InternalSearch
	session.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if query.Scope == admodel.ScopeSubtree &&
			admodel.InternalTopologySameDN(query.Base, InternalTopologyTestSiteA) {
			var rows []admodel.Object
			for _, object := range session.InternalObjects {
				if admodel.InternalTopologySameDN(
					object.DistinguishedName,
					InternalTopologyTestSiteA,
				) {
					rows = append(rows, object)
					continue
				}
				parent, _ := admodel.InternalParentDirectoryDN(object.DistinguishedName)
				if admodel.InternalTopologySameDN(parent, InternalTopologyTestSiteA) {
					rows = append(rows, object)
				}
			}
			return InternalObjectTestCursor(rows...), nil // Descendant servers are hidden.
		}
		return search(ctx, query)
	}
	result, err := adservice_replication.New(client).
		DeleteReplicationSite(context.Background(), InternalTopologyTestIdentity(InternalTopologyTestSiteA), admodel.ObjectMutationOptions{})
	if !errors.Is(err, admodel.ErrObjectNotLeaf) || len(result.Steps) != 1 ||
		result.Steps[0].Mutation.State != admodel.ObjectWriteRejected ||
		len(session.InternalWrites) != 1 ||
		result.Steps[0].Name != "CN=Servers,"+InternalTopologyTestSiteA {
		t.Fatal(result, err)
	}
	if _, ok := session.InternalLookup("CN=NTDS Site Settings," + InternalTopologyTestSiteA); !ok {
		t.Fatal("settings were removed before nonempty container rejection")
	}
}
