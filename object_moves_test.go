package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const moveTestConfig = "CN=Configuration,DC=example"
const moveTestSourceDN = `CN=李\, Demo,OU=Old,DC=example`

type moveTestSession struct {
	root        map[string][][]byte
	objects     map[string]Object
	search      func(context.Context, SearchOptions) (searchCursor, error)
	write       func(context.Context, ldapWriteRequest) ldapWriteAttempt
	security    MoveSecurity
	securityErr error
}

func (s *moveTestSession) baseObject(context.Context, string, []string) (map[string][][]byte, error) {
	return s.root, nil
}
func (s *moveTestSession) rangedBaseObject(context.Context, string, []string) (map[string][][]byte, error) {
	// Moves do not issue ranged reads; satisfy the shared replication session seam.
	return nil, ErrUnsupported
}
func (s *moveTestSession) close() error { return nil }
func (s *moveTestSession) startSearch(ctx context.Context, options SearchOptions) (searchCursor, error) {
	if s.search != nil {
		return s.search(ctx, options)
	}
	if object, found := s.objects[options.Base]; found && options.Scope == ScopeBase {
		return objectTestCursor(object), nil
	}
	if strings.HasPrefix(options.Filter, "(objectGUID=") {
		for _, object := range s.objects {
			if values := object.Attributes["objectguid"]; len(values) == 1 && options.Filter == "(objectGUID="+identityBinaryLiteral(values[0])+")" {
				return objectTestCursor(object), nil
			}
		}
	}
	return objectTestCursor(), nil
}
func (s *moveTestSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	return s.write(ctx, request)
}
func (s *moveTestSession) moveSecurity(context.Context) (MoveSecurity, error) {
	return s.security, s.securityErr
}

type moveTestFixture struct {
	source, destination *Client
	src, dst            *moveTestSession
	request             MoveObjectRequest
	writes              []ldapWriteRequest
	attempt             ldapWriteAttempt
	readback            func(Object) Object
}

func moveIdentity(dn string) Identity { identity, _ := IdentityByDN(dn); return identity }
func moveTestObject(dn, class string, guidByte byte) Object {
	guid := make([]byte, 16)
	guid[0] = guidByte
	return Object{DistinguishedName: dn, Attributes: map[string][][]byte{"objectguid": {guid}, "objectclass": {[]byte("top"), []byte(class)}, "instancetype": {[]byte("4")}, "usnchanged": {[]byte("7")}}}
}
func newMoveTestFixture(t *testing.T, cross, lds bool) *moveTestFixture {
	t.Helper()
	f := &moveTestFixture{attempt: ldapWriteAttempt{State: ldapWriteAccepted}}
	create := func(host, nc string) (*Client, *moveTestSession) {
		capability := CapabilityActiveDirectory
		if lds {
			capability = CapabilityADLDS
		}
		dsa := "CN=NTDS Settings,CN=" + host + ",CN=Servers,CN=Default-Site,CN=Sites," + moveTestConfig
		s := &moveTestSession{root: map[string][][]byte{"supportedcapabilities": {[]byte(capability)}, "namingcontexts": {[]byte(nc), []byte(moveTestConfig), []byte("CN=Schema," + moveTestConfig)}, "defaultnamingcontext": {[]byte(nc)}, "configurationnamingcontext": {[]byte(moveTestConfig)}, "schemanamingcontext": {[]byte("CN=Schema," + moveTestConfig)}, "rootdomainnamingcontext": {[]byte("DC=example")}, "dnshostname": {[]byte(host)}, "dsservicename": {[]byte(dsa)}, "supportedcontrol": {[]byte(objectCrossDomainMoveControl), []byte(objectAssertionControl)}}, objects: map[string]Object{}, security: MoveSecurity{Package: "Kerberos", Delegated: true, Complete: true}}
		domain := moveTestObject(nc, "domainDNS", 2)
		domain.Attributes["instancetype"] = [][]byte{[]byte("5")}
		managerDN := "CN=RID Manager$,CN=System," + nc
		domain.Attributes["ridmanagerreference"] = [][]byte{[]byte(managerDN)}
		manager := moveTestObject(managerDN, "rIDManager", 3)
		manager.Attributes["fsmoroleowner"] = [][]byte{[]byte(dsa)}
		s.objects[nc], s.objects[managerDN], s.objects[moveTestConfig] = domain, manager, moveTestObject(moveTestConfig, "configuration", 9)
		client := newClient(Config{Endpoint: Endpoint{Host: host, Port: 389}, AllowDelegation: true, Timeout: time.Second}, s)
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		})
		return client, s
	}
	f.source, f.src = create("src.example", "DC=example")
	f.destination, f.dst = f.source, f.src
	if cross {
		f.destination, f.dst = create("dst.child.example", "DC=child,DC=example")
	}
	parentDN := "OU=目标," + string(f.dst.root["defaultnamingcontext"][0])
	f.dst.objects[parentDN] = moveTestObject(parentDN, "organizationalUnit", 7)
	f.src.objects[moveTestSourceDN] = moveTestObject(moveTestSourceDN, "user", 1)
	f.request = MoveObjectRequest{Identity: moveIdentity(moveTestSourceDN), TargetParent: moveIdentity(parentDN), Options: ObjectMutationOptions{Properties: []string{"description"}}}
	if cross {
		f.request.Destination = f.destination
	}
	f.src.write = func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
		f.writes = append(f.writes, request)
		if f.attempt.State == ldapWriteAccepted {
			object := f.src.objects[moveTestSourceDN]
			delete(f.src.objects, moveTestSourceDN)
			object.DistinguishedName = request.newRDN + "," + request.newParent
			object.Attributes["description"] = [][]byte{[]byte("retained")}
			if f.readback != nil {
				object = f.readback(object)
			}
			f.dst.objects[object.DistinguishedName] = object
		}
		return f.attempt
	}
	f.dst.write = f.src.write
	return f
}

func TestMoveObjectNativeSemanticsPortable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cross, lds bool
	}{{"DS", false, false}, {"LDS", false, true}, {"cross-domain", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMoveTestFixture(t, tc.cross, tc.lds)
			id, _ := IdentityByGUID("00000001-0000-0000-0000-000000000000")
			f.request.Identity = id
			f.request.Options.ExpectedVersion = &ObjectVersion{Source: f.source.config.Endpoint, USNChanged: 7}
			guid, _ := GUIDFromBytes(f.src.objects[moveTestSourceDN].Attributes["objectguid"][0])
			f.request.Options.ExpectedVersion.GUID = guid
			result, err := f.source.MoveObject(context.Background(), f.request)
			if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted || len(f.writes) != 1 {
				t.Fatalf("%+v %v writes=%d", result, err, len(f.writes))
			}
			write := f.writes[0]
			if write.operation != ldapWriteRename || write.dn != objectGUIDTarget(guid) || write.newRDN != `CN=李\, Demo` || write.newParent != f.request.TargetParent.String() || !write.deleteOldRDN || len(write.modifications) != 0 {
				t.Fatalf("%+v", write)
			}
			if write.controls[0].oid != objectAssertionControl || !write.controls[0].critical {
				t.Fatal(write.controls)
			}
			if tc.cross {
				if len(write.controls) != 2 || string(write.controls[1].value) != "dst.child.example" || !write.controls[1].critical || write.controls[1].oid != objectCrossDomainMoveControl {
					t.Fatal(write.controls)
				}
				if !result.Security.Complete || !result.SourceObservation.Complete || !result.DestinationObservation.Complete || len(result.SourceObservation.Objects) != 3 || len(result.DestinationObservation.Objects) != 3 || !result.Mutation.PartialEffectsPossible {
					t.Fatal(result)
				}
			} else if len(write.controls) != 1 || result.Mutation.PartialEffectsPossible {
				t.Fatal(result)
			}
			if result.Mutation.Partition != "DC=example" || result.Mutation.After == nil || result.Mutation.After.Attributes["description"] == nil {
				t.Fatal(result)
			}
		})
	}
}

func TestMoveObjectGuardsAndOutcomes(t *testing.T) {
	for _, mode := range []string{"no-delegation", "simple", "security", "security-incomplete", "LDS", "source-RID", "destination-RID", "missing-RID", "hidden-forest", "other-forest", "other-root", "wrong-host", "missing-control", "source-GC", "readonly-domain", "readonly-object", "class", "deleted", "critical", "protected", "domain-flag", "trust-account", "restricted-SID", "builtin-group", "missing-instance", "ranged-class", "wrong-parent-GUID", "same-domain", "denied", "collision", "not-leaf", "rejected-partial", "uncertain", "readback-missing", "readback-GUID", "readback-moved", "readback-deleted"} {
		t.Run(mode, func(t *testing.T) {
			f := newMoveTestFixture(t, true, false)
			object := f.src.objects[moveTestSourceDN]
			wantWrite := false
			switch mode {
			case "no-delegation":
				f.source.config.AllowDelegation = false
			case "simple":
				f.source.config.Authentication = AuthenticationSimple
			case "security":
				f.src.securityErr = ErrMoveDelegation
			case "security-incomplete":
				f.src.security.Complete = false
			case "LDS":
				f.dst.root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "source-RID", "destination-RID", "missing-RID":
				s := f.src
				if mode != "source-RID" {
					s = f.dst
				}
				for key, o := range s.objects {
					if strings.HasPrefix(key, "CN=RID Manager$") {
						if mode == "missing-RID" {
							delete(o.Attributes, "fsmoroleowner")
						} else {
							o.Attributes["fsmoroleowner"] = [][]byte{[]byte("CN=Other," + moveTestConfig)}
						}
						s.objects[key] = o
					}
				}
			case "hidden-forest":
				delete(f.dst.objects, moveTestConfig)
			case "other-forest":
				o := f.dst.objects[moveTestConfig]
				o.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
				f.dst.objects[moveTestConfig] = o
			case "other-root":
				f.dst.root["rootdomainnamingcontext"] = [][]byte{[]byte("DC=other")}
			case "wrong-host":
				f.dst.root["dnshostname"] = [][]byte{[]byte("alias.example")}
			case "missing-control":
				f.src.root["supportedcontrol"] = nil
			case "source-GC":
				f.source.config.Endpoint.Port = 3268
			case "readonly-domain":
				o := f.dst.objects["DC=child,DC=example"]
				o.Attributes["instancetype"] = [][]byte{[]byte("1")}
				f.dst.objects[o.DistinguishedName] = o
			case "readonly-object":
				object.Attributes["instancetype"] = [][]byte{[]byte("0")}
			case "missing-instance":
				delete(object.Attributes, "instancetype")
			case "class":
				object.Attributes["objectclass"] = [][]byte{[]byte("trustedDomain")}
			case "deleted":
				object.Attributes["isdeleted"] = [][]byte{[]byte("TRUE")}
			case "critical":
				object.Attributes["iscriticalsystemobject"] = [][]byte{[]byte("TRUE")}
			case "protected":
				object.Attributes["systemflags"] = [][]byte{[]byte("-2147483648")}
			case "domain-flag":
				object.Attributes["systemflags"] = [][]byte{[]byte("67108864")}
			case "trust-account":
				object.Attributes["useraccountcontrol"] = [][]byte{[]byte("8192")}
			case "restricted-SID":
				sid, _ := ParseSID("S-1-5-21-1-2-3-500")
				object.Attributes["objectsid"] = [][]byte{sid.Bytes()}
			case "builtin-group":
				object.Attributes["objectclass"] = [][]byte{[]byte("group")}
				object.Attributes["grouptype"] = [][]byte{[]byte("-2147483643")}
			case "ranged-class":
				delete(object.Attributes, "objectclass")
				object.Attributes["objectclass;range=0-0"] = [][]byte{[]byte("user")}
			case "wrong-parent-GUID":
				f.request.TargetParent = objectGUIDIdentity(objectTestGUID())
				f.dst.search = func(context.Context, SearchOptions) (searchCursor, error) {
					return objectTestCursor(f.dst.objects["OU=目标,DC=child,DC=example"]), nil
				}
			case "same-domain":
				f.request.Destination = f.source
			case "denied", "collision", "not-leaf", "rejected-partial":
				wantWrite = true
				code := uint32(50)
				if mode == "collision" {
					code = 68
				}
				if mode == "not-leaf" {
					code = 66
				}
				if mode == "rejected-partial" {
					code = 80
				}
				f.attempt = ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: code, Diagnostic: "native detail"}}
			case "uncertain":
				wantWrite = true
				f.attempt = ldapWriteAttempt{State: ldapWriteUncertain, Err: context.DeadlineExceeded}
			case "readback-missing":
				wantWrite = true
				f.readback = func(o Object) Object {
					f.dst.search = func(context.Context, SearchOptions) (searchCursor, error) { return objectTestCursor(), nil }
					return o
				}
			case "readback-GUID":
				wantWrite = true
				f.readback = func(o Object) Object { o.Attributes["objectguid"] = [][]byte{make([]byte, 16)}; return o }
			case "readback-moved":
				wantWrite = true
				f.readback = func(o Object) Object { o.DistinguishedName = "CN=Elsewhere,DC=child,DC=example"; return o }
			case "readback-deleted":
				wantWrite = true
				f.readback = func(o Object) Object { o.Attributes["isdeleted"] = [][]byte{[]byte("TRUE")}; return o }
			}
			f.src.objects[moveTestSourceDN] = object
			result, err := f.source.MoveObject(context.Background(), f.request)
			if err == nil || result.Mutation.Verified || len(f.writes) != map[bool]int{true: 1, false: 0}[wantWrite] {
				t.Fatalf("%+v err=%v writes=%d", result, err, len(f.writes))
			}
			if wantWrite && !result.Mutation.PartialEffectsPossible {
				t.Fatal("cross-domain partial effects lost")
			}
			if mode == "uncertain" && (result.Mutation.State != ObjectWriteUncertain || !errors.Is(err, ErrObjectWriteUncertain)) {
				t.Fatal(result, err)
			}
			if strings.HasPrefix(mode, "readback-") && result.Mutation.State != ObjectWriteAccepted {
				t.Fatal(result, err)
			}
		})
	}
}

func TestMoveObjectScopeAndValidation(t *testing.T) {
	for _, mode := range []string{"nil", "bad-target", "unexpected-partition", "cross-partition", "descendant", "NC-root", "parent-missing", "unsupported-version", "cancel", "gate-timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newMoveTestFixture(t, false, false)
			ctx := context.Background()
			switch mode {
			case "nil":
				f.source = nil
			case "bad-target":
				f.request.TargetParent = Identity{}
			case "unexpected-partition":
				f.request.DestinationPartition = "DC=example"
			case "cross-partition":
				f.request.TargetParent = moveIdentity("CN=Else," + moveTestConfig)
			case "descendant":
				f.request.TargetParent = moveIdentity("OU=Inside," + moveTestSourceDN)
				f.src.objects[f.request.TargetParent.String()] = moveTestObject(f.request.TargetParent.String(), "organizationalUnit", 8)
			case "NC-root":
				f.request.Identity = moveIdentity("DC=example")
			case "parent-missing":
				delete(f.src.objects, f.request.TargetParent.String())
			case "unsupported-version":
				f.src.root["supportedcontrol"] = nil
				guid, _ := GUIDFromBytes(f.src.objects[moveTestSourceDN].Attributes["objectguid"][0])
				f.request.Options.ExpectedVersion = &ObjectVersion{Source: f.source.config.Endpoint, GUID: guid, USNChanged: 7}
			case "cancel":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "gate-timeout":
				f.source.config.Timeout = 5 * time.Millisecond
				<-f.source.gate
				defer func() { f.source.gate <- struct{}{} }()
			}
			result, err := f.source.MoveObject(ctx, f.request)
			if err == nil || len(f.writes) != 0 || result.Mutation.State != ObjectWriteNotAttempted {
				t.Fatal(result, err)
			}
		})
	}
}

func TestMoveOptionsDoNotAliasCallerProperties(t *testing.T) {
	f := newMoveTestFixture(t, false, false)
	properties := make([]string, 1, 32)
	properties[0] = "description"
	f.request.Options.Properties = properties
	if _, err := f.source.MoveObject(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(properties, []string{"description"}) {
		t.Fatal(properties)
	}
}

func TestMoveObjectPartialObservationsPreventDispatch(t *testing.T) {
	for _, destination := range []bool{false, true} {
		t.Run(map[bool]string{false: "source", true: "destination"}[destination], func(t *testing.T) {
			f := newMoveTestFixture(t, true, false)
			s := f.src
			object := f.src.objects[moveTestSourceDN]
			if destination {
				s = f.dst
				object = f.dst.objects[f.request.TargetParent.String()]
			}
			s.search = func(context.Context, SearchOptions) (searchCursor, error) {
				return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
					return []Object{object}, true, &LDAPError{Code: 50}
				}, finish: func() error { return nil }}, nil
			}
			result, err := f.source.MoveObject(context.Background(), f.request)
			if !errors.Is(err, ErrObjectWritePermission) || len(f.writes) != 0 {
				t.Fatal(err, f.writes)
			}
			if destination {
				if len(result.Parent.Candidates) != 1 || result.Parent.Complete {
					t.Fatal(result.Parent)
				}
			} else if len(result.Mutation.PreflightCandidates) != 1 {
				t.Fatal(result.Mutation.PreflightCandidates)
			}
		})
	}
}

func TestMoveObjectExplicitParentGUID(t *testing.T) {
	f := newMoveTestFixture(t, true, false)
	parent := f.dst.objects[f.request.TargetParent.String()]
	guid, _ := GUIDFromBytes(parent.Attributes["objectguid"][0])
	f.request.TargetParent = objectGUIDIdentity(guid)
	f.request.DestinationPartition = "DC=child,DC=example"
	result, err := f.source.MoveObject(context.Background(), f.request)
	if err != nil || !result.Mutation.Verified || result.Parent.Object.DistinguishedName != parent.DistinguishedName {
		t.Fatal(err)
	}
}

func TestMoveObjectLocalRestrictions(t *testing.T) {
	for _, mode := range []string{"RODC", "secret", "trustedDomain", "domain-move-flag", "schema-class"} {
		t.Run(mode, func(t *testing.T) {
			f := newMoveTestFixture(t, false, false)
			o := f.src.objects[moveTestSourceDN]
			switch mode {
			case "RODC":
				f.src.root["supportedcapabilities"] = append(f.src.root["supportedcapabilities"], []byte("1.2.840.113556.1.4.1920"))
			case "secret", "trustedDomain":
				o.Attributes["objectclass"] = [][]byte{[]byte(mode)}
			case "domain-move-flag":
				o.Attributes["systemflags"] = [][]byte{[]byte("67108864")}
			case "schema-class":
				o.Attributes["objectclass"] = [][]byte{[]byte("classSchema")}
			}
			f.src.objects[moveTestSourceDN] = o
			result, err := f.source.MoveObject(context.Background(), f.request)
			if err == nil || result.Mutation.State != ObjectWriteNotAttempted || len(f.writes) != 0 {
				t.Fatal(result.Mutation.State, err)
			}
		})
	}
}

func TestMoveObjectClientLifetimeAndDestinationBounds(t *testing.T) {
	for _, mode := range []string{"source-closed", "destination-closed", "destination-empty", "destination-timeout", "destination-canceled", "source-timeout", "destination-closed-after-acceptance", "local-verification"} {
		t.Run(mode, func(t *testing.T) {
			f := newMoveTestFixture(t, mode != "local-verification", false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "source-closed":
				_ = f.source.Close()
			case "destination-closed":
				_ = f.destination.Close()
			case "destination-empty":
				f.request.Destination = &Client{}
			case "destination-timeout", "destination-canceled":
				f.destination.config.Timeout = 5 * time.Millisecond
				f.dst.search = func(ctx context.Context, _ SearchOptions) (searchCursor, error) {
					if mode == "destination-canceled" {
						cancel()
					}
					<-ctx.Done()
					return nil, context.Cause(ctx)
				}
			case "source-timeout":
				f.source.config.Timeout = 5 * time.Millisecond
				f.src.search = func(ctx context.Context, _ SearchOptions) (searchCursor, error) {
					<-ctx.Done()
					return nil, context.Cause(ctx)
				}
			case "destination-closed-after-acceptance":
				f.readback = func(o Object) Object { _ = f.destination.Close(); return o }
			case "local-verification":
				f.readback = func(o Object) Object { o.DistinguishedName = "CN=Elsewhere,DC=example"; return o }
			}
			result, err := f.source.MoveObject(ctx, f.request)
			if err == nil || result.Mutation.Verified {
				t.Fatal(result.Mutation.State, err)
			}
			if mode == "destination-closed-after-acceptance" || mode == "local-verification" {
				if result.Mutation.State != ObjectWriteAccepted || !errors.Is(err, ErrObjectReadback) || len(f.writes) != 1 {
					t.Fatal(result.Mutation.State, err)
				}
			} else if result.Mutation.State != ObjectWriteNotAttempted || len(f.writes) != 0 {
				t.Fatal(result.Mutation.State, err)
			}
			if strings.HasSuffix(mode, "timeout") && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			if mode == "destination-canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

func TestMoveObjectReciprocalClientsReleaseGates(t *testing.T) {
	f := newMoveTestFixture(t, true, false)
	parentA := "OU=Return,DC=example"
	f.src.objects[parentA] = moveTestObject(parentA, "organizationalUnit", 8)
	objectB := "CN=Second,DC=child,DC=example"
	f.dst.objects[objectB] = moveTestObject(objectB, "user", 11)
	reverse := MoveObjectRequest{Identity: moveIdentity(objectB), TargetParent: moveIdentity(parentA), Destination: f.source}
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	for _, target := range []struct {
		s      *moveTestSession
		parent string
	}{{f.src, parentA}, {f.dst, f.request.TargetParent.String()}} {
		plain := *target.s
		target.s.search = func(ctx context.Context, options SearchOptions) (searchCursor, error) {
			if options.Scope == ScopeBase && options.Base == target.parent {
				arrived <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			}
			return plain.startSearch(ctx, options)
		}
	}
	writes := make(chan struct{}, 2)
	write := func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		writes <- struct{}{}
		return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50}}
	}
	f.src.write, f.dst.write = write, write
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() { _, err := f.source.MoveObject(ctx, f.request); results <- err }()
	go func() { _, err := f.destination.MoveObject(ctx, reverse); results <- err }()
	for range 2 {
		select {
		case <-arrived:
		case <-ctx.Done():
			t.Fatal("reciprocal preflights retained both gates")
		}
	}
	close(release)
	for range 2 {
		select {
		case err := <-results:
			if !errors.Is(err, ErrObjectWritePermission) {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("reciprocal dispatch retained a gate")
		}
	}
	if len(writes) != 2 {
		t.Fatal("unexpected dispatch count", len(writes))
	}
}

func TestMoveObjectCrossDomainRIDBoundary(t *testing.T) {
	for _, rid := range []string{"1000", "1001"} {
		t.Run(rid, func(t *testing.T) {
			f := newMoveTestFixture(t, true, false)
			o := f.src.objects[moveTestSourceDN]
			sid, err := ParseSID("S-1-5-21-1-2-3-" + rid)
			if err != nil {
				t.Fatal(err)
			}
			o.Attributes["objectsid"] = [][]byte{sid.Bytes()}
			f.src.objects[moveTestSourceDN] = o
			result, err := f.source.MoveObject(context.Background(), f.request)
			if rid == "1000" {
				if !errors.Is(err, ErrObjectMoveForbidden) || len(f.writes) != 0 {
					t.Fatal(err)
				}
			} else if err != nil || !result.Mutation.Verified || len(f.writes) != 1 {
				t.Fatal(err)
			}
		})
	}
}
