package acceptance

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

const (
	InternalMoveTestConfig   = "CN=Configuration,DC=example"
	InternalMoveTestSourceDN = `CN=李\, Demo,OU=Old,DC=example`
)

type InternalMoveTestSession struct {
	InternalRoot        map[string][][]byte
	InternalObjects     map[string]admodel.Object
	InternalSearch      func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error)
	InternalWrite       func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt
	InternalSecurity    admodel.MoveSecurity
	InternalSecurityErr error
}

func (s *InternalMoveTestSession) InternalBaseObject(
	context.Context,
	string,
	[]string,
) (map[string][][]byte, error) {
	return s.InternalRoot, nil
}

func (s *InternalMoveTestSession) InternalRangedBaseObject(
	context.Context,
	string,
	[]string,
) (map[string][][]byte, error) {
	// Moves do not issue ranged reads; satisfy the shared replication session seam.
	return nil, admodel.ErrUnsupported
}
func (s *InternalMoveTestSession) InternalClose() error { return nil }

func (s *InternalMoveTestSession) InternalStartSearch(
	ctx context.Context,
	options admodel.SearchOptions,
) (admodel.InternalSearchCursor, error) {
	if s.InternalSearch != nil {
		return s.InternalSearch(ctx, options)
	}
	if object, found := s.InternalObjects[options.Base]; found &&
		options.Scope == admodel.ScopeBase {
		return InternalObjectTestCursor(object), nil
	}
	if strings.HasPrefix(options.Filter, "(objectGUID=") {
		for _, object := range s.InternalObjects {
			if values := object.Attributes["objectguid"]; len(values) == 1 &&
				options.Filter == "(objectGUID="+admodel.InternalIdentityBinaryLiteral(
					values[0],
				)+")" {
				return InternalObjectTestCursor(object), nil
			}
		}
	}
	return InternalObjectTestCursor(), nil
}

func (s *InternalMoveTestSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	return s.InternalWrite(ctx, request)
}

func (s *InternalMoveTestSession) InternalMoveSecurity(
	context.Context,
) (admodel.MoveSecurity, error) {
	return s.InternalSecurity, s.InternalSecurityErr
}

type InternalMoveTestFixture struct {
	InternalSource, InternalDestination *adengine.Client
	InternalSrc, InternalDst            *InternalMoveTestSession
	InternalRequest                     adengine.MoveObjectRequest
	InternalWrites                      []admodel.InternalLdapWriteRequest
	InternalAttempt                     admodel.InternalLdapWriteAttempt
	InternalReadback                    func(admodel.Object) admodel.Object
}

func InternalMoveIdentity(dn string) admodel.Identity {
	identity, _ := admodel.IdentityByDN(dn)
	return identity
}

func InternalMoveTestObject(dn, class string, guidByte byte) admodel.Object {
	guid := make([]byte, 16)
	guid[0] = guidByte
	return admodel.Object{
		DistinguishedName: dn,
		Attributes: map[string][][]byte{
			"objectguid":   {guid},
			"objectclass":  {[]byte("top"), []byte(class)},
			"instancetype": {[]byte("4")},
			"usnchanged":   {[]byte("7")},
		},
	}
}

func InternalNewMoveTestFixture(t *testing.T, cross, lds bool) *InternalMoveTestFixture {
	t.Helper()
	f := &InternalMoveTestFixture{
		InternalAttempt: admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted},
	}
	create := func(host, nc string) (*adengine.Client, *InternalMoveTestSession) {
		capability := admodel.CapabilityActiveDirectory
		if lds {
			capability = admodel.CapabilityADLDS
		}
		dsa := "CN=NTDS Settings,CN=" + host + ",CN=Servers,CN=Default-Site,CN=Sites," + InternalMoveTestConfig
		s := &InternalMoveTestSession{
			InternalRoot: map[string][][]byte{
				"supportedcapabilities": {[]byte(capability)},
				"namingcontexts": {
					[]byte(nc),
					[]byte(InternalMoveTestConfig),
					[]byte("CN=Schema," + InternalMoveTestConfig),
				},
				"defaultnamingcontext":       {[]byte(nc)},
				"configurationnamingcontext": {[]byte(InternalMoveTestConfig)},
				"schemanamingcontext":        {[]byte("CN=Schema," + InternalMoveTestConfig)},
				"rootdomainnamingcontext":    {[]byte("DC=example")},
				"dnshostname":                {[]byte(host)},
				"dsservicename":              {[]byte(dsa)},
				"supportedcontrol": {
					[]byte(admodel.InternalObjectCrossDomainMoveControl),
					[]byte(admodel.InternalObjectAssertionControl),
				},
			},
			InternalObjects: map[string]admodel.Object{},
			InternalSecurity: admodel.MoveSecurity{
				Package:   "Kerberos",
				Delegated: true,
				Complete:  true,
			},
		}
		domain := InternalMoveTestObject(nc, "domainDNS", 2)
		domain.Attributes["instancetype"] = [][]byte{[]byte("5")}
		managerDN := "CN=RID Manager$,CN=System," + nc
		domain.Attributes["ridmanagerreference"] = [][]byte{[]byte(managerDN)}
		manager := InternalMoveTestObject(managerDN, "rIDManager", 3)
		manager.Attributes["fsmoroleowner"] = [][]byte{[]byte(dsa)}
		s.InternalObjects[nc], s.InternalObjects[managerDN], s.InternalObjects[InternalMoveTestConfig] = domain, manager, InternalMoveTestObject(
			InternalMoveTestConfig,
			"configuration",
			9,
		)
		client := adengine.InternalNewClient(
			admodel.Config{
				Endpoint:        admodel.Endpoint{Host: host, Port: 389},
				AllowDelegation: true,
				Timeout:         time.Second,
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
	f.InternalSource, f.InternalSrc = create("src.example", "DC=example")
	f.InternalDestination, f.InternalDst = f.InternalSource, f.InternalSrc
	if cross {
		f.InternalDestination, f.InternalDst = create("dst.child.example", "DC=child,DC=example")
	}
	parentDN := "OU=目标," + string(f.InternalDst.InternalRoot["defaultnamingcontext"][0])
	f.InternalDst.InternalObjects[parentDN] = InternalMoveTestObject(
		parentDN,
		"organizationalUnit",
		7,
	)
	f.InternalSrc.InternalObjects[InternalMoveTestSourceDN] = InternalMoveTestObject(
		InternalMoveTestSourceDN,
		"user",
		1,
	)
	f.InternalRequest = adengine.MoveObjectRequest{
		Identity:     InternalMoveIdentity(InternalMoveTestSourceDN),
		TargetParent: InternalMoveIdentity(parentDN),
		Options:      admodel.ObjectMutationOptions{Properties: []string{"description"}},
	}
	if cross {
		f.InternalRequest.Destination = f.InternalDestination
	}
	f.InternalSrc.InternalWrite = func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
		f.InternalWrites = append(f.InternalWrites, request)
		if f.InternalAttempt.State == admodel.InternalLdapWriteAccepted {
			object := f.InternalSrc.InternalObjects[InternalMoveTestSourceDN]
			delete(f.InternalSrc.InternalObjects, InternalMoveTestSourceDN)
			object.DistinguishedName = request.InternalNewRDN + "," + request.InternalNewParent
			object.Attributes["description"] = [][]byte{[]byte("retained")}
			if f.InternalReadback != nil {
				object = f.InternalReadback(object)
			}
			f.InternalDst.InternalObjects[object.DistinguishedName] = object
		}
		return f.InternalAttempt
	}
	f.InternalDst.InternalWrite = f.InternalSrc.InternalWrite
	return f
}

func TestMoveObjectNativeSemanticsPortable(t *testing.T) {
	for _, tc := range []struct {
		InternalName               string
		InternalCross, InternalLds bool
	}{{"DS", false, false}, {"LDS", false, true}, {"cross-domain", true, false}} {
		t.Run(tc.InternalName, func(t *testing.T) {
			f := InternalNewMoveTestFixture(t, tc.InternalCross, tc.InternalLds)
			id, _ := admodel.IdentityByGUID("00000001-0000-0000-0000-000000000000")
			f.InternalRequest.Identity = id
			f.InternalRequest.Options.ExpectedVersion = &admodel.ObjectVersion{
				Source:     (*adengine.InternalClientConfigPointer(f.InternalSource)).Endpoint,
				USNChanged: 7,
			}
			guid, _ := admodel.GUIDFromBytes(
				f.InternalSrc.InternalObjects[InternalMoveTestSourceDN].Attributes["objectguid"][0],
			)
			f.InternalRequest.Options.ExpectedVersion.GUID = guid
			result, err := f.InternalSource.MoveObject(context.Background(), f.InternalRequest)
			if err != nil || !result.Mutation.Verified ||
				result.Mutation.State != admodel.ObjectWriteAccepted ||
				len(f.InternalWrites) != 1 {
				t.Fatalf("%+v %v writes=%d", result, err, len(f.InternalWrites))
			}
			write := f.InternalWrites[0]
			if write.InternalOperation != admodel.InternalLdapWriteRename ||
				write.InternalDn != admodel.InternalObjectGUIDTarget(guid) ||
				write.InternalNewRDN != `CN=李\, Demo` ||
				write.InternalNewParent != f.InternalRequest.TargetParent.String() ||
				!write.InternalDeleteOldRDN ||
				len(write.InternalModifications) != 0 {
				t.Fatalf("%+v", write)
			}
			if write.InternalControls[0].InternalOid != admodel.InternalObjectAssertionControl ||
				!write.InternalControls[0].InternalCritical {
				t.Fatal(write.InternalControls)
			}
			if tc.InternalCross {
				if len(write.InternalControls) != 2 ||
					string(write.InternalControls[1].InternalValue) != "dst.child.example" ||
					!write.InternalControls[1].InternalCritical ||
					write.InternalControls[1].InternalOid != admodel.InternalObjectCrossDomainMoveControl {
					t.Fatal(write.InternalControls)
				}
				if !result.Security.Complete || !result.SourceObservation.Complete ||
					!result.DestinationObservation.Complete ||
					len(result.SourceObservation.Objects) != 3 ||
					len(result.DestinationObservation.Objects) != 3 ||
					!result.Mutation.PartialEffectsPossible {
					t.Fatal(result)
				}
			} else if len(write.InternalControls) != 1 || result.Mutation.PartialEffectsPossible {
				t.Fatal(result)
			}
			if result.Mutation.Partition != "DC=example" || result.Mutation.After == nil ||
				result.Mutation.After.Attributes["description"] == nil {
				t.Fatal(result)
			}
		})
	}
}

func TestMoveObjectGuardsAndOutcomes(t *testing.T) {
	for _, mode := range []string{"no-delegation", "simple", "security", "security-incomplete", "LDS", "source-RID", "destination-RID", "missing-RID", "hidden-forest", "other-forest", "other-root", "wrong-host", "missing-control", "source-GC", "readonly-domain", "readonly-object", "class", "deleted", "critical", "protected", "domain-flag", "trust-account", "restricted-SID", "builtin-group", "missing-instance", "ranged-class", "wrong-parent-GUID", "same-domain", "denied", "collision", "not-leaf", "rejected-partial", "uncertain", "readback-missing", "readback-GUID", "readback-moved", "readback-deleted"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewMoveTestFixture(t, true, false)
			object := f.InternalSrc.InternalObjects[InternalMoveTestSourceDN]
			wantWrite := false
			switch mode {
			case "no-delegation":
				(*adengine.InternalClientConfigPointer(f.InternalSource)).AllowDelegation = false
			case "simple":
				(*adengine.InternalClientConfigPointer(f.InternalSource)).Authentication = admodel.AuthenticationSimple
			case "security":
				f.InternalSrc.InternalSecurityErr = admodel.ErrMoveDelegation
			case "security-incomplete":
				f.InternalSrc.InternalSecurity.Complete = false
			case "LDS":
				f.InternalDst.InternalRoot["supportedcapabilities"] = [][]byte{
					[]byte(admodel.CapabilityADLDS),
				}
			case "source-RID", "destination-RID", "missing-RID":
				s := f.InternalSrc
				if mode != "source-RID" {
					s = f.InternalDst
				}
				for key, o := range s.InternalObjects {
					if strings.HasPrefix(key, "CN=RID Manager$") {
						if mode == "missing-RID" {
							delete(o.Attributes, "fsmoroleowner")
						} else {
							o.Attributes["fsmoroleowner"] = [][]byte{
								[]byte("CN=Other," + InternalMoveTestConfig),
							}
						}
						s.InternalObjects[key] = o
					}
				}
			case "hidden-forest":
				delete(f.InternalDst.InternalObjects, InternalMoveTestConfig)
			case "other-forest":
				o := f.InternalDst.InternalObjects[InternalMoveTestConfig]
				o.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
				f.InternalDst.InternalObjects[InternalMoveTestConfig] = o
			case "other-root":
				f.InternalDst.InternalRoot["rootdomainnamingcontext"] = [][]byte{[]byte("DC=other")}
			case "wrong-host":
				f.InternalDst.InternalRoot["dnshostname"] = [][]byte{[]byte("alias.example")}
			case "missing-control":
				f.InternalSrc.InternalRoot["supportedcontrol"] = nil
			case "source-GC":
				(*adengine.InternalClientConfigPointer(f.InternalSource)).Endpoint.Port = 3268
			case "readonly-domain":
				o := f.InternalDst.InternalObjects["DC=child,DC=example"]
				o.Attributes["instancetype"] = [][]byte{[]byte("1")}
				f.InternalDst.InternalObjects[o.DistinguishedName] = o
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
				sid, _ := admodel.ParseSID("S-1-5-21-1-2-3-500")
				object.Attributes["objectsid"] = [][]byte{sid.Bytes()}
			case "builtin-group":
				object.Attributes["objectclass"] = [][]byte{[]byte("group")}
				object.Attributes["grouptype"] = [][]byte{[]byte("-2147483643")}
			case "ranged-class":
				delete(object.Attributes, "objectclass")
				object.Attributes["objectclass;range=0-0"] = [][]byte{[]byte("user")}
			case "wrong-parent-GUID":
				f.InternalRequest.TargetParent = admodel.InternalObjectGUIDIdentity(
					InternalObjectTestGUID(),
				)
				f.InternalDst.InternalSearch = func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					return InternalObjectTestCursor(
						f.InternalDst.InternalObjects["OU=目标,DC=child,DC=example"],
					), nil
				}
			case "same-domain":
				f.InternalRequest.Destination = f.InternalSource
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
				f.InternalAttempt = admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: code, Diagnostic: "native detail"},
				}
			case "uncertain":
				wantWrite = true
				f.InternalAttempt = admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteUncertain,
					Err:   context.DeadlineExceeded,
				}
			case "readback-missing":
				wantWrite = true
				f.InternalReadback = func(o admodel.Object) admodel.Object {
					f.InternalDst.InternalSearch = func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						return InternalObjectTestCursor(), nil
					}
					return o
				}
			case "readback-GUID":
				wantWrite = true
				f.InternalReadback = func(o admodel.Object) admodel.Object {
					o.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
					return o
				}
			case "readback-moved":
				wantWrite = true
				f.InternalReadback = func(o admodel.Object) admodel.Object {
					o.DistinguishedName = "CN=Elsewhere,DC=child,DC=example"
					return o
				}
			case "readback-deleted":
				wantWrite = true
				f.InternalReadback = func(o admodel.Object) admodel.Object { o.Attributes["isdeleted"] = [][]byte{[]byte("TRUE")}; return o }
			}
			f.InternalSrc.InternalObjects[InternalMoveTestSourceDN] = object
			result, err := f.InternalSource.MoveObject(context.Background(), f.InternalRequest)
			if err == nil || result.Mutation.Verified ||
				len(f.InternalWrites) != map[bool]int{true: 1, false: 0}[wantWrite] {
				t.Fatalf("%+v err=%v writes=%d", result, err, len(f.InternalWrites))
			}
			if wantWrite && !result.Mutation.PartialEffectsPossible {
				t.Fatal("cross-domain partial effects lost")
			}
			if mode == "uncertain" &&
				(result.Mutation.State != admodel.ObjectWriteUncertain || !errors.Is(err, admodel.ErrObjectWriteUncertain)) {
				t.Fatal(result, err)
			}
			if strings.HasPrefix(mode, "readback-") &&
				result.Mutation.State != admodel.ObjectWriteAccepted {
				t.Fatal(result, err)
			}
		})
	}
}

func TestMoveObjectScopeAndValidation(t *testing.T) {
	for _, mode := range []string{"nil", "bad-target", "unexpected-partition", "cross-partition", "descendant", "NC-root", "parent-missing", "unsupported-version", "cancel", "gate-timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewMoveTestFixture(t, false, false)
			ctx := context.Background()
			switch mode {
			case "nil":
				f.InternalSource = nil
			case "bad-target":
				f.InternalRequest.TargetParent = admodel.Identity{}
			case "unexpected-partition":
				f.InternalRequest.DestinationPartition = "DC=example"
			case "cross-partition":
				f.InternalRequest.TargetParent = InternalMoveIdentity(
					"CN=Else," + InternalMoveTestConfig,
				)
			case "descendant":
				f.InternalRequest.TargetParent = InternalMoveIdentity(
					"OU=Inside," + InternalMoveTestSourceDN,
				)
				f.InternalSrc.InternalObjects[f.InternalRequest.TargetParent.String()] = InternalMoveTestObject(
					f.InternalRequest.TargetParent.String(),
					"organizationalUnit",
					8,
				)
			case "NC-root":
				f.InternalRequest.Identity = InternalMoveIdentity("DC=example")
			case "parent-missing":
				delete(f.InternalSrc.InternalObjects, f.InternalRequest.TargetParent.String())
			case "unsupported-version":
				f.InternalSrc.InternalRoot["supportedcontrol"] = nil
				guid, _ := admodel.GUIDFromBytes(
					f.InternalSrc.InternalObjects[InternalMoveTestSourceDN].Attributes["objectguid"][0],
				)
				f.InternalRequest.Options.ExpectedVersion = &admodel.ObjectVersion{
					Source:     (*adengine.InternalClientConfigPointer(f.InternalSource)).Endpoint,
					GUID:       guid,
					USNChanged: 7,
				}
			case "cancel":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "gate-timeout":
				(*adengine.InternalClientConfigPointer(f.InternalSource)).Timeout = 5 * time.Millisecond
				<-adengine.InternalClientGate(f.InternalSource)
				defer func() { adengine.InternalClientGate(f.InternalSource) <- struct{}{} }()
			}
			result, err := f.InternalSource.MoveObject(ctx, f.InternalRequest)
			if err == nil || len(f.InternalWrites) != 0 ||
				result.Mutation.State != admodel.ObjectWriteNotAttempted {
				t.Fatal(result, err)
			}
		})
	}
}

func TestMoveOptionsDoNotAliasCallerProperties(t *testing.T) {
	f := InternalNewMoveTestFixture(t, false, false)
	properties := make([]string, 1, 32)
	properties[0] = "description"
	f.InternalRequest.Options.Properties = properties
	if _, err := f.InternalSource.MoveObject(context.Background(), f.InternalRequest); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(properties, []string{"description"}) {
		t.Fatal(properties)
	}
}

func TestMoveObjectPartialObservationsPreventDispatch(t *testing.T) {
	for _, destination := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "source", true: "destination"}[destination],
			func(t *testing.T) {
				f := InternalNewMoveTestFixture(t, true, false)
				s := f.InternalSrc
				object := f.InternalSrc.InternalObjects[InternalMoveTestSourceDN]
				if destination {
					s = f.InternalDst
					object = f.InternalDst.InternalObjects[f.InternalRequest.TargetParent.String()]
				}
				s.InternalSearch = func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					return InternalTestSearchCursor{
						InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
							return []admodel.Object{object}, true, &admodel.LDAPError{Code: 50}
						},
						InternalFinish: func() error { return nil },
					}, nil
				}
				result, err := f.InternalSource.MoveObject(context.Background(), f.InternalRequest)
				if !errors.Is(err, admodel.ErrObjectWritePermission) || len(f.InternalWrites) != 0 {
					t.Fatal(err, f.InternalWrites)
				}
				if destination {
					if len(result.Parent.Candidates) != 1 || result.Parent.Complete {
						t.Fatal(result.Parent)
					}
				} else if len(result.Mutation.PreflightCandidates) != 1 {
					t.Fatal(result.Mutation.PreflightCandidates)
				}
			},
		)
	}
}

func TestMoveObjectExplicitParentGUID(t *testing.T) {
	f := InternalNewMoveTestFixture(t, true, false)
	parent := f.InternalDst.InternalObjects[f.InternalRequest.TargetParent.String()]
	guid, _ := admodel.GUIDFromBytes(parent.Attributes["objectguid"][0])
	f.InternalRequest.TargetParent = admodel.InternalObjectGUIDIdentity(guid)
	f.InternalRequest.DestinationPartition = "DC=child,DC=example"
	result, err := f.InternalSource.MoveObject(context.Background(), f.InternalRequest)
	if err != nil || !result.Mutation.Verified ||
		result.Parent.Object.DistinguishedName != parent.DistinguishedName {
		t.Fatal(err)
	}
}

func TestMoveObjectLocalRestrictions(t *testing.T) {
	for _, mode := range []string{"RODC", "secret", "trustedDomain", "domain-move-flag", "schema-class"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewMoveTestFixture(t, false, false)
			o := f.InternalSrc.InternalObjects[InternalMoveTestSourceDN]
			switch mode {
			case "RODC":
				f.InternalSrc.InternalRoot["supportedcapabilities"] = append(
					f.InternalSrc.InternalRoot["supportedcapabilities"],
					[]byte("1.2.840.113556.1.4.1920"),
				)
			case "secret", "trustedDomain":
				o.Attributes["objectclass"] = [][]byte{[]byte(mode)}
			case "domain-move-flag":
				o.Attributes["systemflags"] = [][]byte{[]byte("67108864")}
			case "schema-class":
				o.Attributes["objectclass"] = [][]byte{[]byte("classSchema")}
			}
			f.InternalSrc.InternalObjects[InternalMoveTestSourceDN] = o
			result, err := f.InternalSource.MoveObject(context.Background(), f.InternalRequest)
			if err == nil || result.Mutation.State != admodel.ObjectWriteNotAttempted ||
				len(f.InternalWrites) != 0 {
				t.Fatal(result.Mutation.State, err)
			}
		})
	}
}

func TestMoveObjectClientLifetimeAndDestinationBounds(t *testing.T) {
	for _, mode := range []string{"source-closed", "destination-closed", "destination-empty", "destination-timeout", "destination-canceled", "source-timeout", "destination-closed-after-acceptance", "local-verification"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewMoveTestFixture(t, mode != "local-verification", false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "source-closed":
				_ = f.InternalSource.Close()
			case "destination-closed":
				_ = f.InternalDestination.Close()
			case "destination-empty":
				f.InternalRequest.Destination = &adengine.Client{}
			case "destination-timeout", "destination-canceled":
				(*adengine.InternalClientConfigPointer(f.InternalDestination)).Timeout = 5 * time.Millisecond
				f.InternalDst.InternalSearch = func(ctx context.Context, _ admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if mode == "destination-canceled" {
						cancel()
					}
					<-ctx.Done()
					return nil, context.Cause(ctx)
				}
			case "source-timeout":
				(*adengine.InternalClientConfigPointer(f.InternalSource)).Timeout = 5 * time.Millisecond
				f.InternalSrc.InternalSearch = func(ctx context.Context, _ admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					<-ctx.Done()
					return nil, context.Cause(ctx)
				}
			case "destination-closed-after-acceptance":
				f.InternalReadback = func(o admodel.Object) admodel.Object { _ = f.InternalDestination.Close(); return o }
			case "local-verification":
				f.InternalReadback = func(o admodel.Object) admodel.Object { o.DistinguishedName = "CN=Elsewhere,DC=example"; return o }
			}
			result, err := f.InternalSource.MoveObject(ctx, f.InternalRequest)
			if err == nil || result.Mutation.Verified {
				t.Fatal(result.Mutation.State, err)
			}
			if mode == "destination-closed-after-acceptance" || mode == "local-verification" {
				if result.Mutation.State != admodel.ObjectWriteAccepted ||
					!errors.Is(err, admodel.ErrObjectReadback) ||
					len(f.InternalWrites) != 1 {
					t.Fatal(result.Mutation.State, err)
				}
			} else if result.Mutation.State != admodel.ObjectWriteNotAttempted || len(f.InternalWrites) != 0 {
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
	f := InternalNewMoveTestFixture(t, true, false)
	parentA := "OU=Return,DC=example"
	f.InternalSrc.InternalObjects[parentA] = InternalMoveTestObject(
		parentA,
		"organizationalUnit",
		8,
	)
	objectB := "CN=Second,DC=child,DC=example"
	f.InternalDst.InternalObjects[objectB] = InternalMoveTestObject(objectB, "user", 11)
	reverse := adengine.MoveObjectRequest{
		Identity:     InternalMoveIdentity(objectB),
		TargetParent: InternalMoveIdentity(parentA),
		Destination:  f.InternalSource,
	}
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	for _, target := range []struct {
		InternalS      *InternalMoveTestSession
		InternalParent string
	}{{f.InternalSrc, parentA}, {f.InternalDst, f.InternalRequest.TargetParent.String()}} {
		plain := *target.InternalS
		target.InternalS.InternalSearch = func(ctx context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			if options.Scope == admodel.ScopeBase && options.Base == target.InternalParent {
				arrived <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			}
			return plain.InternalStartSearch(ctx, options)
		}
	}
	writes := make(chan struct{}, 2)
	write := func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
		writes <- struct{}{}
		return admodel.InternalLdapWriteAttempt{
			State: admodel.InternalLdapWriteRejected,
			Err:   &admodel.LDAPError{Code: 50},
		}
	}
	f.InternalSrc.InternalWrite, f.InternalDst.InternalWrite = write, write
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() { _, err := f.InternalSource.MoveObject(ctx, f.InternalRequest); results <- err }()
	go func() { _, err := f.InternalDestination.MoveObject(ctx, reverse); results <- err }()
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
			if !errors.Is(err, admodel.ErrObjectWritePermission) {
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
			f := InternalNewMoveTestFixture(t, true, false)
			o := f.InternalSrc.InternalObjects[InternalMoveTestSourceDN]
			sid, err := admodel.ParseSID("S-1-5-21-1-2-3-" + rid)
			if err != nil {
				t.Fatal(err)
			}
			o.Attributes["objectsid"] = [][]byte{sid.Bytes()}
			f.InternalSrc.InternalObjects[InternalMoveTestSourceDN] = o
			result, err := f.InternalSource.MoveObject(context.Background(), f.InternalRequest)
			if rid == "1000" {
				if !errors.Is(err, admodel.ErrObjectMoveForbidden) || len(f.InternalWrites) != 0 {
					t.Fatal(err)
				}
			} else if err != nil || !result.Mutation.Verified || len(f.InternalWrites) != 1 {
				t.Fatal(err)
			}
		})
	}
}
