package acceptance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_operation_master "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/operation_master"
)

type InternalOperationMasterTestSession struct {
	InternalTestSession
	InternalModify func(context.Context, string, []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt
}

func (s InternalOperationMasterTestSession) InternalOperationMasterModify(
	ctx context.Context,
	dn string,
	mods []admodel.InternalOperationMasterModification,
) admodel.OperationMasterAttempt {
	return s.InternalModify(ctx, dn, mods)
}

const (
	InternalOperationTestDomain = "DC=example,DC=test"
	InternalOperationTestConfig = "CN=Configuration," + InternalOperationTestDomain
	InternalOperationTestSchema = "CN=Schema," + InternalOperationTestConfig
	InternalOperationTestTarget = "CN=NTDS Settings,CN=NEW,CN=Servers,CN=Site,CN=Sites," + InternalOperationTestConfig
	InternalOperationTestOld    = "CN=NTDS Settings,CN=OLD,CN=Servers,CN=Site,CN=Sites," + InternalOperationTestConfig
	InternalOperationTestRID    = "CN=RID Manager$,CN=System," + InternalOperationTestDomain
)

func InternalOperationMasterFixture() (map[string]map[string][][]byte, map[admodel.OperationMasterRole]string, []byte) {
	objects := make(map[string]map[string][][]byte)
	root := map[string][][]byte{
		"supportedcapabilities":      {[]byte(admodel.CapabilityActiveDirectory)},
		"dsservicename":              {[]byte(InternalOperationTestTarget)},
		"issynchronized":             {[]byte("TRUE")},
		"defaultnamingcontext":       {[]byte(InternalOperationTestDomain)},
		"configurationnamingcontext": {[]byte(InternalOperationTestConfig)},
		"schemanamingcontext":        {[]byte(InternalOperationTestSchema)},
	}
	objects[""] = root
	objects[InternalOperationTestTarget] = map[string][][]byte{
		"distinguishedname": {
			[]byte(InternalOperationTestTarget),
		},
		"objectclass": {[]byte("nTDSDSA")},
		"msds-isrodc": {[]byte("FALSE")},
	}
	locations := map[admodel.OperationMasterRole]string{
		admodel.OperationMasterPDCEmulator:          InternalOperationTestDomain,
		admodel.OperationMasterRIDMaster:            InternalOperationTestRID,
		admodel.OperationMasterInfrastructureMaster: "CN=Infrastructure," + InternalOperationTestDomain,
		admodel.OperationMasterSchemaMaster:         InternalOperationTestSchema,
		admodel.OperationMasterDomainNamingMaster:   "CN=Partitions," + InternalOperationTestConfig,
	}
	for role, dn := range locations {
		objects[dn] = map[string][][]byte{
			"distinguishedname": {
				[]byte(dn),
			},
			"objectclass": {
				[]byte(admodel.InternalOperationMasterDefinitions[role].InternalClass),
			},
			"fsmoroleowner": {[]byte(InternalOperationTestOld)},
		}
	}
	sid := make([]byte, 24)
	sid[0], sid[1], sid[7] = 1, 4, 5
	for i, value := range []uint32{21, 111, 222, 333} {
		binary.LittleEndian.PutUint32(sid[8+4*i:], value)
	}
	objects[InternalOperationTestDomain]["objectsid"] = [][]byte{sid}
	objects[InternalOperationTestDomain]["ridmanagerreference"] = [][]byte{
		[]byte(InternalOperationTestRID),
	}
	objects[InternalOperationTestRID]["ridavailablepool"] = [][]byte{[]byte("4611686014132422708")}
	return objects, locations, sid
}

func InternalOperationMasterFixtureClient(
	objects map[string]map[string][][]byte,
	modify func(context.Context, string, []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt,
) *adengine.Client {
	return adengine.InternalNewClient(
		admodel.Config{Timeout: time.Second},
		InternalOperationMasterTestSession{
			InternalTestSession: InternalTestSession{
				InternalBase: func(ctx context.Context, dn string, _ []string) (map[string][][]byte, error) {
					if err := context.Cause(ctx); err != nil {
						return nil, err
					}
					if attrs, ok := objects[dn]; ok {
						return attrs, nil
					}
					return nil, &admodel.LDAPError{Code: 32, Operation: "test read"}
				},
				InternalFinish: func() error { return nil },
			},
			InternalModify: modify,
		},
	)
}

func TestOperationMasterTransfersAndReadback(t *testing.T) {
	objects, locations, sid := InternalOperationMasterFixture()
	roles := []admodel.OperationMasterRole{
		admodel.OperationMasterPDCEmulator,
		admodel.OperationMasterRIDMaster,
		admodel.OperationMasterInfrastructureMaster,
		admodel.OperationMasterSchemaMaster,
		admodel.OperationMasterDomainNamingMaster,
	}
	attributes := []string{
		"becomePdc",
		"becomeRidMaster",
		"becomeInfrastructureMaster",
		"becomeSchemaMaster",
		"becomeDomainMaster",
	}
	calls := 0
	client := InternalOperationMasterFixtureClient(
		objects,
		func(_ context.Context, dn string, mods []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt {
			i := calls
			calls++
			if dn != "" || len(mods) != 1 || mods[0].InternalOperation != 0 ||
				mods[0].InternalAttribute != attributes[i] {
				t.Fatalf("transfer %d: dn=%q mods=%+v", i, dn, mods)
			}
			want := []byte("1")
			if i == 0 {
				want = sid
			}
			if !bytes.Equal(mods[0].InternalValue, want) {
				t.Fatalf("%s payload %x, want %x", roles[i], mods[0].InternalValue, want)
			}
			objects[locations[roles[i]]]["fsmoroleowner"] = [][]byte{
				[]byte(InternalOperationTestTarget),
			}
			return admodel.OperationMasterAttempt{State: admodel.OperationMasterWriteAccepted}
		},
	)
	// Explicit Partition must not redirect the domain roles.
	(*adengine.InternalClientConfigPointer(client)).Partition = "DC=unrelated,DC=test"
	result, err := adservice_operation_master.New(client).
		MoveOperationMasterRoles(context.Background(), admodel.MoveOperationMasterRolesRequest{Roles: roles, Force: true})
	if err != nil || calls != 5 || result.TargetDSA != InternalOperationTestTarget {
		t.Fatalf("result=%+v, calls=%d, err=%v", result, calls, err)
	}
	for _, outcome := range result.Outcomes {
		if outcome.Status != admodel.OperationMasterTransferred || !outcome.Verified ||
			outcome.RoleObjectDN != locations[outcome.Role] ||
			outcome.Seizure.State != admodel.OperationMasterWriteNotAttempted ||
			outcome.Err != nil {
			t.Fatalf("outcome=%+v", outcome)
		}
	}
}

func TestOperationMasterSeizesExactRoleObjectsAfterTransfer(t *testing.T) {
	for _, role := range []admodel.OperationMasterRole{admodel.OperationMasterPDCEmulator, admodel.OperationMasterRIDMaster, admodel.OperationMasterInfrastructureMaster, admodel.OperationMasterSchemaMaster, admodel.OperationMasterDomainNamingMaster} {
		t.Run(string(role), func(t *testing.T) {
			objects, locations, _ := InternalOperationMasterFixture()
			calls := 0
			transferErr := &admodel.LDAPError{Code: 52, Diagnostic: "000020AF: holder unavailable"}
			client := InternalOperationMasterFixtureClient(
				objects,
				func(_ context.Context, dn string, mods []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt {
					calls++
					if calls == 1 {
						if dn != "" ||
							mods[0].InternalAttribute != admodel.InternalOperationMasterDefinitions[role].InternalAttribute {
							t.Fatal("did not attempt transfer first")
						}
						return admodel.OperationMasterAttempt{
							State: admodel.OperationMasterWriteRejected,
							Err:   transferErr,
						}
					}
					if calls != 2 || dn != locations[role] {
						t.Fatalf("wrong seizure destination or replay: %q, %d", dn, calls)
					}
					want := []admodel.InternalOperationMasterModification{
						{
							InternalOperation: 1,
							InternalAttribute: "fSMORoleOwner",
							InternalValue:     []byte(InternalOperationTestOld),
						},
						{
							InternalOperation: 0,
							InternalAttribute: "fSMORoleOwner",
							InternalValue:     []byte(InternalOperationTestTarget),
						},
					}
					if role == admodel.OperationMasterRIDMaster {
						want = append(
							want,
							admodel.InternalOperationMasterModification{
								InternalOperation: 1,
								InternalAttribute: "rIDAvailablePool",
								InternalValue:     []byte("4611686014132422708"),
							},
							admodel.InternalOperationMasterModification{
								InternalOperation: 0,
								InternalAttribute: "rIDAvailablePool",
								InternalValue:     []byte("4611686014132452708"),
							},
						)
						objects[dn]["ridavailablepool"] = [][]byte{[]byte("4611686014132452708")}
					}
					if !reflect.DeepEqual(mods, want) {
						t.Fatalf("mods=%+v, want=%+v", mods, want)
					}
					objects[dn]["fsmoroleowner"] = [][]byte{[]byte(InternalOperationTestTarget)}
					return admodel.OperationMasterAttempt{
						State: admodel.OperationMasterWriteAccepted,
					}
				},
			)
			result, err := adservice_operation_master.New(client).
				MoveOperationMasterRoles(context.Background(), admodel.MoveOperationMasterRolesRequest{Roles: []admodel.OperationMasterRole{role}, Force: true})
			outcome := result.Outcomes[0]
			if err != nil || calls != 2 || outcome.Status != admodel.OperationMasterSeized ||
				!outcome.Verified ||
				!errors.Is(outcome.Transfer.Err, transferErr) {
				t.Fatalf("outcome=%+v calls=%d err=%v", outcome, calls, err)
			}
			if role == admodel.OperationMasterRIDMaster &&
				(outcome.RequestedRIDPool == nil || outcome.ObservedRIDPool == nil || *outcome.ObservedRIDPool-*outcome.PreviousRIDPool != 30000) {
				t.Fatal("RID burn was not observed")
			}
		})
	}
}

func TestOperationMasterStopsWithoutReplay(t *testing.T) {
	for _, test := range []struct {
		InternalName  string
		InternalState admodel.OperationMasterWriteState
		InternalErr   error
		InternalForce bool
		InternalWant  error
	}{
		{"permission", admodel.OperationMasterWriteRejected, &admodel.LDAPError{Code: 50, Diagnostic: "sensitive"}, true, admodel.ErrOperationMasterPermission},
		{"no-force", admodel.OperationMasterWriteRejected, &admodel.LDAPError{Code: 52}, false, nil},
		{"unsupported", admodel.OperationMasterWriteNotAttempted, admodel.ErrUnsupported, true, admodel.ErrUnsupported},
		{"unknown", admodel.OperationMasterWriteUncertain, context.DeadlineExceeded, true, admodel.ErrOperationMasterUncertain},
		{"cleanup", admodel.OperationMasterWriteRejected, errors.Join(&admodel.LDAPError{Code: 52}, admodel.ErrInvalidResult), true, admodel.ErrInvalidResult},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			objects, _, _ := InternalOperationMasterFixture()
			calls := 0
			client := InternalOperationMasterFixtureClient(
				objects,
				func(context.Context, string, []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt {
					calls++
					return admodel.OperationMasterAttempt{
						State: test.InternalState,
						Err:   test.InternalErr,
					}
				},
			)
			result, err := adservice_operation_master.New(client).
				MoveOperationMasterRoles(context.Background(), admodel.MoveOperationMasterRolesRequest{Roles: []admodel.OperationMasterRole{admodel.OperationMasterSchemaMaster, admodel.OperationMasterPDCEmulator}, Force: test.InternalForce})
			if err == nil || calls != 1 ||
				result.Outcomes[1].Status != admodel.OperationMasterNotAttempted ||
				(test.InternalWant != nil && !errors.Is(err, test.InternalWant)) {
				t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
			}
		})
	}
}

func TestOperationMasterPreflightRejectsBeforeAnyWrite(t *testing.T) {
	for _, test := range []string{"unknown", "rodc", "missing-rodc", "not-ready", "wrong-role-class", "wrong-dn", "missing-owner", "invalid-sid", "text-sid", "missing-rid-reference", "lds-domain-role"} {
		t.Run(test, func(t *testing.T) {
			objects, _, _ := InternalOperationMasterFixture()
			switch test {
			case "unknown":
				delete(objects[""], "supportedcapabilities")
			case "rodc":
				objects[InternalOperationTestTarget]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "missing-rodc":
				delete(objects[InternalOperationTestTarget], "msds-isrodc")
			case "not-ready":
				objects[""]["issynchronized"] = [][]byte{[]byte("FALSE")}
			case "wrong-role-class":
				objects[InternalOperationTestRID]["objectclass"] = [][]byte{[]byte("container")}
			case "wrong-dn":
				objects[InternalOperationTestSchema]["distinguishedname"] = [][]byte{
					[]byte(InternalOperationTestConfig),
				}
			case "missing-owner":
				delete(objects[InternalOperationTestDomain], "fsmoroleowner")
			case "invalid-sid":
				objects[InternalOperationTestDomain]["objectsid"][0][1] = 5
			case "text-sid":
				objects[InternalOperationTestDomain]["objectsid"] = [][]byte{
					[]byte("S-1-5-21-1-2-3"),
				}
			case "missing-rid-reference":
				delete(objects[InternalOperationTestDomain], "ridmanagerreference")
			case "lds-domain-role":
				objects[""]["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
			}
			client := InternalOperationMasterFixtureClient(
				objects,
				func(context.Context, string, []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt {
					t.Fatal("preflight failure reached native write")
					return admodel.OperationMasterAttempt{}
				},
			)
			_, err := adservice_operation_master.New(client).
				MoveOperationMasterRoles(context.Background(), admodel.MoveOperationMasterRolesRequest{Roles: []admodel.OperationMasterRole{admodel.OperationMasterSchemaMaster, admodel.OperationMasterRIDMaster, admodel.OperationMasterPDCEmulator}, Force: true})
			if err == nil {
				t.Fatal("accepted invalid server state")
			}
		})
	}
}

func TestOperationMasterLDSForestRolesAndGUIDDSA(t *testing.T) {
	objects, locations, _ := InternalOperationMasterFixture()
	objects[""]["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
	objects[""]["dsservicename"] = [][]byte{[]byte("<GUID=12345678-1234-1234-1234-123456789012>")}
	objects["<GUID=12345678-1234-1234-1234-123456789012>"] = objects[InternalOperationTestTarget]
	delete(objects[InternalOperationTestTarget], "msds-isrodc")
	delete(objects[""], "defaultnamingcontext")
	client := InternalOperationMasterFixtureClient(
		objects,
		func(_ context.Context, _ string, mods []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt {
			for role, definition := range admodel.InternalOperationMasterDefinitions {
				if definition.InternalAttribute == mods[0].InternalAttribute {
					objects[locations[role]]["fsmoroleowner"] = [][]byte{
						[]byte(InternalOperationTestTarget),
					}
				}
			}
			return admodel.OperationMasterAttempt{State: admodel.OperationMasterWriteAccepted}
		},
	)
	_, err := adservice_operation_master.New(client).
		MoveOperationMasterRoles(context.Background(), admodel.MoveOperationMasterRolesRequest{Roles: []admodel.OperationMasterRole{admodel.OperationMasterSchemaMaster, admodel.OperationMasterDomainNamingMaster}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOperationMasterRIDPoolBoundsAndConcurrentChange(t *testing.T) {
	for _, test := range []string{"exhausted", "overflow", "changed-owner", "readback-denied", "pool-not-advanced", "already-owned"} {
		t.Run(test, func(t *testing.T) {
			objects, _, _ := InternalOperationMasterFixture()
			if test == "exhausted" {
				objects[InternalOperationTestRID]["ridavailablepool"] = [][]byte{
					[]byte(strconv.FormatUint((uint64(0x3fffffff)<<32)|0x3ffff000, 10)),
				}
			}
			if test == "overflow" {
				objects[InternalOperationTestRID]["ridavailablepool"] = [][]byte{
					[]byte("18446744073709551615"),
				}
			}
			if test == "already-owned" {
				objects[InternalOperationTestRID]["fsmoroleowner"] = [][]byte{
					[]byte(InternalOperationTestTarget),
				}
			}
			calls := 0
			client := InternalOperationMasterFixtureClient(
				objects,
				func(_ context.Context, dn string, _ []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt {
					calls++
					if dn != "" {
						if test != "pool-not-advanced" {
							t.Fatal("unexpected seizure")
						}
						objects[InternalOperationTestRID]["fsmoroleowner"] = [][]byte{
							[]byte(InternalOperationTestTarget),
						}
						return admodel.OperationMasterAttempt{
							State: admodel.OperationMasterWriteAccepted,
						}
					}
					if test == "changed-owner" {
						objects[InternalOperationTestRID]["fsmoroleowner"] = [][]byte{
							[]byte(strings.Replace(InternalOperationTestOld, "OLD", "THIRD", 1)),
						}
					}
					if test == "readback-denied" {
						delete(objects, InternalOperationTestRID)
					}
					return admodel.OperationMasterAttempt{
						State: admodel.OperationMasterWriteRejected,
						Err:   &admodel.LDAPError{Code: 52},
					}
				},
			)
			result, err := adservice_operation_master.New(client).
				MoveOperationMasterRoles(context.Background(), admodel.MoveOperationMasterRolesRequest{Roles: []admodel.OperationMasterRole{admodel.OperationMasterRIDMaster}, Force: true})
			if test == "already-owned" {
				if err != nil || calls != 0 ||
					result.Outcomes[0].Status != admodel.OperationMasterAlreadyOwned {
					t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
				}
			} else if err == nil || result.Outcomes[0].Verified {
				t.Fatalf("unverified failure accepted: %+v, %v", result, err)
			}
			if test == "changed-owner" && !errors.Is(err, admodel.ErrOperationMasterChanged) {
				t.Fatal(err)
			}
			if test == "pool-not-advanced" &&
				(!errors.Is(err, admodel.ErrOperationMasterReadback) || result.Outcomes[0].Status != admodel.OperationMasterSeized) {
				t.Fatal(err)
			}
		})
	}
}

func TestOperationMasterPartialCompletionAndValidation(t *testing.T) {
	for _, roles := range [][]admodel.OperationMasterRole{nil, {admodel.OperationMasterSchemaMaster, admodel.OperationMasterSchemaMaster}, {"invalid"}} {
		if err := (admodel.MoveOperationMasterRolesRequest{Roles: roles}).Validate(); !errors.Is(
			err,
			admodel.ErrInvalidOperationMasterRequest,
		) {
			t.Fatal(err)
		}
	}
	objects, _, _ := InternalOperationMasterFixture()
	calls := 0
	client := InternalOperationMasterFixtureClient(
		objects,
		func(context.Context, string, []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt {
			calls++
			if calls == 1 {
				objects[InternalOperationTestSchema]["fsmoroleowner"] = [][]byte{
					[]byte(InternalOperationTestTarget),
				}
				return admodel.OperationMasterAttempt{State: admodel.OperationMasterWriteAccepted}
			}
			return admodel.OperationMasterAttempt{
				State: admodel.OperationMasterWriteUncertain,
				Err:   context.DeadlineExceeded,
			}
		},
	)
	result, err := adservice_operation_master.New(client).
		MoveOperationMasterRoles(context.Background(), admodel.MoveOperationMasterRolesRequest{Roles: []admodel.OperationMasterRole{admodel.OperationMasterSchemaMaster, admodel.OperationMasterPDCEmulator, admodel.OperationMasterRIDMaster}, Force: true})
	got := []admodel.OperationMasterStatus{
		result.Outcomes[0].Status,
		result.Outcomes[1].Status,
		result.Outcomes[2].Status,
	}
	if !errors.Is(err, admodel.ErrOperationMasterUncertain) || calls != 2 ||
		!slices.Equal(
			got,
			[]admodel.OperationMasterStatus{
				admodel.OperationMasterTransferred,
				admodel.OperationMasterUncertain,
				admodel.OperationMasterNotAttempted,
			},
		) {
		t.Fatalf("statuses=%v calls=%d err=%v", got, calls, err)
	}
}

func TestOperationMasterCloseWaitsForSubmittedWrite(t *testing.T) {
	objects, _, _ := InternalOperationMasterFixture()
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	client := InternalOperationMasterFixtureClient(
		objects,
		func(ctx context.Context, _ string, _ []admodel.InternalOperationMasterModification) admodel.OperationMasterAttempt {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return admodel.OperationMasterAttempt{
				State: admodel.OperationMasterWriteUncertain,
				Err:   context.Cause(ctx),
			}
		},
	)
	session := adengine.InternalClientSession(client).(InternalOperationMasterTestSession)
	unbound := make(chan struct{})
	session.InternalFinish = func() error { close(unbound); return nil }
	(*adengine.InternalClientSessionPointer(client)) = session
	completed := make(chan error, 1)
	go func() {
		_, err := adservice_operation_master.New(client).
			MoveOperationMasterRoles(context.Background(), admodel.MoveOperationMasterRolesRequest{Roles: []admodel.OperationMasterRole{admodel.OperationMasterSchemaMaster}, Force: true})
		completed <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("write did not begin")
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the operation")
	}
	select {
	case <-unbound:
		t.Fatal("unbound with a native write still using the session")
	default:
	}
	close(release)
	if err := <-completed; !errors.Is(err, admodel.ErrOperationMasterUncertain) ||
		!errors.Is(err, admodel.ErrClosed) {
		t.Fatalf("lost uncertain/canceled write: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}
