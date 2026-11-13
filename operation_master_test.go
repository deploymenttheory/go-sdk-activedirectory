package activedirectory

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
)

type operationMasterTestSession struct {
	testSession
	modify func(context.Context, string, []operationMasterModification) OperationMasterAttempt
}

func (s operationMasterTestSession) operationMasterModify(ctx context.Context, dn string, mods []operationMasterModification) OperationMasterAttempt {
	return s.modify(ctx, dn, mods)
}

const (
	operationTestDomain = "DC=example,DC=test"
	operationTestConfig = "CN=Configuration," + operationTestDomain
	operationTestSchema = "CN=Schema," + operationTestConfig
	operationTestTarget = "CN=NTDS Settings,CN=NEW,CN=Servers,CN=Site,CN=Sites," + operationTestConfig
	operationTestOld    = "CN=NTDS Settings,CN=OLD,CN=Servers,CN=Site,CN=Sites," + operationTestConfig
	operationTestRID    = "CN=RID Manager$,CN=System," + operationTestDomain
)

func operationMasterFixture() (map[string]map[string][][]byte, map[OperationMasterRole]string, []byte) {
	objects := make(map[string]map[string][][]byte)
	root := map[string][][]byte{
		"supportedcapabilities":      {[]byte(CapabilityActiveDirectory)},
		"dsservicename":              {[]byte(operationTestTarget)},
		"issynchronized":             {[]byte("TRUE")},
		"defaultnamingcontext":       {[]byte(operationTestDomain)},
		"configurationnamingcontext": {[]byte(operationTestConfig)},
		"schemanamingcontext":        {[]byte(operationTestSchema)},
	}
	objects[""] = root
	objects[operationTestTarget] = map[string][][]byte{
		"distinguishedname": {[]byte(operationTestTarget)}, "objectclass": {[]byte("nTDSDSA")}, "msds-isrodc": {[]byte("FALSE")},
	}
	locations := map[OperationMasterRole]string{
		OperationMasterPDCEmulator:          operationTestDomain,
		OperationMasterRIDMaster:            operationTestRID,
		OperationMasterInfrastructureMaster: "CN=Infrastructure," + operationTestDomain,
		OperationMasterSchemaMaster:         operationTestSchema,
		OperationMasterDomainNamingMaster:   "CN=Partitions," + operationTestConfig,
	}
	for role, dn := range locations {
		objects[dn] = map[string][][]byte{
			"distinguishedname": {[]byte(dn)}, "objectclass": {[]byte(operationMasterDefinitions[role].class)}, "fsmoroleowner": {[]byte(operationTestOld)},
		}
	}
	sid := make([]byte, 24)
	sid[0], sid[1], sid[7] = 1, 4, 5
	for i, value := range []uint32{21, 111, 222, 333} {
		binary.LittleEndian.PutUint32(sid[8+4*i:], value)
	}
	objects[operationTestDomain]["objectsid"] = [][]byte{sid}
	objects[operationTestDomain]["ridmanagerreference"] = [][]byte{[]byte(operationTestRID)}
	objects[operationTestRID]["ridavailablepool"] = [][]byte{[]byte("4611686014132422708")}
	return objects, locations, sid
}

func operationMasterFixtureClient(objects map[string]map[string][][]byte, modify func(context.Context, string, []operationMasterModification) OperationMasterAttempt) *Client {
	return newClient(Config{Timeout: time.Second}, operationMasterTestSession{
		testSession: testSession{
			base: func(ctx context.Context, dn string, _ []string) (map[string][][]byte, error) {
				if err := context.Cause(ctx); err != nil {
					return nil, err
				}
				if attrs, ok := objects[dn]; ok {
					return attrs, nil
				}
				return nil, &LDAPError{Code: 32, Operation: "test read"}
			},
			finish: func() error { return nil },
		},
		modify: modify,
	})
}

func TestOperationMasterTransfersAndReadback(t *testing.T) {
	objects, locations, sid := operationMasterFixture()
	roles := []OperationMasterRole{OperationMasterPDCEmulator, OperationMasterRIDMaster, OperationMasterInfrastructureMaster, OperationMasterSchemaMaster, OperationMasterDomainNamingMaster}
	attributes := []string{"becomePdc", "becomeRidMaster", "becomeInfrastructureMaster", "becomeSchemaMaster", "becomeDomainMaster"}
	calls := 0
	client := operationMasterFixtureClient(objects, func(_ context.Context, dn string, mods []operationMasterModification) OperationMasterAttempt {
		i := calls
		calls++
		if dn != "" || len(mods) != 1 || mods[0].operation != 0 || mods[0].attribute != attributes[i] {
			t.Fatalf("transfer %d: dn=%q mods=%+v", i, dn, mods)
		}
		want := []byte("1")
		if i == 0 {
			want = sid
		}
		if !bytes.Equal(mods[0].value, want) {
			t.Fatalf("%s payload %x, want %x", roles[i], mods[0].value, want)
		}
		objects[locations[roles[i]]]["fsmoroleowner"] = [][]byte{[]byte(operationTestTarget)}
		return OperationMasterAttempt{State: OperationMasterWriteAccepted}
	})
	// Explicit Partition must not redirect the domain roles.
	client.config.Partition = "DC=unrelated,DC=test"
	result, err := client.MoveOperationMasterRoles(context.Background(), MoveOperationMasterRolesRequest{Roles: roles, Force: true})
	if err != nil || calls != 5 || result.TargetDSA != operationTestTarget {
		t.Fatalf("result=%+v, calls=%d, err=%v", result, calls, err)
	}
	for _, outcome := range result.Outcomes {
		if outcome.Status != OperationMasterTransferred || !outcome.Verified || outcome.RoleObjectDN != locations[outcome.Role] || outcome.Seizure.State != OperationMasterWriteNotAttempted || outcome.Err != nil {
			t.Fatalf("outcome=%+v", outcome)
		}
	}
}

func TestOperationMasterSeizesExactRoleObjectsAfterTransfer(t *testing.T) {
	for _, role := range []OperationMasterRole{OperationMasterPDCEmulator, OperationMasterRIDMaster, OperationMasterInfrastructureMaster, OperationMasterSchemaMaster, OperationMasterDomainNamingMaster} {
		t.Run(string(role), func(t *testing.T) {
			objects, locations, _ := operationMasterFixture()
			calls := 0
			transferErr := &LDAPError{Code: 52, Diagnostic: "000020AF: holder unavailable"}
			client := operationMasterFixtureClient(objects, func(_ context.Context, dn string, mods []operationMasterModification) OperationMasterAttempt {
				calls++
				if calls == 1 {
					if dn != "" || mods[0].attribute != operationMasterDefinitions[role].attribute {
						t.Fatal("did not attempt transfer first")
					}
					return OperationMasterAttempt{State: OperationMasterWriteRejected, Err: transferErr}
				}
				if calls != 2 || dn != locations[role] {
					t.Fatalf("wrong seizure destination or replay: %q, %d", dn, calls)
				}
				want := []operationMasterModification{{1, "fSMORoleOwner", []byte(operationTestOld)}, {0, "fSMORoleOwner", []byte(operationTestTarget)}}
				if role == OperationMasterRIDMaster {
					want = append(want, operationMasterModification{1, "rIDAvailablePool", []byte("4611686014132422708")}, operationMasterModification{0, "rIDAvailablePool", []byte("4611686014132452708")})
					objects[dn]["ridavailablepool"] = [][]byte{[]byte("4611686014132452708")}
				}
				if !reflect.DeepEqual(mods, want) {
					t.Fatalf("mods=%+v, want=%+v", mods, want)
				}
				objects[dn]["fsmoroleowner"] = [][]byte{[]byte(operationTestTarget)}
				return OperationMasterAttempt{State: OperationMasterWriteAccepted}
			})
			result, err := client.MoveOperationMasterRoles(context.Background(), MoveOperationMasterRolesRequest{Roles: []OperationMasterRole{role}, Force: true})
			outcome := result.Outcomes[0]
			if err != nil || calls != 2 || outcome.Status != OperationMasterSeized || !outcome.Verified || !errors.Is(outcome.Transfer.Err, transferErr) {
				t.Fatalf("outcome=%+v calls=%d err=%v", outcome, calls, err)
			}
			if role == OperationMasterRIDMaster && (outcome.RequestedRIDPool == nil || outcome.ObservedRIDPool == nil || *outcome.ObservedRIDPool-*outcome.PreviousRIDPool != 30000) {
				t.Fatal("RID burn was not observed")
			}
		})
	}
}

func TestOperationMasterStopsWithoutReplay(t *testing.T) {
	for _, test := range []struct {
		name  string
		state OperationMasterWriteState
		err   error
		force bool
		want  error
	}{
		{"permission", OperationMasterWriteRejected, &LDAPError{Code: 50, Diagnostic: "sensitive"}, true, ErrOperationMasterPermission},
		{"no-force", OperationMasterWriteRejected, &LDAPError{Code: 52}, false, nil},
		{"unsupported", OperationMasterWriteNotAttempted, ErrUnsupported, true, ErrUnsupported},
		{"unknown", OperationMasterWriteUncertain, context.DeadlineExceeded, true, ErrOperationMasterUncertain},
		{"cleanup", OperationMasterWriteRejected, errors.Join(&LDAPError{Code: 52}, ErrInvalidResult), true, ErrInvalidResult},
	} {
		t.Run(test.name, func(t *testing.T) {
			objects, _, _ := operationMasterFixture()
			calls := 0
			client := operationMasterFixtureClient(objects, func(context.Context, string, []operationMasterModification) OperationMasterAttempt {
				calls++
				return OperationMasterAttempt{State: test.state, Err: test.err}
			})
			result, err := client.MoveOperationMasterRoles(context.Background(), MoveOperationMasterRolesRequest{Roles: []OperationMasterRole{OperationMasterSchemaMaster, OperationMasterPDCEmulator}, Force: test.force})
			if err == nil || calls != 1 || result.Outcomes[1].Status != OperationMasterNotAttempted || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
			}
		})
	}
}

func TestOperationMasterPreflightRejectsBeforeAnyWrite(t *testing.T) {
	for _, test := range []string{"unknown", "rodc", "missing-rodc", "not-ready", "wrong-role-class", "wrong-dn", "missing-owner", "invalid-sid", "text-sid", "missing-rid-reference", "lds-domain-role"} {
		t.Run(test, func(t *testing.T) {
			objects, _, _ := operationMasterFixture()
			switch test {
			case "unknown":
				delete(objects[""], "supportedcapabilities")
			case "rodc":
				objects[operationTestTarget]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "missing-rodc":
				delete(objects[operationTestTarget], "msds-isrodc")
			case "not-ready":
				objects[""]["issynchronized"] = [][]byte{[]byte("FALSE")}
			case "wrong-role-class":
				objects[operationTestRID]["objectclass"] = [][]byte{[]byte("container")}
			case "wrong-dn":
				objects[operationTestSchema]["distinguishedname"] = [][]byte{[]byte(operationTestConfig)}
			case "missing-owner":
				delete(objects[operationTestDomain], "fsmoroleowner")
			case "invalid-sid":
				objects[operationTestDomain]["objectsid"][0][1] = 5
			case "text-sid":
				objects[operationTestDomain]["objectsid"] = [][]byte{[]byte("S-1-5-21-1-2-3")}
			case "missing-rid-reference":
				delete(objects[operationTestDomain], "ridmanagerreference")
			case "lds-domain-role":
				objects[""]["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			}
			client := operationMasterFixtureClient(objects, func(context.Context, string, []operationMasterModification) OperationMasterAttempt {
				t.Fatal("preflight failure reached native write")
				return OperationMasterAttempt{}
			})
			_, err := client.MoveOperationMasterRoles(context.Background(), MoveOperationMasterRolesRequest{Roles: []OperationMasterRole{OperationMasterSchemaMaster, OperationMasterRIDMaster, OperationMasterPDCEmulator}, Force: true})
			if err == nil {
				t.Fatal("accepted invalid server state")
			}
		})
	}
}

func TestOperationMasterLDSForestRolesAndGUIDDSA(t *testing.T) {
	objects, locations, _ := operationMasterFixture()
	objects[""]["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
	objects[""]["dsservicename"] = [][]byte{[]byte("<GUID=12345678-1234-1234-1234-123456789012>")}
	objects["<GUID=12345678-1234-1234-1234-123456789012>"] = objects[operationTestTarget]
	delete(objects[operationTestTarget], "msds-isrodc")
	delete(objects[""], "defaultnamingcontext")
	client := operationMasterFixtureClient(objects, func(_ context.Context, _ string, mods []operationMasterModification) OperationMasterAttempt {
		for role, definition := range operationMasterDefinitions {
			if definition.attribute == mods[0].attribute {
				objects[locations[role]]["fsmoroleowner"] = [][]byte{[]byte(operationTestTarget)}
			}
		}
		return OperationMasterAttempt{State: OperationMasterWriteAccepted}
	})
	_, err := client.MoveOperationMasterRoles(context.Background(), MoveOperationMasterRolesRequest{Roles: []OperationMasterRole{OperationMasterSchemaMaster, OperationMasterDomainNamingMaster}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOperationMasterRIDPoolBoundsAndConcurrentChange(t *testing.T) {
	for _, test := range []string{"exhausted", "overflow", "changed-owner", "readback-denied", "pool-not-advanced", "already-owned"} {
		t.Run(test, func(t *testing.T) {
			objects, _, _ := operationMasterFixture()
			if test == "exhausted" {
				objects[operationTestRID]["ridavailablepool"] = [][]byte{[]byte(strconv.FormatUint((uint64(0x3fffffff)<<32)|0x3ffff000, 10))}
			}
			if test == "overflow" {
				objects[operationTestRID]["ridavailablepool"] = [][]byte{[]byte("18446744073709551615")}
			}
			if test == "already-owned" {
				objects[operationTestRID]["fsmoroleowner"] = [][]byte{[]byte(operationTestTarget)}
			}
			calls := 0
			client := operationMasterFixtureClient(objects, func(_ context.Context, dn string, _ []operationMasterModification) OperationMasterAttempt {
				calls++
				if dn != "" {
					if test != "pool-not-advanced" {
						t.Fatal("unexpected seizure")
					}
					objects[operationTestRID]["fsmoroleowner"] = [][]byte{[]byte(operationTestTarget)}
					return OperationMasterAttempt{State: OperationMasterWriteAccepted}
				}
				if test == "changed-owner" {
					objects[operationTestRID]["fsmoroleowner"] = [][]byte{[]byte(strings.Replace(operationTestOld, "OLD", "THIRD", 1))}
				}
				if test == "readback-denied" {
					delete(objects, operationTestRID)
				}
				return OperationMasterAttempt{State: OperationMasterWriteRejected, Err: &LDAPError{Code: 52}}
			})
			result, err := client.MoveOperationMasterRoles(context.Background(), MoveOperationMasterRolesRequest{Roles: []OperationMasterRole{OperationMasterRIDMaster}, Force: true})
			if test == "already-owned" {
				if err != nil || calls != 0 || result.Outcomes[0].Status != OperationMasterAlreadyOwned {
					t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
				}
			} else if err == nil || result.Outcomes[0].Verified {
				t.Fatalf("unverified failure accepted: %+v, %v", result, err)
			}
			if test == "changed-owner" && !errors.Is(err, ErrOperationMasterChanged) {
				t.Fatal(err)
			}
			if test == "pool-not-advanced" && (!errors.Is(err, ErrOperationMasterReadback) || result.Outcomes[0].Status != OperationMasterSeized) {
				t.Fatal(err)
			}
		})
	}
}

func TestOperationMasterPartialCompletionAndValidation(t *testing.T) {
	for _, roles := range [][]OperationMasterRole{nil, {OperationMasterSchemaMaster, OperationMasterSchemaMaster}, {"invalid"}} {
		if err := (MoveOperationMasterRolesRequest{Roles: roles}).Validate(); !errors.Is(err, ErrInvalidOperationMasterRequest) {
			t.Fatal(err)
		}
	}
	objects, _, _ := operationMasterFixture()
	calls := 0
	client := operationMasterFixtureClient(objects, func(context.Context, string, []operationMasterModification) OperationMasterAttempt {
		calls++
		if calls == 1 {
			objects[operationTestSchema]["fsmoroleowner"] = [][]byte{[]byte(operationTestTarget)}
			return OperationMasterAttempt{State: OperationMasterWriteAccepted}
		}
		return OperationMasterAttempt{State: OperationMasterWriteUncertain, Err: context.DeadlineExceeded}
	})
	result, err := client.MoveOperationMasterRoles(context.Background(), MoveOperationMasterRolesRequest{Roles: []OperationMasterRole{OperationMasterSchemaMaster, OperationMasterPDCEmulator, OperationMasterRIDMaster}, Force: true})
	got := []OperationMasterStatus{result.Outcomes[0].Status, result.Outcomes[1].Status, result.Outcomes[2].Status}
	if !errors.Is(err, ErrOperationMasterUncertain) || calls != 2 || !slices.Equal(got, []OperationMasterStatus{OperationMasterTransferred, OperationMasterUncertain, OperationMasterNotAttempted}) {
		t.Fatalf("statuses=%v calls=%d err=%v", got, calls, err)
	}
}

func TestOperationMasterCloseWaitsForSubmittedWrite(t *testing.T) {
	objects, _, _ := operationMasterFixture()
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	client := operationMasterFixtureClient(objects, func(ctx context.Context, _ string, _ []operationMasterModification) OperationMasterAttempt {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return OperationMasterAttempt{State: OperationMasterWriteUncertain, Err: context.Cause(ctx)}
	})
	session := client.session.(operationMasterTestSession)
	unbound := make(chan struct{})
	session.finish = func() error { close(unbound); return nil }
	client.session = session
	completed := make(chan error, 1)
	go func() {
		_, err := client.MoveOperationMasterRoles(context.Background(), MoveOperationMasterRolesRequest{Roles: []OperationMasterRole{OperationMasterSchemaMaster}, Force: true})
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
	if err := <-completed; !errors.Is(err, ErrOperationMasterUncertain) || !errors.Is(err, ErrClosed) {
		t.Fatalf("lost uncertain/canceled write: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}
