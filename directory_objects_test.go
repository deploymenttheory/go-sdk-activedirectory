package activedirectory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type objectWriteTestSession struct {
	testSession
	write func(context.Context, ldapWriteRequest) ldapWriteAttempt
}

func (s objectWriteTestSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	return s.write(ctx, request)
}

func objectTestGUID() GUID { guid, _ := ParseGUID("00112233-4455-6677-8899-aabbccddeeff"); return guid }
func objectTestIdentity() Identity {
	identity, _ := IdentityByDN("CN=sample,DC=example")
	return identity
}
func objectTestEntry(dn string) Object {
	return Object{DistinguishedName: dn, Attributes: map[string][][]byte{"objectguid": {objectTestGUID().Bytes()}, "usnchanged": {[]byte("7")}}}
}
func objectTestCursor(objects ...Object) searchCursor {
	return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return objects, true, nil }, finish: func() error { return nil }}
}
func objectTestClient(t *testing.T, controls []string, search func(context.Context, SearchOptions) (searchCursor, error), write func(context.Context, ldapWriteRequest) ldapWriteAttempt) *Client {
	t.Helper()
	client := newClient(Config{Endpoint: Endpoint{Host: "dc.example", Port: 389}, Timeout: time.Second}, objectWriteTestSession{testSession: testSession{
		read: func(context.Context, []string) (map[string][][]byte, error) {
			root := identityTestRoot(CapabilityActiveDirectory)
			root["schemanamingcontext"] = [][]byte{[]byte("CN=Schema,CN=Configuration,DC=example")}
			for _, control := range controls {
				root["supportedcontrol"] = append(root["supportedcontrol"], []byte(control))
			}
			return root, nil
		}, search: search, finish: func() error { return nil },
	}, write: write})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func TestObjectChangesPreserveBinaryMultivalueAndClear(t *testing.T) {
	changes := []AttributeChange{
		{Attribute: "photo", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte{0, 0xff}), NewRawValue([]byte{})}},
		{Attribute: "description", Kind: AttributeClear},
		{Attribute: "member", Kind: AttributeAddValues, Values: []RawValue{NewRawValue([]byte("CN=李,DC=example"))}},
		{Attribute: "otherTelephone", Kind: AttributeRemoveValues, Values: []RawValue{NewRawValue([]byte("123"))}},
	}
	mods, err := objectChanges(changes)
	if err != nil || len(mods) != 4 || mods[0].operation != 2 || len(mods[0].values) != 2 || !bytes.Equal(mods[0].values[0], []byte{0, 0xff}) || len(mods[0].values[1]) != 0 || mods[1].operation != 1 || len(mods[1].values) != 0 || mods[2].operation != 0 || mods[3].operation != 1 {
		t.Fatalf("%+v %v", mods, err)
	}
	mods[0].values[0][0] = 9
	if changes[0].Values[0].Bytes()[0] != 0 {
		t.Fatal("mutation aliases RawValue")
	}
}

func TestObjectChangesStrictAtomicRemoveThenAdd(t *testing.T) {
	for _, values := range [][]string{{"old", "new"}, {"old1", "old2", "new1", "new2"}} {
		half := len(values) / 2
		var oldValues, newValues []RawValue
		for _, value := range values[:half] {
			oldValues = append(oldValues, NewRawValue([]byte(value)))
		}
		for _, value := range values[half:] {
			newValues = append(newValues, NewRawValue([]byte(value)))
		}
		writes := 0
		client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
			entry := objectTestEntry("CN=sample,DC=example")
			for _, value := range newValues {
				entry.Attributes["description"] = append(entry.Attributes["description"], value.Bytes())
			}
			return objectTestCursor(entry), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if request.operation != ldapWriteModify || len(request.modifications) != 2 || request.modifications[0].operation != 1 || request.modifications[1].operation != 0 || len(request.controls) != 0 || string(request.modifications[0].values[0]) != values[0] {
				t.Fatalf("%+v", request)
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		result, err := client.UpdateObject(context.Background(), UpdateObjectRequest{Identity: objectTestIdentity(), Changes: []AttributeChange{{Attribute: "description", Kind: AttributeAddValues, Values: newValues}, {Attribute: "DESCRIPTION", Kind: AttributeRemoveValues, Values: oldValues}}})
		if err != nil || !result.Verified || writes != 1 {
			t.Fatalf("%+v %v", result, err)
		}
	}
	value := []RawValue{NewRawValue([]byte("same"))}
	for _, changes := range [][]AttributeChange{
		{{Attribute: "description", Kind: AttributeAddValues, Values: value}, {Attribute: "description", Kind: AttributeRemoveValues, Values: value}},
		{{Attribute: "description", Kind: AttributeAddValues, Values: value}, {Attribute: "description", Kind: AttributeAddValues, Values: value}},
		{{Attribute: "description", Kind: AttributeClear}, {Attribute: "description", Kind: AttributeAddValues, Values: value}},
	} {
		if _, err := objectChanges(changes); !errors.Is(err, ErrInvalidObjectMutation) {
			t.Fatal(err)
		}
	}
}

func TestObjectReadbackVerificationIsConservative(t *testing.T) {
	for _, tc := range []struct {
		name         string
		attributes   map[string][][]byte
		kind         AttributeChangeKind
		wantComplete bool
	}{
		{"set differs", map[string][][]byte{"description": {[]byte("other")}, "objectguid": {objectTestGUID().Bytes()}}, AttributeSet, true},
		{"set hidden", map[string][][]byte{"objectguid": {objectTestGUID().Bytes()}}, AttributeSet, true},
		{"set ranged", map[string][][]byte{"description;range=0-0": {[]byte("wanted")}, "objectguid": {objectTestGUID().Bytes()}}, AttributeSet, true},
		{"clear hidden", map[string][][]byte{"objectguid": {objectTestGUID().Bytes()}}, AttributeClear, true},
		{"wrong GUID", map[string][][]byte{"objectguid": {make([]byte, 16)}}, AttributeSet, false},
		{"missing GUID", nil, AttributeSet, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
				reads++
				if reads == 1 {
					return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
				}
				return objectTestCursor(Object{DistinguishedName: "CN=sample,DC=example", Attributes: tc.attributes}), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			change := AttributeChange{Attribute: "description", Kind: tc.kind}
			if tc.kind != AttributeClear {
				change.Values = []RawValue{NewRawValue([]byte("wanted"))}
			}
			result, err := client.UpdateObject(context.Background(), UpdateObjectRequest{Identity: objectTestIdentity(), Changes: []AttributeChange{change}})
			if err == nil || result.State != ObjectWriteAccepted || result.Verified || result.ReadbackComplete != tc.wantComplete {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}

func TestObjectMutationRetainsPartialResolutionCandidates(t *testing.T) {
	permission := &LDAPError{Code: 50, Diagnostic: "private readback diagnostic"}
	cleanup := errors.New("injected readback cleanup failure")
	for _, phase := range []string{"preflight", "readback"} {
		for _, failure := range []string{"permission", "cancellation", "cleanup"} {
			t.Run(phase+"/"+failure, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				reads, writes, closed := 0, 0, 0
				want := error(permission)
				if failure == "cancellation" {
					want = context.Canceled
				}
				if failure == "cleanup" {
					want = cleanup
				}
				client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
					reads++
					if phase == "readback" && reads == 1 {
						return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
					}
					return testSearchCursor{
						read: func(context.Context, uint32) ([]Object, bool, error) {
							entry := objectTestEntry("CN=sample,DC=example")
							entry.Attributes["description"] = [][]byte{{0, 0xff, 0x42}}
							if failure == "permission" {
								return []Object{entry}, false, permission
							}
							if failure == "cancellation" {
								cancel()
							}
							return []Object{entry}, true, nil
						},
						finish: func() error {
							closed++
							if failure == "cleanup" {
								return cleanup
							}
							return nil
						},
					}, nil
				}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
					writes++
					return ldapWriteAttempt{State: ldapWriteAccepted}
				})
				result, err := client.UpdateObject(ctx, UpdateObjectRequest{Identity: objectTestIdentity(), Changes: []AttributeChange{{Attribute: "description", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte{0, 0xff, 0x42})}}}})
				if !errors.Is(err, want) || result.After != nil || result.ReadbackComplete || result.Verified || closed != 1 {
					t.Fatalf("%+v %v closed=%d", result, err, closed)
				}
				candidates := result.PreflightCandidates
				if phase == "preflight" {
					if writes != 0 || result.State != ObjectWriteNotAttempted || result.Before != nil || len(result.ReadbackCandidates) != 0 {
						t.Fatalf("%+v writes=%d", result, writes)
					}
				} else {
					candidates = result.ReadbackCandidates
					if writes != 1 || result.State != ObjectWriteAccepted || result.Before == nil || !errors.Is(err, ErrObjectReadback) {
						t.Fatalf("%+v %v writes=%d", result, err, writes)
					}
				}
				if len(candidates) != 1 || candidates[0].DistinguishedName != "CN=sample,DC=example" || !bytes.Equal(candidates[0].Attributes["description"][0], []byte{0, 0xff, 0x42}) {
					t.Fatalf("lost raw candidates: %+v", candidates)
				}
			})
		}
	}
}

func TestObjectMutationInvalidRequestsNeverWrite(t *testing.T) {
	client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
		t.Fatal("invalid request performed a read")
		return nil, nil
	}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		t.Fatal("invalid request wrote")
		return ldapWriteAttempt{}
	})
	value := []RawValue{NewRawValue([]byte("x"))}
	for _, changes := range [][]AttributeChange{
		nil, {{Attribute: "description", Kind: AttributeSet}}, {{Attribute: "description", Kind: AttributeClear, Values: value}},
		{{Attribute: "description", Kind: 99, Values: value}}, {{Attribute: "description;binary", Kind: AttributeSet, Values: value}},
		{{Attribute: "1.2.3", Kind: AttributeSet, Values: value}}, {{Attribute: "objectGUID", Kind: AttributeClear}},
		{{Attribute: "description", Kind: AttributeSet, Values: value}, {Attribute: "DESCRIPTION", Kind: AttributeAddValues, Values: value}},
		{{Attribute: "description", Kind: AttributeSet, Values: []RawValue{value[0], value[0]}}},
	} {
		result, err := client.UpdateObject(context.Background(), UpdateObjectRequest{Identity: objectTestIdentity(), Changes: changes})
		if !errors.Is(err, ErrInvalidObjectMutation) || result.State != ObjectWriteNotAttempted {
			t.Fatalf("%+v %v", result, err)
		}
	}
	if _, err := client.RenameObject(context.Background(), RenameObjectRequest{Identity: objectTestIdentity(), Name: "bad\x00"}); !errors.Is(err, ErrInvalidObjectMutation) {
		t.Fatal(err)
	}
	if _, err := client.CreateObject(context.Background(), CreateObjectRequest{Parent: objectTestIdentity(), Class: "container", Name: "x", Options: ObjectMutationOptions{ExpectedVersion: &ObjectVersion{}}}); !errors.Is(err, ErrObjectControlUnsupported) {
		t.Fatal(err)
	}
}

func TestCreateObjectSchemaInheritanceEscapedNameAndReadback(t *testing.T) {
	name := " #Jörg, 李+ "
	wantDN := `cn=\ #Jörg\, 李\+\ ,CN=sample,DC=example`
	reads, writes := 0, 0
	client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
		reads++
		switch reads {
		case 1:
			return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
		case 2:
			if query.Scope != ScopeOneLevel || query.Filter != "(&(objectClass=classSchema)(lDAPDisplayName=customContainer))" {
				t.Fatal(query)
			}
			return objectTestCursor(Object{Attributes: map[string][][]byte{"objectclasscategory": {[]byte("1")}, "subclassof": {[]byte("container")}}}), nil
		case 3:
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}}}), nil
		case 4:
			if query.Base != wantDN || query.Scope != ScopeBase {
				t.Fatal(query)
			}
			entry := objectTestEntry(wantDN)
			entry.Attributes["cn"] = [][]byte{[]byte(name)}
			entry.Attributes["photo"] = [][]byte{{0, 0xff}}
			entry.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("customContainer")}
			return objectTestCursor(entry), nil
		default:
			t.Fatal("unexpected read")
			return nil, nil
		}
	}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
		writes++
		if request.operation != ldapWriteAdd || request.dn != wantDN || len(request.modifications) != 3 || !bytes.Equal(request.modifications[0].values[0], []byte{0, 0xff}) || string(request.modifications[2].values[0]) != name {
			t.Fatalf("%+v", request)
		}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	})
	result, err := client.CreateObject(context.Background(), CreateObjectRequest{Parent: objectTestIdentity(), Class: "customContainer", Name: name, Attributes: map[string][]RawValue{"photo": {NewRawValue([]byte{0, 0xff})}}})
	if err != nil || result.State != ObjectWriteAccepted || result.Before != nil || !result.ReadbackComplete || result.After == nil || result.TargetGUID == nil || writes != 1 {
		t.Fatalf("%+v %v writes=%d", result, err, writes)
	}
}

func TestObjectWriteUsesResolvedGUIDAndPreservesReadback(t *testing.T) {
	for _, rename := range []bool{false, true} {
		reads, writes := 0, 0
		client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
			reads++
			if reads == 1 {
				return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
			}
			if query.Scope != ScopeSubtree || query.Filter != `(objectGUID=\33\22\11\00\55\44\77\66\88\99\aa\bb\cc\dd\ee\ff)` {
				t.Fatal(query)
			}
			return objectTestCursor(objectTestEntry(`CN=Renamed\, 李,DC=example`)), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if request.dn != "<GUID=33221100554477668899aabbccddeeff>" {
				t.Fatal(request.dn)
			}
			if rename && (request.operation != ldapWriteRename || request.newRDN != `cn=Renamed\, 李` || !request.deleteOldRDN) {
				t.Fatalf("%+v", request)
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		var result ObjectMutationResult
		var err error
		if rename {
			result, err = client.RenameObject(context.Background(), RenameObjectRequest{Identity: objectTestIdentity(), Name: "Renamed, 李"})
		} else {
			result, err = client.UpdateObject(context.Background(), UpdateObjectRequest{Identity: objectTestIdentity(), Changes: []AttributeChange{{Attribute: "description", Kind: AttributeClear}}})
		}
		if (rename && err != nil) || (!rename && !errors.Is(err, ErrObjectVerification)) || result.Verified != rename || writes != 1 || !result.ReadbackComplete || result.After == nil || result.Before == nil || result.After.DistinguishedName == result.Before.DistinguishedName {
			t.Fatalf("%+v %v", result, err)
		}
	}
}

func TestObjectWriteOutcomesNeverReplay(t *testing.T) {
	permission := &LDAPError{Code: 50, Diagnostic: "private ACL detail", MatchedDN: "DC=example"}
	for _, tc := range []struct {
		name    string
		attempt ldapWriteAttempt
		want    error
		state   ObjectWriteState
	}{
		{"permission", ldapWriteAttempt{State: ldapWriteRejected, Err: permission}, ErrObjectWritePermission, ObjectWriteRejected},
		{"schema", ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 65}}, nil, ObjectWriteRejected},
		{"duplicate", ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 68}}, ErrObjectAlreadyExists, ObjectWriteRejected},
		{"protected", ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 53}}, nil, ObjectWriteRejected},
		{"uncertain", ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}, ErrObjectWriteUncertain, ObjectWriteUncertain},
		{"accepted cleanup failure", ldapWriteAttempt{State: ldapWriteAccepted, Err: context.Canceled}, context.Canceled, ObjectWriteAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, writes := 0, 0
			client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
				reads++
				return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt { writes++; return tc.attempt })
			result, err := client.UpdateObject(context.Background(), UpdateObjectRequest{Identity: objectTestIdentity(), Changes: []AttributeChange{{Attribute: "description", Kind: AttributeClear}}})
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || result.State != tc.state || writes != 1 || reads != 1 || result.ReadbackComplete {
				t.Fatalf("%+v %v reads=%d writes=%d", result, err, reads, writes)
			}
			if tc.attempt.Err == permission {
				var native *LDAPError
				if !errors.As(err, &native) || native != permission || strings.Contains(err.Error(), permission.Diagnostic) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestObjectDeleteLeafAndPartialTreeResults(t *testing.T) {
	for _, tc := range []struct {
		recursive bool
		code      uint32
		accepted  bool
		partial   bool
		want      error
	}{
		{false, 66, false, false, ErrObjectNotLeaf}, {true, 11, false, true, nil}, {true, 0, true, true, nil}, {false, 0, true, false, nil},
	} {
		writes, reads := 0, 0
		client := objectTestClient(t, []string{objectTreeDeleteControl}, func(context.Context, SearchOptions) (searchCursor, error) {
			reads++
			if reads == 1 {
				return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
			}
			return objectTestCursor(), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if request.operation != ldapWriteDelete || len(request.controls) != boolInt(tc.recursive) {
				t.Fatalf("%+v", request)
			}
			if tc.recursive && (request.controls[0].oid != objectTreeDeleteControl || !request.controls[0].critical || request.controls[0].value != nil) {
				t.Fatal(request.controls)
			}
			if tc.accepted {
				return ldapWriteAttempt{State: ldapWriteAccepted}
			}
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: tc.code, Diagnostic: "000020B3: ERROR_DS_TREE_DELETE_NOT_FINISHED"}}
		})
		result, err := client.DeleteObject(context.Background(), DeleteObjectRequest{Identity: objectTestIdentity(), Recursive: tc.recursive})
		if writes != 1 || result.PartialEffectsPossible != tc.partial || result.AbsentAfter != tc.accepted || result.ReadbackComplete != tc.accepted || (tc.want != nil && !errors.Is(err, tc.want)) || (tc.accepted && err != nil) {
			t.Fatalf("%+v %v", result, err)
		}
		if !tc.accepted {
			var native *LDAPError
			if !errors.As(err, &native) || native.Code != tc.code || reads != 1 {
				t.Fatalf("%+v %v reads=%d", result, err, reads)
			}
		}
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestObjectVersionAssertionsAndUnsupportedGuards(t *testing.T) {
	version := ObjectVersion{Source: Endpoint{Host: "dc.example", Port: 389}, GUID: objectTestGUID(), USNChanged: 7}
	want, _ := hex.DecodeString("a031a31e040a6f626a65637447554944041033221100554477668899aabbccddeeffa30f040a75534e4368616e676564040137")
	if got := objectVersionAssertion(version); !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	for _, tc := range []struct {
		controls  []string
		version   ObjectVersion
		recursive bool
		want      error
	}{
		{nil, version, false, ErrObjectControlUnsupported},
		{[]string{objectAssertionControl}, version, false, ErrObjectConcurrency},
		{[]string{objectAssertionControl, objectTreeDeleteControl}, version, true, ErrObjectControlUnsupported},
		{[]string{objectAssertionControl}, ObjectVersion{Source: Endpoint{Host: "other.example", Port: 389}, GUID: objectTestGUID()}, false, ErrObjectConcurrency},
	} {
		writes := 0
		client := objectTestClient(t, tc.controls, func(context.Context, SearchOptions) (searchCursor, error) {
			return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if !reflect.DeepEqual(request.controls, []ldapWriteControl{{oid: objectAssertionControl, critical: true, value: want}}) {
				t.Fatal(request.controls)
			}
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 122}}
		})
		result, err := client.DeleteObject(context.Background(), DeleteObjectRequest{Identity: objectTestIdentity(), Recursive: tc.recursive, Options: ObjectMutationOptions{ExpectedVersion: &tc.version}})
		if !errors.Is(err, tc.want) || (writes > 0 && result.State != ObjectWriteRejected) || writes > 1 {
			t.Fatalf("%+v %v writes=%d", result, err, writes)
		}
	}
}

func TestObjectMutationScopeCancellationAndReadbackFailure(t *testing.T) {
	reads, writes := 0, 0
	client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
		reads++
		if reads == 1 {
			return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
		}
		return nil, &LDAPError{Code: 50}
	}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		writes++
		return ldapWriteAttempt{State: ldapWriteAccepted}
	})
	wrong, _ := IdentityByDN("CN=sample,DC=other")
	if result, err := client.DeleteObject(context.Background(), DeleteObjectRequest{Identity: wrong}); !errors.Is(err, ErrIdentityScope) || result.State != ObjectWriteNotAttempted || writes != 0 || reads != 0 {
		t.Fatalf("%+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.DeleteObject(ctx, DeleteObjectRequest{Identity: objectTestIdentity()}); !errors.Is(err, context.Canceled) || writes != 0 {
		t.Fatal(err)
	}
	result, err := client.RenameObject(context.Background(), RenameObjectRequest{Identity: objectTestIdentity(), Name: "new"})
	if !errors.Is(err, ErrObjectReadback) || !errors.Is(err, ErrObjectWritePermission) || result.State != ObjectWriteAccepted || result.ReadbackComplete || writes != 1 {
		t.Fatalf("%+v %v writes=%d", result, err, writes)
	}
}

func TestObjectMutationLDSArbitraryPorts(t *testing.T) {
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		for _, port := range []uint16{3268, 3269} {
			reads, writes := 0, 0
			client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
				reads++
				if reads == 1 {
					return objectTestCursor(objectTestEntry("CN=sample,DC=example")), nil
				}
				return objectTestCursor(), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				writes++
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			client.config.Endpoint.Port = port
			session := client.session.(objectWriteTestSession)
			session.read = func(context.Context, []string) (map[string][][]byte, error) { return identityTestRoot(kind), nil }
			client.session = session
			result, err := client.DeleteObject(context.Background(), DeleteObjectRequest{Identity: objectTestIdentity()})
			if kind == CapabilityActiveDirectory {
				if !errors.Is(err, ErrObjectWriteTarget) || writes != 0 {
					t.Fatalf("%+v %v", result, err)
				}
			} else if err != nil || writes != 1 || !result.Verified {
				t.Fatalf("%+v %v", result, err)
			}
		}
	}
}

func FuzzObjectNamingRoundTrip(f *testing.F) {
	for _, name := range []string{"normal", " 李,+# ", "#leading", `slash\equals=`, "quoted\""} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if name == "" || !validDirectoryText(name) {
			return
		}
		parsed, err := parseIdentityDN("CN=" + escapeObjectName(name) + ",DC=example")
		if err != nil || len(parsed) != 2 || len(parsed[0]) != 1 || parsed[0][0].value != name {
			t.Fatalf("%q: %+v %v", name, parsed, err)
		}
	})
}
