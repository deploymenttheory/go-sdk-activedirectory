package acceptance

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalObjectWriteTestSession struct {
	InternalTestSession
	InternalWrite func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt
}

func (s InternalObjectWriteTestSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	return s.InternalWrite(ctx, request)
}

func InternalObjectTestGUID() admodel.GUID {
	guid, _ := admodel.ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	return guid
}

func InternalObjectTestIdentity() admodel.Identity {
	identity, _ := admodel.IdentityByDN("CN=sample,DC=example")
	return identity
}

func InternalObjectTestEntry(dn string) admodel.Object {
	return admodel.Object{
		DistinguishedName: dn,
		Attributes: map[string][][]byte{
			"objectguid": {InternalObjectTestGUID().Bytes()},
			"usnchanged": {[]byte("7")},
		},
	}
}

func InternalObjectTestCursor(objects ...admodel.Object) admodel.InternalSearchCursor {
	return InternalTestSearchCursor{
		InternalRead:   func(context.Context, uint32) ([]admodel.Object, bool, error) { return objects, true, nil },
		InternalFinish: func() error { return nil },
	}
}

func InternalObjectTestClient(
	t *testing.T,
	controls []string,
	search func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error),
	write func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt,
) *adengine.Client {
	t.Helper()
	client := adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example", Port: 389},
			Timeout:  time.Second,
		},
		InternalObjectWriteTestSession{InternalTestSession: InternalTestSession{
			InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
				root := InternalIdentityTestRoot(admodel.CapabilityActiveDirectory)
				root["schemanamingcontext"] = [][]byte{
					[]byte("CN=Schema,CN=Configuration,DC=example"),
				}
				for _, control := range controls {
					root["supportedcontrol"] = append(root["supportedcontrol"], []byte(control))
				}
				return root, nil
			}, InternalSearch: search, InternalFinish: func() error { return nil },
		}, InternalWrite: write},
	)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func TestObjectChangesPreserveBinaryMultivalueAndClear(t *testing.T) {
	changes := []admodel.AttributeChange{
		{
			Attribute: "photo",
			Kind:      admodel.AttributeSet,
			Values: []admodel.RawValue{
				admodel.NewRawValue([]byte{0, 0xff}),
				admodel.NewRawValue([]byte{}),
			},
		},
		{Attribute: "description", Kind: admodel.AttributeClear},
		{
			Attribute: "member",
			Kind:      admodel.AttributeAddValues,
			Values:    []admodel.RawValue{admodel.NewRawValue([]byte("CN=李,DC=example"))},
		},
		{
			Attribute: "otherTelephone",
			Kind:      admodel.AttributeRemoveValues,
			Values:    []admodel.RawValue{admodel.NewRawValue([]byte("123"))},
		},
	}
	mods, err := admodel.InternalObjectChanges(changes)
	if err != nil || len(mods) != 4 || mods[0].InternalOperation != 2 ||
		len(mods[0].InternalValues) != 2 ||
		!bytes.Equal(mods[0].InternalValues[0], []byte{0, 0xff}) ||
		len(mods[0].InternalValues[1]) != 0 ||
		mods[1].InternalOperation != 1 ||
		len(mods[1].InternalValues) != 0 ||
		mods[2].InternalOperation != 0 ||
		mods[3].InternalOperation != 1 {
		t.Fatalf("%+v %v", mods, err)
	}
	mods[0].InternalValues[0][0] = 9
	if changes[0].Values[0].Bytes()[0] != 0 {
		t.Fatal("mutation aliases RawValue")
	}
}

func TestObjectChangesStrictAtomicRemoveThenAdd(t *testing.T) {
	for _, values := range [][]string{{"old", "new"}, {"old1", "old2", "new1", "new2"}} {
		half := len(values) / 2
		var oldValues, newValues []admodel.RawValue
		for _, value := range values[:half] {
			oldValues = append(oldValues, admodel.NewRawValue([]byte(value)))
		}
		for _, value := range values[half:] {
			newValues = append(newValues, admodel.NewRawValue([]byte(value)))
		}
		writes := 0
		client := InternalObjectTestClient(
			t,
			nil,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				entry := InternalObjectTestEntry("CN=sample,DC=example")
				for _, value := range newValues {
					entry.Attributes["description"] = append(
						entry.Attributes["description"],
						value.Bytes(),
					)
				}
				return InternalObjectTestCursor(entry), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if request.InternalOperation != admodel.InternalLdapWriteModify ||
					len(request.InternalModifications) != 2 ||
					request.InternalModifications[0].InternalOperation != 1 ||
					request.InternalModifications[1].InternalOperation != 0 ||
					len(request.InternalControls) != 0 ||
					string(request.InternalModifications[0].InternalValues[0]) != values[0] {
					t.Fatalf("%+v", request)
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		result, err := client.UpdateObject(
			context.Background(),
			admodel.UpdateObjectRequest{
				Identity: InternalObjectTestIdentity(),
				Changes: []admodel.AttributeChange{
					{Attribute: "description", Kind: admodel.AttributeAddValues, Values: newValues},
					{
						Attribute: "DESCRIPTION",
						Kind:      admodel.AttributeRemoveValues,
						Values:    oldValues,
					},
				},
			},
		)
		if err != nil || !result.Verified || writes != 1 {
			t.Fatalf("%+v %v", result, err)
		}
	}
	value := []admodel.RawValue{admodel.NewRawValue([]byte("same"))}
	for _, changes := range [][]admodel.AttributeChange{
		{{Attribute: "description", Kind: admodel.AttributeAddValues, Values: value}, {Attribute: "description", Kind: admodel.AttributeRemoveValues, Values: value}},
		{{Attribute: "description", Kind: admodel.AttributeAddValues, Values: value}, {Attribute: "description", Kind: admodel.AttributeAddValues, Values: value}},
		{{Attribute: "description", Kind: admodel.AttributeClear}, {Attribute: "description", Kind: admodel.AttributeAddValues, Values: value}},
	} {
		if _, err := admodel.InternalObjectChanges(
			changes,
		); !errors.Is(
			err,
			admodel.ErrInvalidObjectMutation,
		) {
			t.Fatal(err)
		}
	}
}

func TestObjectReadbackVerificationIsConservative(t *testing.T) {
	for _, tc := range []struct {
		InternalName         string
		InternalAttributes   map[string][][]byte
		InternalKind         admodel.AttributeChangeKind
		InternalWantComplete bool
	}{
		{"set differs", map[string][][]byte{"description": {[]byte("other")}, "objectguid": {InternalObjectTestGUID().Bytes()}}, admodel.AttributeSet, true},
		{"set hidden", map[string][][]byte{"objectguid": {InternalObjectTestGUID().Bytes()}}, admodel.AttributeSet, true},
		{"set ranged", map[string][][]byte{"description;range=0-0": {[]byte("wanted")}, "objectguid": {InternalObjectTestGUID().Bytes()}}, admodel.AttributeSet, true},
		{"clear hidden", map[string][][]byte{"objectguid": {InternalObjectTestGUID().Bytes()}}, admodel.AttributeClear, true},
		{"wrong GUID", map[string][][]byte{"objectguid": {make([]byte, 16)}}, admodel.AttributeSet, false},
		{"missing GUID", nil, admodel.AttributeSet, false},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			reads := 0
			client := InternalObjectTestClient(
				t,
				nil,
				func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					reads++
					if reads == 1 {
						return InternalObjectTestCursor(
							InternalObjectTestEntry("CN=sample,DC=example"),
						), nil
					}
					return InternalObjectTestCursor(
						admodel.Object{
							DistinguishedName: "CN=sample,DC=example",
							Attributes:        tc.InternalAttributes,
						},
					), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			change := admodel.AttributeChange{Attribute: "description", Kind: tc.InternalKind}
			if tc.InternalKind != admodel.AttributeClear {
				change.Values = []admodel.RawValue{admodel.NewRawValue([]byte("wanted"))}
			}
			result, err := client.UpdateObject(
				context.Background(),
				admodel.UpdateObjectRequest{
					Identity: InternalObjectTestIdentity(),
					Changes:  []admodel.AttributeChange{change},
				},
			)
			if err == nil || result.State != admodel.ObjectWriteAccepted || result.Verified ||
				result.ReadbackComplete != tc.InternalWantComplete {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}

func TestObjectMutationRetainsPartialResolutionCandidates(t *testing.T) {
	permission := &admodel.LDAPError{Code: 50, Diagnostic: "private readback diagnostic"}
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
				client := InternalObjectTestClient(
					t,
					nil,
					func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						reads++
						if phase == "readback" && reads == 1 {
							return InternalObjectTestCursor(
								InternalObjectTestEntry("CN=sample,DC=example"),
							), nil
						}
						return InternalTestSearchCursor{
							InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
								entry := InternalObjectTestEntry("CN=sample,DC=example")
								entry.Attributes["description"] = [][]byte{{0, 0xff, 0x42}}
								if failure == "permission" {
									return []admodel.Object{entry}, false, permission
								}
								if failure == "cancellation" {
									cancel()
								}
								return []admodel.Object{entry}, true, nil
							},
							InternalFinish: func() error {
								closed++
								if failure == "cleanup" {
									return cleanup
								}
								return nil
							},
						}, nil
					},
					func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						writes++
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteAccepted,
						}
					},
				)
				result, err := client.UpdateObject(
					ctx,
					admodel.UpdateObjectRequest{
						Identity: InternalObjectTestIdentity(),
						Changes: []admodel.AttributeChange{
							{
								Attribute: "description",
								Kind:      admodel.AttributeSet,
								Values: []admodel.RawValue{
									admodel.NewRawValue([]byte{0, 0xff, 0x42}),
								},
							},
						},
					},
				)
				if !errors.Is(err, want) || result.After != nil || result.ReadbackComplete ||
					result.Verified ||
					closed != 1 {
					t.Fatalf("%+v %v closed=%d", result, err, closed)
				}
				candidates := result.PreflightCandidates
				if phase == "preflight" {
					if writes != 0 || result.State != admodel.ObjectWriteNotAttempted ||
						result.Before != nil ||
						len(result.ReadbackCandidates) != 0 {
						t.Fatalf("%+v writes=%d", result, writes)
					}
				} else {
					candidates = result.ReadbackCandidates
					if writes != 1 || result.State != admodel.ObjectWriteAccepted ||
						result.Before == nil ||
						!errors.Is(err, admodel.ErrObjectReadback) {
						t.Fatalf("%+v %v writes=%d", result, err, writes)
					}
				}
				if len(candidates) != 1 ||
					candidates[0].DistinguishedName != "CN=sample,DC=example" ||
					!bytes.Equal(
						candidates[0].Attributes["description"][0],
						[]byte{0, 0xff, 0x42},
					) {
					t.Fatalf("lost raw candidates: %+v", candidates)
				}
			})
		}
	}
}

func TestObjectMutationInvalidRequestsNeverWrite(t *testing.T) {
	client := InternalObjectTestClient(
		t,
		nil,
		func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			t.Fatal("invalid request performed a read")
			return nil, nil
		},
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			t.Fatal("invalid request wrote")
			return admodel.InternalLdapWriteAttempt{}
		},
	)
	value := []admodel.RawValue{admodel.NewRawValue([]byte("x"))}
	for _, changes := range [][]admodel.AttributeChange{
		nil,
		{{Attribute: "description", Kind: admodel.AttributeSet}},
		{{Attribute: "description", Kind: admodel.AttributeClear, Values: value}},
		{{Attribute: "description", Kind: 99, Values: value}},
		{{Attribute: "description;binary", Kind: admodel.AttributeSet, Values: value}},
		{{Attribute: "1.2.3", Kind: admodel.AttributeSet, Values: value}},
		{{Attribute: "objectGUID", Kind: admodel.AttributeClear}},
		{{Attribute: "description", Kind: admodel.AttributeSet, Values: value}, {Attribute: "DESCRIPTION", Kind: admodel.AttributeAddValues, Values: value}},
		{{Attribute: "description", Kind: admodel.AttributeSet, Values: []admodel.RawValue{value[0], value[0]}}},
	} {
		result, err := client.UpdateObject(
			context.Background(),
			admodel.UpdateObjectRequest{Identity: InternalObjectTestIdentity(), Changes: changes},
		)
		if !errors.Is(err, admodel.ErrInvalidObjectMutation) ||
			result.State != admodel.ObjectWriteNotAttempted {
			t.Fatalf("%+v %v", result, err)
		}
	}
	if _, err := client.RenameObject(
		context.Background(),
		admodel.RenameObjectRequest{Identity: InternalObjectTestIdentity(), Name: "bad\x00"},
	); !errors.Is(
		err,
		admodel.ErrInvalidObjectMutation,
	) {
		t.Fatal(err)
	}
	if _, err := client.CreateObject(
		context.Background(),
		admodel.CreateObjectRequest{
			Parent:  InternalObjectTestIdentity(),
			Class:   "container",
			Name:    "x",
			Options: admodel.ObjectMutationOptions{ExpectedVersion: &admodel.ObjectVersion{}},
		},
	); !errors.Is(
		err,
		admodel.ErrObjectControlUnsupported,
	) {
		t.Fatal(err)
	}
}

func TestCreateObjectSchemaInheritanceEscapedNameAndReadback(t *testing.T) {
	name := " #Jörg, 李+ "
	wantDN := `cn=\ #Jörg\, 李\+\ ,CN=sample,DC=example`
	reads, writes := 0, 0
	client := InternalObjectTestClient(
		t,
		nil,
		func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			reads++
			switch reads {
			case 1:
				return InternalObjectTestCursor(
					InternalObjectTestEntry("CN=sample,DC=example"),
				), nil
			case 2:
				if query.Scope != admodel.ScopeOneLevel ||
					query.Filter != "(&(objectClass=classSchema)(lDAPDisplayName=customContainer))" {
					t.Fatal(query)
				}
				return InternalObjectTestCursor(
					admodel.Object{
						Attributes: map[string][][]byte{
							"objectclasscategory": {[]byte("1")},
							"subclassof":          {[]byte("container")},
						},
					},
				), nil
			case 3:
				return InternalObjectTestCursor(
					admodel.Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}}},
				), nil
			case 4:
				if query.Base != wantDN || query.Scope != admodel.ScopeBase {
					t.Fatal(query)
				}
				entry := InternalObjectTestEntry(wantDN)
				entry.Attributes["cn"] = [][]byte{[]byte(name)}
				entry.Attributes["photo"] = [][]byte{{0, 0xff}}
				entry.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("customContainer")}
				return InternalObjectTestCursor(entry), nil
			default:
				t.Fatal("unexpected read")
				return nil, nil
			}
		},
		func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			writes++
			if request.InternalOperation != admodel.InternalLdapWriteAdd ||
				request.InternalDn != wantDN ||
				len(request.InternalModifications) != 3 ||
				!bytes.Equal(request.InternalModifications[0].InternalValues[0], []byte{0, 0xff}) ||
				string(request.InternalModifications[2].InternalValues[0]) != name {
				t.Fatalf("%+v", request)
			}
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
		},
	)
	result, err := client.CreateObject(
		context.Background(),
		admodel.CreateObjectRequest{
			Parent: InternalObjectTestIdentity(),
			Class:  "customContainer",
			Name:   name,
			Attributes: map[string][]admodel.RawValue{
				"photo": {admodel.NewRawValue([]byte{0, 0xff})},
			},
		},
	)
	if err != nil || result.State != admodel.ObjectWriteAccepted || result.Before != nil ||
		!result.ReadbackComplete ||
		result.After == nil ||
		result.TargetGUID == nil ||
		writes != 1 {
		t.Fatalf("%+v %v writes=%d", result, err, writes)
	}
}

func TestObjectWriteUsesResolvedGUIDAndPreservesReadback(t *testing.T) {
	for _, rename := range []bool{false, true} {
		reads, writes := 0, 0
		client := InternalObjectTestClient(
			t,
			nil,
			func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				reads++
				if reads == 1 {
					return InternalObjectTestCursor(
						InternalObjectTestEntry("CN=sample,DC=example"),
					), nil
				}
				if query.Scope != admodel.ScopeSubtree ||
					query.Filter != `(objectGUID=\33\22\11\00\55\44\77\66\88\99\aa\bb\cc\dd\ee\ff)` {
					t.Fatal(query)
				}
				return InternalObjectTestCursor(
					InternalObjectTestEntry(`CN=Renamed\, 李,DC=example`),
				), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if request.InternalDn != "<GUID=33221100554477668899aabbccddeeff>" {
					t.Fatal(request.InternalDn)
				}
				if rename &&
					(request.InternalOperation != admodel.InternalLdapWriteRename || request.InternalNewRDN != `cn=Renamed\, 李` || !request.InternalDeleteOldRDN) {
					t.Fatalf("%+v", request)
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		var result admodel.ObjectMutationResult
		var err error
		if rename {
			result, err = client.RenameObject(
				context.Background(),
				admodel.RenameObjectRequest{
					Identity: InternalObjectTestIdentity(),
					Name:     "Renamed, 李",
				},
			)
		} else {
			result, err = client.UpdateObject(
				context.Background(),
				admodel.UpdateObjectRequest{
					Identity: InternalObjectTestIdentity(),
					Changes: []admodel.AttributeChange{
						{Attribute: "description", Kind: admodel.AttributeClear},
					},
				},
			)
		}
		if (rename && err != nil) || (!rename && !errors.Is(err, admodel.ErrObjectUnverifiable)) ||
			result.Verified != rename ||
			writes != 1 ||
			!result.ReadbackComplete ||
			result.After == nil ||
			result.Before == nil ||
			result.After.DistinguishedName == result.Before.DistinguishedName {
			t.Fatalf("%+v %v", result, err)
		}
	}
}

func TestObjectWriteOutcomesNeverReplay(t *testing.T) {
	permission := &admodel.LDAPError{
		Code:       50,
		Diagnostic: "private ACL detail",
		MatchedDN:  "DC=example",
	}
	for _, tc := range []struct {
		InternalName    string
		InternalAttempt admodel.InternalLdapWriteAttempt
		InternalWant    error
		InternalState   admodel.ObjectWriteState
	}{
		{"permission", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: permission}, admodel.ErrObjectWritePermission, admodel.ObjectWriteRejected},
		{"schema", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 65}}, nil, admodel.ObjectWriteRejected},
		{"duplicate", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 68}}, admodel.ErrObjectAlreadyExists, admodel.ObjectWriteRejected},
		{"protected", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 53}}, nil, admodel.ObjectWriteRejected},
		{"uncertain", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteUncertain, Err: admodel.InternalLDAPWriteUncertainError()}, admodel.ErrObjectWriteUncertain, admodel.ObjectWriteUncertain},
		{"accepted cleanup failure", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted, Err: context.Canceled}, context.Canceled, admodel.ObjectWriteAccepted},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			reads, writes := 0, 0
			client := InternalObjectTestClient(
				t,
				nil,
				func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					reads++
					return InternalObjectTestCursor(
						InternalObjectTestEntry("CN=sample,DC=example"),
					), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return tc.InternalAttempt
				},
			)
			result, err := client.UpdateObject(
				context.Background(),
				admodel.UpdateObjectRequest{
					Identity: InternalObjectTestIdentity(),
					Changes: []admodel.AttributeChange{
						{Attribute: "description", Kind: admodel.AttributeClear},
					},
				},
			)
			if err == nil || (tc.InternalWant != nil && !errors.Is(err, tc.InternalWant)) ||
				result.State != tc.InternalState ||
				writes != 1 ||
				reads != 1 ||
				result.ReadbackComplete {
				t.Fatalf("%+v %v reads=%d writes=%d", result, err, reads, writes)
			}
			if tc.InternalAttempt.Err == permission {
				var native *admodel.LDAPError
				if !errors.As(err, &native) || native != permission ||
					strings.Contains(err.Error(), permission.Diagnostic) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestObjectDeleteLeafAndPartialTreeResults(t *testing.T) {
	for _, tc := range []struct {
		InternalRecursive bool
		InternalCode      uint32
		InternalAccepted  bool
		InternalPartial   bool
		InternalWant      error
	}{
		{false, 66, false, false, admodel.ErrObjectNotLeaf}, {true, 11, false, true, nil}, {true, 0, true, true, nil}, {false, 0, true, false, nil},
	} {
		writes, reads := 0, 0
		client := InternalObjectTestClient(
			t,
			[]string{admodel.InternalObjectTreeDeleteControl},
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				reads++
				if reads == 1 {
					return InternalObjectTestCursor(
						InternalObjectTestEntry("CN=sample,DC=example"),
					), nil
				}
				return InternalObjectTestCursor(), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if request.InternalOperation != admodel.InternalLdapWriteDelete ||
					len(request.InternalControls) != InternalBoolInt(tc.InternalRecursive) {
					t.Fatalf("%+v", request)
				}
				if tc.InternalRecursive &&
					(request.InternalControls[0].InternalOid != admodel.InternalObjectTreeDeleteControl || !request.InternalControls[0].InternalCritical || request.InternalControls[0].InternalValue != nil) {
					t.Fatal(request.InternalControls)
				}
				if tc.InternalAccepted {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				}
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err: &admodel.LDAPError{
						Code:       tc.InternalCode,
						Diagnostic: "000020B3: ERROR_DS_TREE_DELETE_NOT_FINISHED",
					},
				}
			},
		)
		result, err := client.DeleteObject(
			context.Background(),
			admodel.DeleteObjectRequest{
				Identity:  InternalObjectTestIdentity(),
				Recursive: tc.InternalRecursive,
			},
		)
		if writes != 1 || result.PartialEffectsPossible != tc.InternalPartial ||
			result.AbsentAfter != tc.InternalAccepted ||
			result.ReadbackComplete != tc.InternalAccepted ||
			(tc.InternalWant != nil && !errors.Is(err, tc.InternalWant)) ||
			(tc.InternalAccepted && err != nil) {
			t.Fatalf("%+v %v", result, err)
		}
		if !tc.InternalAccepted {
			var native *admodel.LDAPError
			if !errors.As(err, &native) || native.Code != tc.InternalCode || reads != 1 {
				t.Fatalf("%+v %v reads=%d", result, err, reads)
			}
		}
	}
}

func InternalBoolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestObjectVersionAssertionsAndUnsupportedGuards(t *testing.T) {
	version := admodel.ObjectVersion{
		Source:     admodel.Endpoint{Host: "dc.example", Port: 389},
		GUID:       InternalObjectTestGUID(),
		USNChanged: 7,
	}
	want, _ := hex.DecodeString(
		"a031a31e040a6f626a65637447554944041033221100554477668899aabbccddeeffa30f040a75534e4368616e676564040137",
	)
	if got := admodel.InternalObjectVersionAssertion(version); !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	for _, tc := range []struct {
		InternalControls  []string
		InternalVersion   admodel.ObjectVersion
		InternalRecursive bool
		InternalWant      error
	}{
		{nil, version, false, admodel.ErrObjectControlUnsupported},
		{[]string{admodel.InternalObjectAssertionControl}, version, false, admodel.ErrObjectConcurrency},
		{[]string{admodel.InternalObjectAssertionControl, admodel.InternalObjectTreeDeleteControl}, version, true, admodel.ErrObjectControlUnsupported},
		{[]string{admodel.InternalObjectAssertionControl}, admodel.ObjectVersion{Source: admodel.Endpoint{Host: "other.example", Port: 389}, GUID: InternalObjectTestGUID()}, false, admodel.ErrObjectConcurrency},
	} {
		writes := 0
		client := InternalObjectTestClient(
			t,
			tc.InternalControls,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				return InternalObjectTestCursor(
					InternalObjectTestEntry("CN=sample,DC=example"),
				), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if !reflect.DeepEqual(
					request.InternalControls,
					[]admodel.InternalLdapWriteControl{
						{
							InternalOid:      admodel.InternalObjectAssertionControl,
							InternalCritical: true,
							InternalValue:    want,
						},
					},
				) {
					t.Fatal(request.InternalControls)
				}
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: 122},
				}
			},
		)
		result, err := client.DeleteObject(
			context.Background(),
			admodel.DeleteObjectRequest{
				Identity:  InternalObjectTestIdentity(),
				Recursive: tc.InternalRecursive,
				Options:   admodel.ObjectMutationOptions{ExpectedVersion: &tc.InternalVersion},
			},
		)
		if !errors.Is(err, tc.InternalWant) ||
			(writes > 0 && result.State != admodel.ObjectWriteRejected) ||
			writes > 1 {
			t.Fatalf("%+v %v writes=%d", result, err, writes)
		}
	}
}

func TestObjectMutationScopeCancellationAndReadbackFailure(t *testing.T) {
	reads, writes := 0, 0
	client := InternalObjectTestClient(
		t,
		nil,
		func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			reads++
			if reads == 1 {
				return InternalObjectTestCursor(
					InternalObjectTestEntry("CN=sample,DC=example"),
				), nil
			}
			return nil, &admodel.LDAPError{Code: 50}
		},
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			writes++
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
		},
	)
	wrong, _ := admodel.IdentityByDN("CN=sample,DC=other")
	if result, err := client.DeleteObject(
		context.Background(),
		admodel.DeleteObjectRequest{Identity: wrong},
	); !errors.Is(err, admodel.ErrIdentityScope) || result.State != admodel.ObjectWriteNotAttempted || writes != 0 ||
		reads != 0 {
		t.Fatalf("%+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.DeleteObject(
		ctx,
		admodel.DeleteObjectRequest{Identity: InternalObjectTestIdentity()},
	); !errors.Is(err, context.Canceled) ||
		writes != 0 {
		t.Fatal(err)
	}
	result, err := client.RenameObject(
		context.Background(),
		admodel.RenameObjectRequest{Identity: InternalObjectTestIdentity(), Name: "new"},
	)
	if !errors.Is(err, admodel.ErrObjectReadback) ||
		!errors.Is(err, admodel.ErrObjectWritePermission) ||
		result.State != admodel.ObjectWriteAccepted ||
		result.ReadbackComplete ||
		writes != 1 {
		t.Fatalf("%+v %v writes=%d", result, err, writes)
	}
}

func TestObjectMutationLDSArbitraryPorts(t *testing.T) {
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		for _, port := range []uint16{3268, 3269} {
			reads, writes := 0, 0
			client := InternalObjectTestClient(
				t,
				nil,
				func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					reads++
					if reads == 1 {
						return InternalObjectTestCursor(
							InternalObjectTestEntry("CN=sample,DC=example"),
						), nil
					}
					return InternalObjectTestCursor(), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = port
			session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
			session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
				return InternalIdentityTestRoot(kind), nil
			}
			(*adengine.InternalClientSessionPointer(client)) = session
			result, err := client.DeleteObject(
				context.Background(),
				admodel.DeleteObjectRequest{Identity: InternalObjectTestIdentity()},
			)
			if kind == admodel.CapabilityActiveDirectory {
				if !errors.Is(err, admodel.ErrObjectWriteTarget) || writes != 0 {
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
		if name == "" || !admodel.InternalValidDirectoryText(name) {
			return
		}
		parsed, err := admodel.InternalParseIdentityDN(
			"CN=" + admodel.InternalEscapeObjectName(name) + ",DC=example",
		)
		if err != nil || len(parsed) != 2 || len(parsed[0]) != 1 ||
			parsed[0][0].InternalValue != name {
			t.Fatalf("%q: %+v %v", name, parsed, err)
		}
	})
}
