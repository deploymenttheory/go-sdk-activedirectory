package activedirectory

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const restorationDSA = "CN=NTDS Settings,CN=DC,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=example"
const restorationFeatureDN = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=example"
const restorationDeletedDN = `CN=Jörg\, 李\0ADEL:00112233-4455-6677-8899-aabbccddeeff,CN=Deleted Objects,DC=example`

type restorationTestSession struct {
	objectWriteTestSession
	controlled func(context.Context, SearchOptions, []ldapWriteControl) (searchCursor, error)
}

func (s restorationTestSession) startSearchControls(ctx context.Context, options SearchOptions, controls []ldapWriteControl) (searchCursor, error) {
	return s.controlled(ctx, options, controls)
}

func restorationDeletedEntry() Object {
	object := objectTestEntry(restorationDeletedDN)
	object.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("person"), []byte("user")}
	object.Attributes["isdeleted"] = [][]byte{[]byte("TRUE")}
	object.Attributes["lastknownparent"] = [][]byte{[]byte("OU=People,DC=example")}
	object.Attributes["msds-lastknownrdn"] = [][]byte{[]byte("Jörg, 李")}
	return object
}

func restorationTestClient(t *testing.T, kind string, search func(context.Context, SearchOptions) (searchCursor, error), controlled func(context.Context, SearchOptions, []ldapWriteControl) (searchCursor, error), write func(context.Context, ldapWriteRequest) ldapWriteAttempt) *Client {
	t.Helper()
	client := objectTestClient(t, nil, search, write)
	session := client.session.(objectWriteTestSession)
	session.read = func(context.Context, []string) (map[string][][]byte, error) {
		root := identityTestRoot(kind)
		root["configurationnamingcontext"] = [][]byte{[]byte("CN=Configuration,DC=example")}
		root["dsservicename"] = [][]byte{[]byte(restorationDSA)}
		root["supportedcontrol"] = [][]byte{[]byte(objectShowDeletedControl), []byte(objectShowRecycledControl), []byte(objectShowDeactivatedLinksControl), []byte(objectAssertionControl)}
		return root, nil
	}
	client.session = restorationTestSession{objectWriteTestSession: session, controlled: controlled}
	return client
}

func restorationFeatureCursor(options SearchOptions, mode string) (searchCursor, bool) {
	if options.Base == restorationDSA {
		object := objectTestEntry(restorationDSA)
		object.Attributes["msds-enabledfeature"] = [][]byte{[]byte(restorationFeatureDN)}
		if mode == "feature-hidden" {
			delete(object.Attributes, "msds-enabledfeature")
		}
		if mode == "feature-range" {
			delete(object.Attributes, "msds-enabledfeature")
			object.Attributes["msds-enabledfeature;range=0-0"] = [][]byte{[]byte(restorationFeatureDN)}
		}
		return objectTestCursor(object), true
	}
	if options.Base == restorationFeatureDN {
		object := objectTestEntry(restorationFeatureDN)
		guid, _ := ParseGUID(OptionalFeatureRecycleBinGUID)
		if mode == "feature-disabled" {
			guid = objectTestGUID()
		}
		object.Attributes["msds-optionalfeatureguid"] = [][]byte{guid.Bytes()}
		return objectTestCursor(object), true
	}
	return nil, false
}

func TestRestoreObjectTargetsGUIDAndSingleNativeOutcome(t *testing.T) {
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		for _, mode := range []string{"defaults", "new-name", "new-parent", "conditional", "denied", "conflict", "uncertain", "wrong-guid", "moved", "still-deleted", "still-recycled", "missing-parent", "recycled", "unavailable", "protected", "hidden-name", "feature-hidden", "feature-range", "feature-disabled", "unsupported-assertion"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				writes, deletedReads, readbacks := 0, 0, 0
				identity, _ := IdentityByGUID(objectTestGUID().String())
				request := RestoreObjectRequest{Identity: identity, Options: ObjectMutationOptions{Properties: []string{"description"}}}
				want := `cn=Jörg\, 李,OU=People,DC=example`
				if mode == "new-name" {
					name := ` literal*)(cn=*) `
					request.NewName = &name
					want = `cn=\ literal*)(cn\=*)\ ,OU=People,DC=example`
				}
				if mode == "new-parent" {
					request.TargetParent, _ = IdentityByDN("OU=Elsewhere,DC=example")
					want = `cn=Jörg\, 李,OU=Elsewhere,DC=example`
				}
				if mode == "unsupported-assertion" || mode == "conditional" {
					request.Options.ExpectedVersion = &ObjectVersion{Source: Endpoint{Host: "dc.example", Port: 389}, GUID: objectTestGUID(), USNChanged: 7}
				}
				var client *Client
				client = restorationTestClient(t, kind, func(_ context.Context, options SearchOptions) (searchCursor, error) {
					if cursor, ok := restorationFeatureCursor(options, mode); ok {
						return cursor, nil
					}
					if strings.HasPrefix(options.Base, "OU=") {
						if mode == "missing-parent" {
							return objectTestCursor(), nil
						}
						return objectTestCursor(objectTestEntry(options.Base)), nil
					}
					readbacks++
					if writes != 1 || !strings.Contains(options.Filter, "objectGUID=") || !slices.Contains(options.Properties, "description") {
						t.Fatal(options, writes)
					}
					object := objectTestEntry(want)
					if mode == "wrong-guid" {
						guid, _ := ParseGUID("11112233-4455-6677-8899-aabbccddeeff")
						object.Attributes["objectguid"] = [][]byte{guid.Bytes()}
					}
					if mode == "moved" {
						object.DistinguishedName = "CN=somewhere,DC=example"
					}
					if mode == "still-deleted" {
						object.Attributes["isdeleted"] = [][]byte{[]byte("TRUE")}
					}
					if mode == "still-recycled" {
						object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
					}
					return objectTestCursor(object), nil
				}, func(_ context.Context, options SearchOptions, controls []ldapWriteControl) (searchCursor, error) {
					deletedReads++
					if len(controls) != 1 || !controls[0].critical || len(controls[0].value) != 0 {
						t.Fatal(controls)
					}
					object := restorationDeletedEntry()
					if controls[0].oid == objectShowDeletedControl && (mode == "recycled" || mode == "unavailable") {
						return objectTestCursor(), nil
					}
					if controls[0].oid == objectShowRecycledControl {
						if mode == "unavailable" {
							return objectTestCursor(), nil
						}
						object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
					}
					if mode == "protected" {
						object.Attributes["systemflags"] = [][]byte{[]byte("-2147483648")}
					}
					if mode == "hidden-name" {
						delete(object.Attributes, "msds-lastknownrdn")
					}
					return objectTestCursor(object), nil
				}, func(_ context.Context, write ldapWriteRequest) ldapWriteAttempt {
					writes++
					controlCount := 1
					if mode == "conditional" {
						controlCount = 2
					}
					if write.operation != ldapWriteModify || write.dn != objectGUIDTarget(objectTestGUID()) || len(write.modifications) != 2 || write.modifications[0].operation != 1 || write.modifications[0].attribute != "isDeleted" || len(write.modifications[0].values) != 0 || write.modifications[1].operation != 2 || write.modifications[1].attribute != "distinguishedName" || string(write.modifications[1].values[0]) != want || len(write.controls) != controlCount || write.controls[0].oid != objectShowDeletedControl || !write.controls[0].critical {
						t.Fatalf("write=%+v, target=%q want=%q", write, string(write.modifications[1].values[0]), want)
					}
					if mode == "conditional" && (write.controls[1].oid != objectAssertionControl || !write.controls[1].critical || !reflect.DeepEqual(write.controls[1].value, objectVersionAssertion(*request.Options.ExpectedVersion))) {
						t.Fatal(write.controls)
					}
					switch mode {
					case "denied":
						return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50, Diagnostic: "test denied"}}
					case "conflict":
						return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 68}}
					case "uncertain":
						return ldapWriteAttempt{State: ldapWriteUncertain, Err: context.DeadlineExceeded}
					}
					return ldapWriteAttempt{State: ldapWriteAccepted}
				})
				if mode == "unsupported-assertion" {
					session := client.session.(restorationTestSession)
					original := session.read
					session.read = func(ctx context.Context, p []string) (map[string][][]byte, error) {
						root, err := original(ctx, p)
						root["supportedcontrol"] = root["supportedcontrol"][:3]
						return root, err
					}
					client.session = session
				}
				result, err := client.RestoreObject(context.Background(), request)
				switch mode {
				case "defaults", "new-name", "new-parent", "conditional":
					if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted || writes != 1 || readbacks != 1 || result.Deleted.State != DeletedStateDeleted || *result.Mutation.TargetGUID != objectTestGUID() {
						t.Fatal(result, err, writes, readbacks)
					}
				case "denied", "conflict", "uncertain":
					wantState := ObjectWriteRejected
					wantedErr := ErrObjectWritePermission
					if mode == "conflict" {
						wantedErr = ErrObjectAlreadyExists
					}
					if mode == "uncertain" {
						wantState = ObjectWriteUncertain
						wantedErr = ErrObjectWriteUncertain
					}
					if !errors.Is(err, wantedErr) || result.Mutation.State != wantState || writes != 1 || readbacks != 0 || result.Mutation.Verified {
						t.Fatal(result, err, writes, readbacks)
					}
				case "wrong-guid", "moved", "still-deleted", "still-recycled":
					if err == nil || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || writes != 1 || readbacks != 1 {
						t.Fatal(result, err)
					}
				default:
					if err == nil || writes != 0 || result.Mutation.State != ObjectWriteNotAttempted {
						t.Fatal(result, err, writes)
					}
					if strings.HasPrefix(mode, "feature-") && (!errors.Is(err, ErrObjectRestoreFeature) || deletedReads != 0) {
						t.Fatal(result, err, deletedReads)
					}
					if mode == "recycled" && (deletedReads != 2 || result.Deleted.State != DeletedStateRecycled) {
						t.Fatal(result, err, deletedReads)
					}
					if mode == "unavailable" && (!errors.Is(err, ErrDeletedObjectUnavailable) || result.Deleted != nil) {
						t.Fatal(result, err)
					}
				}
			})
		}
	}
}

func TestDeletedObjectsControlsPartialResultsAndUnknownFeatures(t *testing.T) {
	for _, mode := range []string{"complete", "limit", "native-partial", "ranged-values", "feature-hidden", "recycled", "recycled-hidden"} {
		t.Run(mode, func(t *testing.T) {
			closed, pages := 0, 0
			query := DeletedObjectQuery{Search: SearchOptions{Base: "DC=example", Scope: ScopeSubtree, Filter: "(description=literal)", Properties: []string{"description"}, PageSize: 1}, IncludeRecycled: strings.HasPrefix(mode, "recycled"), IncludeDeactivatedLinks: true}
			if mode == "limit" {
				query.Search.ResultLimit = 1
			}
			client := restorationTestClient(t, CapabilityActiveDirectory, func(_ context.Context, options SearchOptions) (searchCursor, error) {
				if cursor, ok := restorationFeatureCursor(options, mode); ok {
					return cursor, nil
				}
				t.Fatal(options)
				return nil, ErrInvalidResult
			}, func(_ context.Context, options SearchOptions, controls []ldapWriteControl) (searchCursor, error) {
				oid := objectShowDeletedControl
				if strings.HasPrefix(mode, "recycled") {
					oid = objectShowRecycledControl
				}
				if len(controls) != 2 || controls[0].oid != oid || controls[1].oid != objectShowDeactivatedLinksControl || !controls[0].critical || !controls[1].critical || options.Filter != "(&(isDeleted=TRUE)(description=literal))" || !slices.Contains(options.Properties, "description") {
					t.Fatal(options, controls)
				}
				return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
					pages++
					object := restorationDeletedEntry()
					object.DistinguishedName = strings.Replace(object.DistinguishedName, "Jörg", "Jörg"+strings.Repeat("x", pages), 1)
					if mode == "recycled" {
						object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
					}
					if mode == "ranged-values" {
						object.Attributes["member;range=0-0"] = [][]byte{[]byte("CN=first,DC=example")}
						return []Object{object}, false, ErrIncompleteResult
					}
					if mode == "native-partial" {
						return []Object{object}, false, &LDAPError{Code: 50}
					}
					return []Object{object}, pages == 2, nil
				}, finish: func() error { closed++; return nil }}, nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				t.Fatal("discovery wrote")
				return ldapWriteAttempt{}
			})
			result, err := client.DeletedObjects(context.Background(), query)
			if len(result.Objects) == 0 || len(result.Objects) != len(result.Observation.Objects) || closed != 1 {
				t.Fatal(result, err, closed)
			}
			switch mode {
			case "complete", "recycled", "recycled-hidden":
				if err != nil || !result.Complete || pages != 2 {
					t.Fatal(result, err)
				}
			case "limit":
				if err != nil || result.Complete || !result.Observation.LimitReached || pages != 1 {
					t.Fatal(result, err)
				}
			default:
				if err == nil || result.Complete {
					t.Fatal(result, err)
				}
			}
			if mode == "feature-hidden" && (result.Capabilities.RecycleBinEnabled != nil || result.Objects[0].State != DeletedStateUnknown) {
				t.Fatal(result)
			}
			if mode == "recycled" && result.Objects[0].State != DeletedStateRecycled {
				t.Fatal(result.Objects)
			}
			if mode == "recycled-hidden" && (result.Objects[0].State != DeletedStateUnknown || result.Objects[0].IsRecycled != nil) {
				t.Fatal(result.Objects)
			}
		})
	}
}

func TestRestoreValidationScopeAndDeadline(t *testing.T) {
	var nilClient *Client
	identity := objectTestIdentity()
	empty, bad := "", "bad\x00"
	for _, request := range []RestoreObjectRequest{{}, {Identity: identity, NewName: &empty}, {Identity: identity, NewName: &bad}, {Identity: identity, Options: ObjectMutationOptions{Properties: []string{"1.1"}}}} {
		if _, err := nilClient.RestoreObject(context.Background(), request); err == nil || errors.Is(err, ErrClosed) {
			t.Fatal(request, err)
		}
	}
	if _, err := nilClient.RestoreObject(context.Background(), RestoreObjectRequest{Identity: identity}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	parent, _ := IdentityByDN("OU=outside,DC=app")
	for _, mode := range []string{"cross-partition", "canceled-feature", "gc", "missing-control"} {
		t.Run(mode, func(t *testing.T) {
			writes := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := restorationTestClient(t, CapabilityActiveDirectory, func(_ context.Context, options SearchOptions) (searchCursor, error) {
				if mode == "canceled-feature" {
					cancel()
					return objectTestCursor(), context.Canceled
				}
				cursor, ok := restorationFeatureCursor(options, "")
				if !ok {
					t.Fatal(options)
				}
				return cursor, nil
			}, func(context.Context, SearchOptions, []ldapWriteControl) (searchCursor, error) {
				return objectTestCursor(restorationDeletedEntry()), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				writes++
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			if mode == "gc" {
				client.config.Endpoint.Port = 3268
			}
			if mode == "missing-control" {
				session := client.session.(restorationTestSession)
				original := session.read
				session.read = func(ctx context.Context, p []string) (map[string][][]byte, error) {
					root, err := original(ctx, p)
					delete(root, "supportedcontrol")
					return root, err
				}
				client.session = session
			}
			result, err := client.RestoreObject(ctx, RestoreObjectRequest{Identity: identity, TargetParent: parent})
			if err == nil || writes != 0 || result.Mutation.State != ObjectWriteNotAttempted {
				t.Fatal(result, err, writes)
			}
		})
	}
	// Typed metadata never aliases requested property slices.
	extra := make([]string, 1, 20)
	extra[0] = "description"
	copyOf := slices.Clone(extra)
	_ = restorationProperties(extra)
	if !reflect.DeepEqual(extra, copyOf) {
		t.Fatal(extra)
	}
	client := restorationTestClient(t, CapabilityActiveDirectory, func(ctx context.Context, _ SearchOptions) (searchCursor, error) {
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}, func(context.Context, SearchOptions, []ldapWriteControl) (searchCursor, error) {
		t.Fatal("timeout dispatched deleted lookup")
		return nil, ErrInvalidResult
	}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		t.Fatal("timeout wrote")
		return ldapWriteAttempt{}
	})
	client.config.Timeout = 5 * time.Millisecond
	result, err := client.RestoreObject(context.Background(), RestoreObjectRequest{Identity: identity})
	if !errors.Is(err, context.DeadlineExceeded) || result.Mutation.State != ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
}
