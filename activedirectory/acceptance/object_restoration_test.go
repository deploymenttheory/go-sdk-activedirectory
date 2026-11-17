package acceptance

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_object_restoration "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/object_restoration"
)

const (
	InternalRestorationDSA       = "CN=NTDS Settings,CN=DC,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=example"
	InternalRestorationFeatureDN = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=example"
	InternalRestorationDeletedDN = `CN=Jörg\, 李\0ADEL:00112233-4455-6677-8899-aabbccddeeff,CN=Deleted Objects,DC=example`
)

type InternalRestorationTestSession struct {
	InternalObjectWriteTestSession
	InternalControlled func(context.Context, admodel.SearchOptions, []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error)
}

func (s InternalRestorationTestSession) InternalStartSearchControls(
	ctx context.Context,
	options admodel.SearchOptions,
	controls []admodel.InternalLdapWriteControl,
) (admodel.InternalSearchCursor, error) {
	return s.InternalControlled(ctx, options, controls)
}

func InternalRestorationDeletedEntry() admodel.Object {
	object := InternalObjectTestEntry(InternalRestorationDeletedDN)
	object.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("person"), []byte("user")}
	object.Attributes["isdeleted"] = [][]byte{[]byte("TRUE")}
	object.Attributes["lastknownparent"] = [][]byte{[]byte("OU=People,DC=example")}
	object.Attributes["msds-lastknownrdn"] = [][]byte{[]byte("Jörg, 李")}
	return object
}

func InternalRestorationTestClient(
	t *testing.T,
	kind string,
	search func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error),
	controlled func(context.Context, admodel.SearchOptions, []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error),
	write func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt,
) *adengine.Client {
	t.Helper()
	client := InternalObjectTestClient(t, nil, search, write)
	session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
	session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
		root := InternalIdentityTestRoot(kind)
		root["configurationnamingcontext"] = [][]byte{[]byte("CN=Configuration,DC=example")}
		root["dsservicename"] = [][]byte{[]byte(InternalRestorationDSA)}
		root["supportedcontrol"] = [][]byte{
			[]byte(admodel.InternalObjectShowDeletedControl),
			[]byte(admodel.InternalObjectShowRecycledControl),
			[]byte(admodel.InternalObjectShowDeactivatedLinksControl),
			[]byte(admodel.InternalObjectAssertionControl),
		}
		return root, nil
	}
	(*adengine.InternalClientSessionPointer(client)) = InternalRestorationTestSession{
		InternalObjectWriteTestSession: session,
		InternalControlled:             controlled,
	}
	return client
}

func InternalRestorationFeatureCursor(
	options admodel.SearchOptions,
	mode string,
) (admodel.InternalSearchCursor, bool) {
	if options.Base == InternalRestorationDSA {
		object := InternalObjectTestEntry(InternalRestorationDSA)
		object.Attributes["msds-enabledfeature"] = [][]byte{[]byte(InternalRestorationFeatureDN)}
		if mode == "feature-hidden" {
			delete(object.Attributes, "msds-enabledfeature")
		}
		if mode == "feature-range" {
			delete(object.Attributes, "msds-enabledfeature")
			object.Attributes["msds-enabledfeature;range=0-0"] = [][]byte{
				[]byte(InternalRestorationFeatureDN),
			}
		}
		return InternalObjectTestCursor(object), true
	}
	if options.Base == InternalRestorationFeatureDN {
		object := InternalObjectTestEntry(InternalRestorationFeatureDN)
		guid, _ := admodel.ParseGUID(admodel.OptionalFeatureRecycleBinGUID)
		if mode == "feature-disabled" {
			guid = InternalObjectTestGUID()
		}
		object.Attributes["msds-optionalfeatureguid"] = [][]byte{guid.Bytes()}
		return InternalObjectTestCursor(object), true
	}
	return nil, false
}

func TestRestoreObjectTargetsGUIDAndSingleNativeOutcome(t *testing.T) {
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		for _, mode := range []string{"defaults", "new-name", "new-parent", "conditional", "denied", "conflict", "uncertain", "wrong-guid", "moved", "still-deleted", "still-recycled", "missing-parent", "recycled", "unavailable", "protected", "hidden-name", "feature-hidden", "feature-range", "feature-disabled", "unsupported-assertion"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				writes, deletedReads, readbacks := 0, 0, 0
				identity, _ := admodel.IdentityByGUID(InternalObjectTestGUID().String())
				request := admodel.RestoreObjectRequest{
					Identity: identity,
					Options:  admodel.ObjectMutationOptions{Properties: []string{"description"}},
				}
				want := `cn=Jörg\, 李,OU=People,DC=example`
				if mode == "new-name" {
					name := ` literal*)(cn=*) `
					request.NewName = &name
					want = `cn=\ literal*)(cn\=*)\ ,OU=People,DC=example`
				}
				if mode == "new-parent" {
					request.TargetParent, _ = admodel.IdentityByDN("OU=Elsewhere,DC=example")
					want = `cn=Jörg\, 李,OU=Elsewhere,DC=example`
				}
				if mode == "unsupported-assertion" || mode == "conditional" {
					request.Options.ExpectedVersion = &admodel.ObjectVersion{
						Source:     admodel.Endpoint{Host: "dc.example", Port: 389},
						GUID:       InternalObjectTestGUID(),
						USNChanged: 7,
					}
				}
				var client *adengine.Client
				client = InternalRestorationTestClient(
					t,
					kind,
					func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						if cursor, ok := InternalRestorationFeatureCursor(options, mode); ok {
							return cursor, nil
						}
						if strings.HasPrefix(options.Base, "OU=") {
							if mode == "missing-parent" {
								return InternalObjectTestCursor(), nil
							}
							return InternalObjectTestCursor(
								InternalObjectTestEntry(options.Base),
							), nil
						}
						readbacks++
						if writes != 1 || !strings.Contains(options.Filter, "objectGUID=") ||
							!slices.Contains(options.Properties, "description") {
							t.Fatal(options, writes)
						}
						object := InternalObjectTestEntry(want)
						if mode == "wrong-guid" {
							guid, _ := admodel.ParseGUID("11112233-4455-6677-8899-aabbccddeeff")
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
						return InternalObjectTestCursor(object), nil
					},
					func(_ context.Context, options admodel.SearchOptions, controls []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error) {
						deletedReads++
						if len(controls) != 1 || !controls[0].InternalCritical ||
							len(controls[0].InternalValue) != 0 {
							t.Fatal(controls)
						}
						object := InternalRestorationDeletedEntry()
						if controls[0].InternalOid == admodel.InternalObjectShowDeletedControl &&
							(mode == "recycled" || mode == "unavailable") {
							return InternalObjectTestCursor(), nil
						}
						if controls[0].InternalOid == admodel.InternalObjectShowRecycledControl {
							if mode == "unavailable" {
								return InternalObjectTestCursor(), nil
							}
							object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
						}
						if mode == "protected" {
							object.Attributes["systemflags"] = [][]byte{[]byte("-2147483648")}
						}
						if mode == "hidden-name" {
							delete(object.Attributes, "msds-lastknownrdn")
						}
						return InternalObjectTestCursor(object), nil
					},
					func(_ context.Context, write admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						writes++
						controlCount := 1
						if mode == "conditional" {
							controlCount = 2
						}
						if write.InternalOperation != admodel.InternalLdapWriteModify ||
							write.InternalDn != admodel.InternalObjectGUIDTarget(
								InternalObjectTestGUID(),
							) ||
							len(write.InternalModifications) != 2 ||
							write.InternalModifications[0].InternalOperation != 1 ||
							write.InternalModifications[0].InternalAttribute != "isDeleted" ||
							len(write.InternalModifications[0].InternalValues) != 0 ||
							write.InternalModifications[1].InternalOperation != 2 ||
							write.InternalModifications[1].InternalAttribute != "distinguishedName" ||
							string(write.InternalModifications[1].InternalValues[0]) != want ||
							len(write.InternalControls) != controlCount ||
							write.InternalControls[0].InternalOid != admodel.InternalObjectShowDeletedControl ||
							!write.InternalControls[0].InternalCritical {
							t.Fatalf(
								"write=%+v, target=%q want=%q",
								write,
								string(write.InternalModifications[1].InternalValues[0]),
								want,
							)
						}
						if mode == "conditional" &&
							(write.InternalControls[1].InternalOid != admodel.InternalObjectAssertionControl || !write.InternalControls[1].InternalCritical || !reflect.DeepEqual(write.InternalControls[1].InternalValue, admodel.InternalObjectVersionAssertion(*request.Options.ExpectedVersion))) {
							t.Fatal(write.InternalControls)
						}
						switch mode {
						case "denied":
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteRejected,
								Err:   &admodel.LDAPError{Code: 50, Diagnostic: "test denied"},
							}
						case "conflict":
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteRejected,
								Err:   &admodel.LDAPError{Code: 68},
							}
						case "uncertain":
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteUncertain,
								Err:   context.DeadlineExceeded,
							}
						}
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteAccepted,
						}
					},
				)
				if mode == "unsupported-assertion" {
					session := adengine.InternalClientSession(client).(InternalRestorationTestSession)
					original := session.InternalRead
					session.InternalRead = func(ctx context.Context, p []string) (map[string][][]byte, error) {
						root, err := original(ctx, p)
						root["supportedcontrol"] = root["supportedcontrol"][:3]
						return root, err
					}
					(*adengine.InternalClientSessionPointer(client)) = session
				}
				result, err := adservice_object_restoration.New(client).
					RestoreObject(context.Background(), request)
				switch mode {
				case "defaults", "new-name", "new-parent", "conditional":
					if err != nil || !result.Mutation.Verified ||
						result.Mutation.State != admodel.ObjectWriteAccepted ||
						writes != 1 ||
						readbacks != 1 ||
						result.Deleted.State != admodel.DeletedStateDeleted ||
						*result.Mutation.TargetGUID != InternalObjectTestGUID() {
						t.Fatal(result, err, writes, readbacks)
					}
				case "denied", "conflict", "uncertain":
					wantState := admodel.ObjectWriteRejected
					wantedErr := admodel.ErrObjectWritePermission
					if mode == "conflict" {
						wantedErr = admodel.ErrObjectAlreadyExists
					}
					if mode == "uncertain" {
						wantState = admodel.ObjectWriteUncertain
						wantedErr = admodel.ErrObjectWriteUncertain
					}
					if !errors.Is(err, wantedErr) || result.Mutation.State != wantState ||
						writes != 1 ||
						readbacks != 0 ||
						result.Mutation.Verified {
						t.Fatal(result, err, writes, readbacks)
					}
				case "wrong-guid", "moved", "still-deleted", "still-recycled":
					if err == nil || result.Mutation.State != admodel.ObjectWriteAccepted ||
						result.Mutation.Verified ||
						writes != 1 ||
						readbacks != 1 {
						t.Fatal(result, err)
					}
				default:
					if err == nil || writes != 0 ||
						result.Mutation.State != admodel.ObjectWriteNotAttempted {
						t.Fatal(result, err, writes)
					}
					if strings.HasPrefix(mode, "feature-") &&
						(!errors.Is(err, admodel.ErrObjectRestoreFeature) || deletedReads != 0) {
						t.Fatal(result, err, deletedReads)
					}
					if mode == "recycled" &&
						(deletedReads != 2 || result.Deleted.State != admodel.DeletedStateRecycled) {
						t.Fatal(result, err, deletedReads)
					}
					if mode == "unavailable" &&
						(!errors.Is(err, admodel.ErrDeletedObjectUnavailable) || result.Deleted != nil) {
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
			query := admodel.DeletedObjectQuery{
				Search: admodel.SearchOptions{
					Base:       "DC=example",
					Scope:      admodel.ScopeSubtree,
					Filter:     "(description=literal)",
					Properties: []string{"description"},
					PageSize:   1,
				},
				IncludeRecycled:         strings.HasPrefix(mode, "recycled"),
				IncludeDeactivatedLinks: true,
			}
			if mode == "limit" {
				query.Search.ResultLimit = 1
			}
			client := InternalRestorationTestClient(
				t,
				admodel.CapabilityActiveDirectory,
				func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if cursor, ok := InternalRestorationFeatureCursor(options, mode); ok {
						return cursor, nil
					}
					t.Fatal(options)
					return nil, admodel.ErrInvalidResult
				},
				func(_ context.Context, options admodel.SearchOptions, controls []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error) {
					oid := admodel.InternalObjectShowDeletedControl
					if strings.HasPrefix(mode, "recycled") {
						oid = admodel.InternalObjectShowRecycledControl
					}
					if len(controls) != 2 || controls[0].InternalOid != oid ||
						controls[1].InternalOid != admodel.InternalObjectShowDeactivatedLinksControl ||
						!controls[0].InternalCritical ||
						!controls[1].InternalCritical ||
						options.Filter != "(&(isDeleted=TRUE)(description=literal))" ||
						!slices.Contains(options.Properties, "description") {
						t.Fatal(options, controls)
					}
					return InternalTestSearchCursor{
						InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
							pages++
							object := InternalRestorationDeletedEntry()
							object.DistinguishedName = strings.Replace(
								object.DistinguishedName,
								"Jörg",
								"Jörg"+strings.Repeat("x", pages),
								1,
							)
							if mode == "recycled" {
								object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
							}
							if mode == "ranged-values" {
								object.Attributes["member;range=0-0"] = [][]byte{
									[]byte("CN=first,DC=example"),
								}
								return []admodel.Object{object}, false, admodel.ErrIncompleteResult
							}
							if mode == "native-partial" {
								return []admodel.Object{object}, false, &admodel.LDAPError{Code: 50}
							}
							return []admodel.Object{object}, pages == 2, nil
						},
						InternalFinish: func() error { closed++; return nil },
					}, nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					t.Fatal("discovery wrote")
					return admodel.InternalLdapWriteAttempt{}
				},
			)
			result, err := adservice_object_restoration.New(client).
				DeletedObjects(context.Background(), query)
			if len(result.Objects) == 0 || len(result.Objects) != len(result.Observation.Objects) ||
				closed != 1 {
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
			if mode == "feature-hidden" &&
				(result.Capabilities.RecycleBinEnabled != nil || result.Objects[0].State != admodel.DeletedStateUnknown) {
				t.Fatal(result)
			}
			if mode == "recycled" && result.Objects[0].State != admodel.DeletedStateRecycled {
				t.Fatal(result.Objects)
			}
			if mode == "recycled-hidden" &&
				(result.Objects[0].State != admodel.DeletedStateUnknown || result.Objects[0].IsRecycled != nil) {
				t.Fatal(result.Objects)
			}
		})
	}
}

func TestRestoreValidationScopeAndDeadline(t *testing.T) {
	var nilClient *adengine.Client
	identity := InternalObjectTestIdentity()
	empty, bad := "", "bad\x00"
	for _, request := range []admodel.RestoreObjectRequest{{}, {Identity: identity, NewName: &empty}, {Identity: identity, NewName: &bad}, {Identity: identity, Options: admodel.ObjectMutationOptions{Properties: []string{"1.1"}}}} {
		if _, err := adservice_object_restoration.New(nilClient).
			RestoreObject(context.Background(), request); err == nil ||
			errors.Is(err, admodel.ErrClosed) {
			t.Fatal(request, err)
		}
	}
	if _, err := adservice_object_restoration.New(nilClient).
		RestoreObject(context.Background(), admodel.RestoreObjectRequest{Identity: identity}); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatal(err)
	}
	parent, _ := admodel.IdentityByDN("OU=outside,DC=app")
	for _, mode := range []string{"cross-partition", "canceled-feature", "gc", "missing-control"} {
		t.Run(mode, func(t *testing.T) {
			writes := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := InternalRestorationTestClient(
				t,
				admodel.CapabilityActiveDirectory,
				func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if mode == "canceled-feature" {
						cancel()
						return InternalObjectTestCursor(), context.Canceled
					}
					cursor, ok := InternalRestorationFeatureCursor(options, "")
					if !ok {
						t.Fatal(options)
					}
					return cursor, nil
				},
				func(context.Context, admodel.SearchOptions, []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error) {
					return InternalObjectTestCursor(InternalRestorationDeletedEntry()), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			if mode == "gc" {
				(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268
			}
			if mode == "missing-control" {
				session := adengine.InternalClientSession(client).(InternalRestorationTestSession)
				original := session.InternalRead
				session.InternalRead = func(ctx context.Context, p []string) (map[string][][]byte, error) {
					root, err := original(ctx, p)
					delete(root, "supportedcontrol")
					return root, err
				}
				(*adengine.InternalClientSessionPointer(client)) = session
			}
			result, err := adservice_object_restoration.New(client).
				RestoreObject(ctx, admodel.RestoreObjectRequest{Identity: identity, TargetParent: parent})
			if err == nil || writes != 0 ||
				result.Mutation.State != admodel.ObjectWriteNotAttempted {
				t.Fatal(result, err, writes)
			}
		})
	}
	// Typed metadata never aliases requested property slices.
	extra := make([]string, 1, 20)
	extra[0] = "description"
	copyOf := slices.Clone(extra)
	_ = admodel.InternalRestorationProperties(extra)
	if !reflect.DeepEqual(extra, copyOf) {
		t.Fatal(extra)
	}
	client := InternalRestorationTestClient(
		t,
		admodel.CapabilityActiveDirectory,
		func(ctx context.Context, _ admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			<-ctx.Done()
			return nil, context.Cause(ctx)
		},
		func(context.Context, admodel.SearchOptions, []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error) {
			t.Fatal("timeout dispatched deleted lookup")
			return nil, admodel.ErrInvalidResult
		},
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			t.Fatal("timeout wrote")
			return admodel.InternalLdapWriteAttempt{}
		},
	)
	(*adengine.InternalClientConfigPointer(client)).Timeout = 5 * time.Millisecond
	result, err := adservice_object_restoration.New(client).
		RestoreObject(context.Background(), admodel.RestoreObjectRequest{Identity: identity})
	if !errors.Is(err, context.DeadlineExceeded) ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
}
