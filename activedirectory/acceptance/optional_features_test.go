package acceptance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_directory_settings "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/directory_settings"
)

const (
	InternalOptionalTestGUID = "11111111-2222-3333-4455-66778899aabb"
	InternalOptionalTestDN   = "CN=Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + InternalOperationTestConfig
)

type InternalOptionalFeatureTestSession struct {
	InternalTestSession
	InternalModify func(context.Context, string, []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt
}

func (s InternalOptionalFeatureTestSession) InternalLdapModify(
	ctx context.Context,
	dn string,
	mods []admodel.InternalLdapModification,
) admodel.InternalLdapWriteAttempt {
	return s.InternalModify(ctx, dn, mods)
}

func InternalOptionalFeatureFixture() (map[string]map[string][][]byte, admodel.Object) {
	objects, _, _ := InternalOperationMasterFixture()
	objects[""]["forestfunctionality"] = [][]byte{[]byte("10")}
	objects[""]["domainfunctionality"] = [][]byte{[]byte("10")}
	objects["CN=Partitions,"+InternalOperationTestConfig]["fsmoroleowner"] = [][]byte{
		[]byte(InternalOperationTestTarget),
	}
	guid, _ := admodel.InternalOptionalFeatureGUIDBytes(InternalOptionalTestGUID)
	feature := admodel.Object{
		DistinguishedName: InternalOptionalTestDN,
		Attributes: map[string][][]byte{
			"distinguishedname": {
				[]byte(InternalOptionalTestDN),
			},
			"objectclass":                        {[]byte("top"), []byte("msDS-OptionalFeature")},
			"name":                               {[]byte("Feature")},
			"objectguid":                         {guid},
			"msds-optionalfeatureguid":           {guid},
			"msds-optionalfeatureflags":          {[]byte("15")},
			"msds-requiredforestbehaviorversion": {[]byte("4")},
		},
		RequestedProperties: admodel.InternalOptionalFeatureProperties(),
	}
	return objects, feature
}

func InternalOptionalFeatureFixtureClient(
	t *testing.T,
	objects map[string]map[string][][]byte,
	feature *admodel.Object,
	modify func(context.Context, string, []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt,
) *adengine.Client {
	t.Helper()
	return adengine.InternalNewClient(
		admodel.Config{Timeout: time.Second},
		InternalOptionalFeatureTestSession{InternalTestSession: InternalTestSession{
			InternalBase: func(ctx context.Context, dn string, _ []string) (map[string][][]byte, error) {
				if err := context.Cause(ctx); err != nil {
					return nil, err
				}
				if dn == feature.DistinguishedName {
					return feature.Attributes, nil
				}
				if attrs, ok := objects[dn]; ok {
					return attrs, nil
				}
				return nil, &admodel.LDAPError{Code: 32}
			},
			InternalSearch: func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				if !strings.Contains(options.Filter, "msDS-OptionalFeature") {
					t.Fatalf("unexpected search: %+v", options)
				}
				return InternalTestSearchCursor{
					InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
						return []admodel.Object{*feature}, true, nil
					},
					InternalFinish: func() error { return nil },
				}, nil
			},
			InternalFinish: func() error { return nil },
		}, InternalModify: modify},
	)
}

func InternalOptionalFeatureRequest(
	scope admodel.OptionalFeatureScope,
) admodel.OptionalFeatureChangeRequest {
	dn := InternalOperationTestTarget
	if scope == admodel.OptionalFeatureForest {
		dn = "CN=Partitions," + InternalOperationTestConfig
	}
	if scope == admodel.OptionalFeatureDomain {
		dn = InternalOperationTestDomain
	}
	return admodel.OptionalFeatureChangeRequest{
		FeatureGUID: InternalOptionalTestGUID,
		Scope:       scope,
		ScopeDN:     dn,
	}
}

func TestOptionalFeatureProjectionAndQuery(t *testing.T) {
	objects, feature := InternalOptionalFeatureFixture()
	feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("-2147483633")}
	feature.Attributes["msds-requiredforestbehaviorversion"] = [][]byte{[]byte("0")}
	feature.Attributes["msds-enabledfeaturebl"] = [][]byte{
		[]byte(InternalOperationTestDomain),
		[]byte(InternalOperationTestTarget),
	}
	client := InternalOptionalFeatureFixtureClient(t, objects, &feature, nil)
	result, err := adservice_directory_settings.New(client).
		OptionalFeatures(context.Background(), admodel.OptionalFeatureQuery{FeatureGUID: InternalOptionalTestGUID})
	if err != nil || !result.Complete || len(result.Features) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	got := result.Features[0]
	if *got.FeatureGUID != InternalOptionalTestGUID || *got.Flags != 0x8000000f ||
		got.RequiredForestLevel == nil ||
		*got.RequiredForestLevel != 0 ||
		got.RequiredDomainLevel != nil ||
		!*got.Disablable ||
		len(got.Scopes) != 3 ||
		len(got.EnabledScopes) != 2 ||
		got.EnabledScopesState != admodel.AttributePresent {
		t.Fatalf("lost projection semantics: %+v", got)
	}
	for _, query := range []admodel.OptionalFeatureQuery{{Name: "x", FeatureGUID: InternalOptionalTestGUID}, {FeatureGUID: "00000000-0000-0000-0000-000000000000"}, {Name: "x\x00"}, {ObjectGUID: "bad"}, {ResultLimit: -1}} {
		if query.Validate() == nil {
			t.Fatalf("accepted invalid query %+v", query)
		}
	}
	for _, guid := range []string{InternalOptionalTestGUID, admodel.OptionalFeatureRecycleBinGUID, admodel.OptionalFeaturePAMGUID, admodel.OptionalFeatureDatabase32KPagesGUID} {
		raw, err := admodel.InternalOptionalFeatureGUIDBytes(guid)
		if err != nil || admodel.InternalOptionalFeatureGUIDString(raw) != guid {
			t.Fatal("GUID endian round trip", guid, err)
		}
	}
}

func TestOptionalFeatureMissingRangedMalformedAndFailedReads(t *testing.T) {
	for _, mode := range []string{"missing", "range", "bad-guid", "bad-flags", "partial-search"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := InternalOptionalFeatureFixture()
			native := &admodel.LDAPError{Code: 50, Diagnostic: "private permission details"}
			client := InternalOptionalFeatureFixtureClient(t, objects, &feature, nil)
			switch mode {
			case "missing":
				delete(feature.Attributes, "msds-optionalfeatureflags")
			case "range":
				feature.Attributes["msds-enabledfeaturebl;range=0-1499"] = [][]byte{
					[]byte(InternalOperationTestDomain),
				}
			case "bad-guid":
				feature.Attributes["msds-optionalfeatureguid"] = [][]byte{{1, 2}}
			case "bad-flags":
				feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("4294967296")}
			case "partial-search":
				s := adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession)
				s.InternalSearch = func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					return InternalTestSearchCursor{
						InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
							return []admodel.Object{feature}, false, native
						},
						InternalFinish: func() error { return nil },
					}, nil
				}
				(*adengine.InternalClientSessionPointer(client)) = s
			}
			result, err := adservice_directory_settings.New(client).
				OptionalFeatures(context.Background(), admodel.OptionalFeatureQuery{})
			if len(result.Features) != 1 {
				t.Fatalf("partial rows lost: %+v", result)
			}
			if mode == "missing" {
				if err != nil || result.Features[0].Flags != nil ||
					result.Features[0].Disablable != nil ||
					result.Features[0].EnabledScopesState != admodel.AttributeAbsent {
					t.Fatalf("missing became false/zero: %+v %v", result, err)
				}
				return
			}
			if err == nil || result.Complete {
				t.Fatalf("accepted incomplete/malformed: %+v %v", result, err)
			}
			if mode == "range" &&
				(result.Features[0].EnabledScopesState != admodel.AttributePartial || len(result.Features[0].Raw.Attributes["msds-enabledfeaturebl;range=0-1499"]) != 1) {
				t.Fatal("ranged evidence lost")
			}
			if mode == "partial-search" &&
				(!errors.Is(err, native) || result.Features[0].EnabledScopesState != admodel.AttributeUnloaded || len(result.Features[0].EnabledScopeObjects) != 0) {
				t.Fatal("native error or unread backlink state lost", result, err)
			}
		})
	}
}

func TestOptionalFeatureChangesUseExactRootDSEOperation(t *testing.T) {
	for _, scope := range []admodel.OptionalFeatureScope{admodel.OptionalFeatureForest, admodel.OptionalFeatureDomain, admodel.OptionalFeatureServer} {
		for _, enable := range []bool{false, true} {
			t.Run(
				string(scope)+map[bool]string{false: "disable", true: "enable"}[enable],
				func(t *testing.T) {
					objects, feature := InternalOptionalFeatureFixture()
					request := InternalOptionalFeatureRequest(scope)
					calls := 0
					objects[request.ScopeDN]["msds-enabledfeature"] = [][]byte{
						[]byte("CN=Unrelated," + InternalOperationTestConfig),
					}
					client := InternalOptionalFeatureFixtureClient(
						t,
						objects,
						&feature,
						func(_ context.Context, dn string, mods []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt {
							calls++
							attribute := "disableOptionalFeature"
							if enable {
								attribute = "enableOptionalFeature"
							}
							if dn != "" || len(mods) != 1 || mods[0].InternalOperation != 0 ||
								mods[0].InternalAttribute != attribute ||
								string(
									mods[0].InternalValue,
								) != request.ScopeDN+":"+InternalOptionalTestGUID {
								t.Fatalf("wrong operation: %q %+v", dn, mods)
							}
							if enable {
								objects[request.ScopeDN]["msds-enabledfeature"] = append(
									objects[request.ScopeDN]["msds-enabledfeature"],
									[]byte(InternalOptionalTestDN),
								)
							}
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteAccepted,
							}
						},
					)
					(*adengine.InternalClientConfigPointer(client)).Partition = "DC=unrelated,DC=test"
					var result admodel.OptionalFeatureChangeResult
					var err error
					if enable {
						result, err = adservice_directory_settings.New(client).
							EnableOptionalFeature(context.Background(), request)
					} else {
						result, err = adservice_directory_settings.New(client).
							DisableOptionalFeature(context.Background(), request)
					}
					if err != nil || calls != 1 || !result.Verified || result.AfterEnabled == nil ||
						*result.AfterEnabled != enable ||
						result.WriteState != admodel.OptionalFeatureWriteAccepted {
						t.Fatalf("%+v calls=%d err=%v", result, calls, err)
					}
				},
			)
		}
	}
}

func TestOptionalFeatureGuardFailuresNeverSubmit(t *testing.T) {
	for _, mode := range []string{"wrong-role", "wrong-scope", "lds-domain", "rodc", "unsynchronized", "scope-flag", "unknown-flags", "forest-level", "domain-level", "irreversible-enable", "irreversible-disable", "known-irreversible-forged-flags", "wrong-guid", "canceled", "32k-no-dsa-proof"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := InternalOptionalFeatureFixture()
			request := InternalOptionalFeatureRequest(admodel.OptionalFeatureForest)
			enable := true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := admodel.ErrOptionalFeaturePrerequisite
			switch mode {
			case "wrong-role":
				objects[request.ScopeDN]["fsmoroleowner"] = [][]byte{
					[]byte(InternalOperationTestOld),
				}
				want = admodel.ErrOptionalFeatureRole
			case "wrong-scope":
				request.ScopeDN = InternalOperationTestDomain
				want = admodel.ErrOptionalFeatureScope
			case "lds-domain":
				request = InternalOptionalFeatureRequest(admodel.OptionalFeatureDomain)
				objects[""]["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
				want = admodel.ErrOptionalFeatureScope
			case "rodc":
				objects[InternalOperationTestTarget]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "unsynchronized":
				objects[""]["issynchronized"] = [][]byte{[]byte("FALSE")}
			case "scope-flag":
				feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("12")}
				want = admodel.ErrOptionalFeatureScope
			case "unknown-flags":
				delete(feature.Attributes, "msds-optionalfeatureflags")
				want = admodel.ErrIncompleteResult
			case "forest-level":
				objects[""]["forestfunctionality"] = [][]byte{[]byte("3")}
			case "domain-level":
				request = InternalOptionalFeatureRequest(admodel.OptionalFeatureDomain)
				feature.Attributes["msds-requireddomainbehaviorversion"] = [][]byte{[]byte("11")}
			case "irreversible-enable", "irreversible-disable":
				feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("1")}
				enable = mode == "irreversible-enable"
				request.AcknowledgeIrreversible = !enable
				want = admodel.ErrOptionalFeatureIrreversible
			case "known-irreversible-forged-flags":
				request.FeatureGUID = admodel.OptionalFeatureRecycleBinGUID
				raw, _ := admodel.InternalOptionalFeatureGUIDBytes(request.FeatureGUID)
				feature.Attributes["msds-optionalfeatureguid"] = [][]byte{raw}
				enable = false
				want = admodel.ErrOptionalFeatureIrreversible
			case "wrong-guid":
				request.FeatureGUID = admodel.OptionalFeaturePAMGUID
				want = admodel.ErrIncompleteResult
			case "canceled":
				cancel()
				want = context.Canceled
			case "32k-no-dsa-proof":
				request.FeatureGUID = admodel.OptionalFeatureDatabase32KPagesGUID
				request.AcknowledgeIrreversible = true
				raw, _ := admodel.InternalOptionalFeatureGUIDBytes(request.FeatureGUID)
				feature.Attributes["msds-optionalfeatureguid"] = [][]byte{raw}
			}
			client := InternalOptionalFeatureFixtureClient(
				t,
				objects,
				&feature,
				func(context.Context, string, []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt {
					t.Fatal("guard submitted write")
					return admodel.InternalLdapWriteAttempt{}
				},
			)
			if mode == "32k-no-dsa-proof" {
				s := adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession)
				original := s.InternalSearch
				s.InternalSearch = func(ctx context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if options.Filter == "(objectClass=nTDSDSA)" {
						return InternalTestSearchCursor{
							InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
								return []admodel.Object{
									{
										DistinguishedName: InternalOperationTestTarget,
										Attributes: map[string][][]byte{
											"msds-jetdbpagesize": {[]byte("8192")},
										},
									},
								}, true, nil
							},
							InternalFinish: func() error { return nil },
						}, nil
					}
					return original(ctx, options)
				}
				(*adengine.InternalClientSessionPointer(client)) = s
			}
			var result admodel.OptionalFeatureChangeResult
			var err error
			if enable {
				result, err = adservice_directory_settings.New(client).
					EnableOptionalFeature(ctx, request)
			} else {
				result, err = adservice_directory_settings.New(client).
					DisableOptionalFeature(ctx, request)
			}
			if !errors.Is(err, want) ||
				result.WriteState != admodel.OptionalFeatureWriteNotAttempted {
				t.Fatalf("%+v err=%v want=%v", result, err, want)
			}
		})
	}
}

func TestOptionalFeatureWriteOutcomesAreNotReplayedOrMasked(t *testing.T) {
	for _, mode := range []string{"permission", "uncertain", "accepted-readback-failed", "accepted-hidden", "accepted-cleanup-error"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := InternalOptionalFeatureFixture()
			request := InternalOptionalFeatureRequest(admodel.OptionalFeatureForest)
			calls := 0
			readsAfterWrite := 0
			native := &admodel.LDAPError{Code: 50, Diagnostic: "private details"}
			failure := errors.New("injected readback/cleanup failure")
			client := InternalOptionalFeatureFixtureClient(
				t,
				objects,
				&feature,
				func(context.Context, string, []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt {
					calls++
					switch mode {
					case "permission":
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteRejected,
							Err:   native,
						}
					case "uncertain":
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteUncertain,
							Err:   admodel.InternalLDAPWriteUncertainError(),
						}
					case "accepted-cleanup-error":
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteAccepted,
							Err:   failure,
						}
					}
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			s := adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession)
			original := s.InternalBase
			s.InternalBase = func(ctx context.Context, dn string, attrs []string) (map[string][][]byte, error) {
				if calls > 0 {
					readsAfterWrite++
					if mode == "accepted-readback-failed" {
						return nil, failure
					}
				}
				return original(ctx, dn, attrs)
			}
			(*adengine.InternalClientSessionPointer(client)) = s
			result, err := adservice_directory_settings.New(client).
				EnableOptionalFeature(context.Background(), request)
			if err == nil || calls != 1 || result.Verified {
				t.Fatalf("%+v calls=%d err=%v", result, calls, err)
			}
			switch mode {
			case "permission":
				if result.WriteState != admodel.OptionalFeatureWriteRejected ||
					!errors.Is(err, admodel.ErrOptionalFeaturePermission) ||
					!errors.Is(err, native) ||
					strings.Contains(err.Error(), "private") {
					t.Fatal(result, err)
				}
			case "uncertain":
				if result.WriteState != admodel.OptionalFeatureWriteUncertain ||
					!errors.Is(err, admodel.ErrOptionalFeatureUncertain) ||
					readsAfterWrite != 0 {
					t.Fatal(result, err, readsAfterWrite)
				}
			default:
				if result.WriteState != admodel.OptionalFeatureWriteAccepted {
					t.Fatal("accepted state lost", result)
				}
			}
		})
	}
}

func TestOptionalFeatureLDSGUIDReferenceResolvesCanonicalScopeAndOwner(t *testing.T) {
	for _, scope := range []admodel.OptionalFeatureScope{admodel.OptionalFeatureForest, admodel.OptionalFeatureServer} {
		t.Run(string(scope), func(t *testing.T) {
			objects, feature := InternalOptionalFeatureFixture()
			reference := "<GUID=11111111-2222-3333-4455-66778899aabb>"
			objects[""]["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
			objects[""]["dsservicename"] = [][]byte{[]byte(reference)}
			objects[reference] = objects[InternalOperationTestTarget]
			delete(objects[reference], "msds-isrodc")
			request := InternalOptionalFeatureRequest(scope)
			calls := 0
			client := InternalOptionalFeatureFixtureClient(
				t,
				objects,
				&feature,
				func(_ context.Context, dn string, mods []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt {
					calls++
					if dn != "" ||
						string(
							mods[0].InternalValue,
						) != request.ScopeDN+":"+InternalOptionalTestGUID {
						t.Fatal("GUID reference leaked into scope operation", dn, mods)
					}
					objects[request.ScopeDN]["msds-enabledfeature"] = [][]byte{
						[]byte(InternalOptionalTestDN),
					}
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			result, err := adservice_directory_settings.New(client).
				EnableOptionalFeature(context.Background(), request)
			if err != nil || calls != 1 || !result.Verified ||
				result.TargetDSA != InternalOperationTestTarget {
				t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
			}
		})
	}
}

func TestOptionalFeatureAcknowledgedKnownEnableAnd32KCapabilityProof(t *testing.T) {
	for _, guid := range []string{admodel.OptionalFeatureRecycleBinGUID, admodel.OptionalFeaturePAMGUID, admodel.OptionalFeatureDatabase32KPagesGUID} {
		t.Run(guid, func(t *testing.T) {
			objects, feature := InternalOptionalFeatureFixture()
			raw, _ := admodel.InternalOptionalFeatureGUIDBytes(guid)
			feature.Attributes["msds-optionalfeatureguid"] = [][]byte{raw}
			feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("1")}
			request := InternalOptionalFeatureRequest(admodel.OptionalFeatureForest)
			request.FeatureGUID = guid
			request.AcknowledgeIrreversible = true
			calls, capabilityReads := 0, 0
			client := InternalOptionalFeatureFixtureClient(
				t,
				objects,
				&feature,
				func(_ context.Context, dn string, mods []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt {
					calls++
					if dn != "" || string(mods[0].InternalValue) != request.ScopeDN+":"+guid {
						t.Fatal("wrong known feature operation")
					}
					objects[request.ScopeDN]["msds-enabledfeature"] = [][]byte{
						[]byte(InternalOptionalTestDN),
					}
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			s := adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession)
			original := s.InternalSearch
			s.InternalSearch = func(ctx context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				if options.Filter != "(objectClass=nTDSDSA)" {
					return original(ctx, options)
				}
				capabilityReads++
				if options.Base != InternalOperationTestConfig ||
					options.Scope != admodel.ScopeSubtree ||
					options.ResultLimit != 0 {
					t.Fatal("incomplete 32K capability enumeration")
				}
				return InternalTestSearchCursor{
					InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
						return []admodel.Object{
							{
								DistinguishedName: InternalOperationTestTarget,
								Attributes: map[string][][]byte{
									"msds-jetdbpagesize": {[]byte("32768")},
								},
							},
							{
								DistinguishedName: InternalOperationTestOld,
								Attributes: map[string][][]byte{
									"msds-jetdbpagesize": {[]byte("32768")},
								},
							},
						}, true, nil
					},
					InternalFinish: func() error { return nil },
				}, nil
			}
			(*adengine.InternalClientSessionPointer(client)) = s
			result, err := adservice_directory_settings.New(client).
				EnableOptionalFeature(context.Background(), request)
			if err != nil || calls != 1 || !result.Verified ||
				(capabilityReads == 1) != (guid == admodel.OptionalFeatureDatabase32KPagesGUID) {
				t.Fatalf(
					"result=%+v writes=%d capability_reads=%d err=%v",
					result,
					calls,
					capabilityReads,
					err,
				)
			}
		})
	}
}
