package activedirectory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const optionalTestGUID = "11111111-2222-3333-4455-66778899aabb"
const optionalTestDN = "CN=Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + operationTestConfig

type optionalFeatureTestSession struct {
	testSession
	modify func(context.Context, string, []ldapModification) ldapWriteAttempt
}

func (s optionalFeatureTestSession) ldapModify(ctx context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
	return s.modify(ctx, dn, mods)
}

func optionalFeatureFixture() (map[string]map[string][][]byte, Object) {
	objects, _, _ := operationMasterFixture()
	objects[""]["forestfunctionality"] = [][]byte{[]byte("10")}
	objects[""]["domainfunctionality"] = [][]byte{[]byte("10")}
	objects["CN=Partitions,"+operationTestConfig]["fsmoroleowner"] = [][]byte{[]byte(operationTestTarget)}
	guid, _ := optionalFeatureGUIDBytes(optionalTestGUID)
	feature := Object{DistinguishedName: optionalTestDN, Attributes: map[string][][]byte{
		"distinguishedname": {[]byte(optionalTestDN)}, "objectclass": {[]byte("top"), []byte("msDS-OptionalFeature")}, "name": {[]byte("Feature")}, "objectguid": {guid}, "msds-optionalfeatureguid": {guid}, "msds-optionalfeatureflags": {[]byte("15")}, "msds-requiredforestbehaviorversion": {[]byte("4")},
	}, RequestedProperties: optionalFeatureProperties()}
	return objects, feature
}

func optionalFeatureFixtureClient(t *testing.T, objects map[string]map[string][][]byte, feature *Object, modify func(context.Context, string, []ldapModification) ldapWriteAttempt) *Client {
	t.Helper()
	return newClient(Config{Timeout: time.Second}, optionalFeatureTestSession{testSession: testSession{
		base: func(ctx context.Context, dn string, _ []string) (map[string][][]byte, error) {
			if err := context.Cause(ctx); err != nil {
				return nil, err
			}
			if attrs, ok := objects[dn]; ok {
				return attrs, nil
			}
			return nil, &LDAPError{Code: 32}
		},
		search: func(_ context.Context, options SearchOptions) (searchCursor, error) {
			if !strings.Contains(options.Filter, "msDS-OptionalFeature") {
				t.Fatalf("unexpected search: %+v", options)
			}
			return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return []Object{*feature}, true, nil }, finish: func() error { return nil }}, nil
		}, finish: func() error { return nil },
	}, modify: modify})
}

func optionalFeatureRequest(scope OptionalFeatureScope) OptionalFeatureChangeRequest {
	dn := operationTestTarget
	if scope == OptionalFeatureForest {
		dn = "CN=Partitions," + operationTestConfig
	}
	if scope == OptionalFeatureDomain {
		dn = operationTestDomain
	}
	return OptionalFeatureChangeRequest{FeatureGUID: optionalTestGUID, Scope: scope, ScopeDN: dn}
}

func TestOptionalFeatureProjectionAndQuery(t *testing.T) {
	objects, feature := optionalFeatureFixture()
	feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("-2147483633")}
	feature.Attributes["msds-requiredforestbehaviorversion"] = [][]byte{[]byte("0")}
	feature.Attributes["msds-enabledfeaturebl"] = [][]byte{[]byte(operationTestDomain), []byte(operationTestTarget)}
	client := optionalFeatureFixtureClient(t, objects, &feature, nil)
	result, err := client.OptionalFeatures(context.Background(), OptionalFeatureQuery{FeatureGUID: optionalTestGUID})
	if err != nil || !result.Complete || len(result.Features) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	got := result.Features[0]
	if *got.FeatureGUID != optionalTestGUID || *got.Flags != 0x8000000f || got.RequiredForestLevel == nil || *got.RequiredForestLevel != 0 || got.RequiredDomainLevel != nil || !*got.Disablable || len(got.Scopes) != 3 || len(got.EnabledScopes) != 2 || got.EnabledScopesState != AttributePresent {
		t.Fatalf("lost projection semantics: %+v", got)
	}
	for _, query := range []OptionalFeatureQuery{{Name: "x", FeatureGUID: optionalTestGUID}, {FeatureGUID: "00000000-0000-0000-0000-000000000000"}, {Name: "x\x00"}, {ObjectGUID: "bad"}, {ResultLimit: -1}} {
		if query.Validate() == nil {
			t.Fatalf("accepted invalid query %+v", query)
		}
	}
	for _, guid := range []string{optionalTestGUID, OptionalFeatureRecycleBinGUID, OptionalFeaturePAMGUID, OptionalFeatureDatabase32KPagesGUID} {
		raw, err := optionalFeatureGUIDBytes(guid)
		if err != nil || optionalFeatureGUIDString(raw) != guid {
			t.Fatal("GUID endian round trip", guid, err)
		}
	}
}

func TestOptionalFeatureMissingRangedMalformedAndFailedReads(t *testing.T) {
	for _, mode := range []string{"missing", "range", "bad-guid", "bad-flags", "partial-search"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := optionalFeatureFixture()
			var native = &LDAPError{Code: 50, Diagnostic: "private permission details"}
			client := optionalFeatureFixtureClient(t, objects, &feature, nil)
			switch mode {
			case "missing":
				delete(feature.Attributes, "msds-optionalfeatureflags")
			case "range":
				feature.Attributes["msds-enabledfeaturebl;range=0-1499"] = [][]byte{[]byte(operationTestDomain)}
			case "bad-guid":
				feature.Attributes["msds-optionalfeatureguid"] = [][]byte{{1, 2}}
			case "bad-flags":
				feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("4294967296")}
			case "partial-search":
				s := client.session.(optionalFeatureTestSession)
				s.search = func(context.Context, SearchOptions) (searchCursor, error) {
					return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return []Object{feature}, false, native }, finish: func() error { return nil }}, nil
				}
				client.session = s
			}
			result, err := client.OptionalFeatures(context.Background(), OptionalFeatureQuery{})
			if len(result.Features) != 1 {
				t.Fatalf("partial rows lost: %+v", result)
			}
			if mode == "missing" {
				if err != nil || result.Features[0].Flags != nil || result.Features[0].Disablable != nil || result.Features[0].EnabledScopesState != AttributeAbsent {
					t.Fatalf("missing became false/zero: %+v %v", result, err)
				}
				return
			}
			if err == nil || result.Complete {
				t.Fatalf("accepted incomplete/malformed: %+v %v", result, err)
			}
			if mode == "range" && (result.Features[0].EnabledScopesState != AttributePartial || len(result.Features[0].Raw.Attributes["msds-enabledfeaturebl;range=0-1499"]) != 1) {
				t.Fatal("ranged evidence lost")
			}
			if mode == "partial-search" && !errors.Is(err, native) {
				t.Fatal("native error lost", err)
			}
		})
	}
}

func TestOptionalFeatureChangesUseExactRootDSEOperation(t *testing.T) {
	for _, scope := range []OptionalFeatureScope{OptionalFeatureForest, OptionalFeatureDomain, OptionalFeatureServer} {
		for _, enable := range []bool{false, true} {
			t.Run(string(scope)+map[bool]string{false: "disable", true: "enable"}[enable], func(t *testing.T) {
				objects, feature := optionalFeatureFixture()
				request := optionalFeatureRequest(scope)
				calls := 0
				objects[request.ScopeDN]["msds-enabledfeature"] = [][]byte{[]byte("CN=Unrelated," + operationTestConfig)}
				client := optionalFeatureFixtureClient(t, objects, &feature, func(_ context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
					calls++
					attribute := "disableOptionalFeature"
					if enable {
						attribute = "enableOptionalFeature"
					}
					if dn != "" || len(mods) != 1 || mods[0].operation != 0 || mods[0].attribute != attribute || string(mods[0].value) != request.ScopeDN+":"+optionalTestGUID {
						t.Fatalf("wrong operation: %q %+v", dn, mods)
					}
					if enable {
						objects[request.ScopeDN]["msds-enabledfeature"] = append(objects[request.ScopeDN]["msds-enabledfeature"], []byte(optionalTestDN))
					}
					return ldapWriteAttempt{State: ldapWriteAccepted}
				})
				client.config.Partition = "DC=unrelated,DC=test"
				var result OptionalFeatureChangeResult
				var err error
				if enable {
					result, err = client.EnableOptionalFeature(context.Background(), request)
				} else {
					result, err = client.DisableOptionalFeature(context.Background(), request)
				}
				if err != nil || calls != 1 || !result.Verified || result.AfterEnabled == nil || *result.AfterEnabled != enable || result.WriteState != OptionalFeatureWriteAccepted {
					t.Fatalf("%+v calls=%d err=%v", result, calls, err)
				}
			})
		}
	}
}

func TestOptionalFeatureGuardFailuresNeverSubmit(t *testing.T) {
	for _, mode := range []string{"wrong-role", "wrong-scope", "lds-domain", "rodc", "unsynchronized", "scope-flag", "unknown-flags", "forest-level", "domain-level", "irreversible-enable", "irreversible-disable", "known-irreversible-forged-flags", "wrong-guid", "canceled", "32k-no-dsa-proof"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := optionalFeatureFixture()
			request := optionalFeatureRequest(OptionalFeatureForest)
			enable := true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrOptionalFeaturePrerequisite
			switch mode {
			case "wrong-role":
				objects[request.ScopeDN]["fsmoroleowner"] = [][]byte{[]byte(operationTestOld)}
				want = ErrOptionalFeatureRole
			case "wrong-scope":
				request.ScopeDN = operationTestDomain
				want = ErrOptionalFeatureScope
			case "lds-domain":
				request = optionalFeatureRequest(OptionalFeatureDomain)
				objects[""]["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
				want = ErrOptionalFeatureScope
			case "rodc":
				objects[operationTestTarget]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "unsynchronized":
				objects[""]["issynchronized"] = [][]byte{[]byte("FALSE")}
			case "scope-flag":
				feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("12")}
				want = ErrOptionalFeatureScope
			case "unknown-flags":
				delete(feature.Attributes, "msds-optionalfeatureflags")
				want = ErrIncompleteResult
			case "forest-level":
				objects[""]["forestfunctionality"] = [][]byte{[]byte("3")}
			case "domain-level":
				request = optionalFeatureRequest(OptionalFeatureDomain)
				feature.Attributes["msds-requireddomainbehaviorversion"] = [][]byte{[]byte("11")}
			case "irreversible-enable", "irreversible-disable":
				feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("1")}
				enable = mode == "irreversible-enable"
				request.AcknowledgeIrreversible = !enable
				want = ErrOptionalFeatureIrreversible
			case "known-irreversible-forged-flags":
				request.FeatureGUID = OptionalFeatureRecycleBinGUID
				raw, _ := optionalFeatureGUIDBytes(request.FeatureGUID)
				feature.Attributes["msds-optionalfeatureguid"] = [][]byte{raw}
				enable = false
				want = ErrOptionalFeatureIrreversible
			case "wrong-guid":
				request.FeatureGUID = OptionalFeaturePAMGUID
				want = ErrIncompleteResult
			case "canceled":
				cancel()
				want = context.Canceled
			case "32k-no-dsa-proof":
				request.FeatureGUID = OptionalFeatureDatabase32KPagesGUID
				request.AcknowledgeIrreversible = true
				raw, _ := optionalFeatureGUIDBytes(request.FeatureGUID)
				feature.Attributes["msds-optionalfeatureguid"] = [][]byte{raw}
			}
			client := optionalFeatureFixtureClient(t, objects, &feature, func(context.Context, string, []ldapModification) ldapWriteAttempt {
				t.Fatal("guard submitted write")
				return ldapWriteAttempt{}
			})
			if mode == "32k-no-dsa-proof" {
				s := client.session.(optionalFeatureTestSession)
				original := s.search
				s.search = func(ctx context.Context, options SearchOptions) (searchCursor, error) {
					if options.Filter == "(objectClass=nTDSDSA)" {
						return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
							return []Object{{DistinguishedName: operationTestTarget, Attributes: map[string][][]byte{"msds-jetdbpagesize": {[]byte("8192")}}}}, true, nil
						}, finish: func() error { return nil }}, nil
					}
					return original(ctx, options)
				}
				client.session = s
			}
			var result OptionalFeatureChangeResult
			var err error
			if enable {
				result, err = client.EnableOptionalFeature(ctx, request)
			} else {
				result, err = client.DisableOptionalFeature(ctx, request)
			}
			if !errors.Is(err, want) || result.WriteState != OptionalFeatureWriteNotAttempted {
				t.Fatalf("%+v err=%v want=%v", result, err, want)
			}
		})
	}
}

func TestOptionalFeatureWriteOutcomesAreNotReplayedOrMasked(t *testing.T) {
	for _, mode := range []string{"permission", "uncertain", "accepted-readback-failed", "accepted-hidden", "accepted-cleanup-error"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := optionalFeatureFixture()
			request := optionalFeatureRequest(OptionalFeatureForest)
			calls := 0
			readsAfterWrite := 0
			native := &LDAPError{Code: 50, Diagnostic: "private details"}
			failure := errors.New("injected readback/cleanup failure")
			client := optionalFeatureFixtureClient(t, objects, &feature, func(context.Context, string, []ldapModification) ldapWriteAttempt {
				calls++
				switch mode {
				case "permission":
					return ldapWriteAttempt{State: ldapWriteRejected, Err: native}
				case "uncertain":
					return ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}
				case "accepted-cleanup-error":
					return ldapWriteAttempt{State: ldapWriteAccepted, Err: failure}
				}
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			s := client.session.(optionalFeatureTestSession)
			original := s.base
			s.base = func(ctx context.Context, dn string, attrs []string) (map[string][][]byte, error) {
				if calls > 0 {
					readsAfterWrite++
					if mode == "accepted-readback-failed" {
						return nil, failure
					}
				}
				return original(ctx, dn, attrs)
			}
			client.session = s
			result, err := client.EnableOptionalFeature(context.Background(), request)
			if err == nil || calls != 1 || result.Verified {
				t.Fatalf("%+v calls=%d err=%v", result, calls, err)
			}
			switch mode {
			case "permission":
				if result.WriteState != OptionalFeatureWriteRejected || !errors.Is(err, ErrOptionalFeaturePermission) || !errors.Is(err, native) || strings.Contains(err.Error(), "private") {
					t.Fatal(result, err)
				}
			case "uncertain":
				if result.WriteState != OptionalFeatureWriteUncertain || !errors.Is(err, ErrOptionalFeatureUncertain) || readsAfterWrite != 0 {
					t.Fatal(result, err, readsAfterWrite)
				}
			default:
				if result.WriteState != OptionalFeatureWriteAccepted {
					t.Fatal("accepted state lost", result)
				}
			}
		})
	}
}

func TestOptionalFeatureLDSGUIDReferenceResolvesCanonicalScopeAndOwner(t *testing.T) {
	for _, scope := range []OptionalFeatureScope{OptionalFeatureForest, OptionalFeatureServer} {
		t.Run(string(scope), func(t *testing.T) {
			objects, feature := optionalFeatureFixture()
			reference := "<GUID=11111111-2222-3333-4455-66778899aabb>"
			objects[""]["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			objects[""]["dsservicename"] = [][]byte{[]byte(reference)}
			objects[reference] = objects[operationTestTarget]
			delete(objects[reference], "msds-isrodc")
			request := optionalFeatureRequest(scope)
			calls := 0
			client := optionalFeatureFixtureClient(t, objects, &feature, func(_ context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
				calls++
				if dn != "" || string(mods[0].value) != request.ScopeDN+":"+optionalTestGUID {
					t.Fatal("GUID reference leaked into scope operation", dn, mods)
				}
				objects[request.ScopeDN]["msds-enabledfeature"] = [][]byte{[]byte(optionalTestDN)}
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			result, err := client.EnableOptionalFeature(context.Background(), request)
			if err != nil || calls != 1 || !result.Verified || result.TargetDSA != operationTestTarget {
				t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
			}
		})
	}
}

func TestOptionalFeatureAcknowledgedKnownEnableAnd32KCapabilityProof(t *testing.T) {
	for _, guid := range []string{OptionalFeatureRecycleBinGUID, OptionalFeaturePAMGUID, OptionalFeatureDatabase32KPagesGUID} {
		t.Run(guid, func(t *testing.T) {
			objects, feature := optionalFeatureFixture()
			raw, _ := optionalFeatureGUIDBytes(guid)
			feature.Attributes["msds-optionalfeatureguid"] = [][]byte{raw}
			feature.Attributes["msds-optionalfeatureflags"] = [][]byte{[]byte("1")}
			request := optionalFeatureRequest(OptionalFeatureForest)
			request.FeatureGUID = guid
			request.AcknowledgeIrreversible = true
			calls, capabilityReads := 0, 0
			client := optionalFeatureFixtureClient(t, objects, &feature, func(_ context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
				calls++
				if dn != "" || string(mods[0].value) != request.ScopeDN+":"+guid {
					t.Fatal("wrong known feature operation")
				}
				objects[request.ScopeDN]["msds-enabledfeature"] = [][]byte{[]byte(optionalTestDN)}
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			s := client.session.(optionalFeatureTestSession)
			original := s.search
			s.search = func(ctx context.Context, options SearchOptions) (searchCursor, error) {
				if options.Filter != "(objectClass=nTDSDSA)" {
					return original(ctx, options)
				}
				capabilityReads++
				if options.Base != operationTestConfig || options.Scope != ScopeSubtree || options.ResultLimit != 0 {
					t.Fatal("incomplete 32K capability enumeration")
				}
				return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
					return []Object{{DistinguishedName: operationTestTarget, Attributes: map[string][][]byte{"msds-jetdbpagesize": {[]byte("32768")}}}, {DistinguishedName: operationTestOld, Attributes: map[string][][]byte{"msds-jetdbpagesize": {[]byte("32768")}}}}, true, nil
				}, finish: func() error { return nil }}, nil
			}
			client.session = s
			result, err := client.EnableOptionalFeature(context.Background(), request)
			if err != nil || calls != 1 || !result.Verified || (capabilityReads == 1) != (guid == OptionalFeatureDatabase32KPagesGUID) {
				t.Fatalf("result=%+v writes=%d capability_reads=%d err=%v", result, calls, capabilityReads, err)
			}
		})
	}
}
