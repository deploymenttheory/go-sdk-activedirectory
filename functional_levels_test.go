package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
)

func runFunctionalMode(ctx context.Context, client *Client, forest bool, target FunctionalLevel, lower bool) (FunctionalLevelTransitionResult, error) {
	request := FunctionalLevelTransitionRequest{Identity: settingsIdentity(forest), Level: target, AllowLowering: lower}
	if forest {
		return client.SetForestMode(ctx, request)
	}
	return client.SetDomainMode(ctx, request)
}

func TestFunctionalLevelsRaiseAndLower(t *testing.T) {
	for _, forest := range []bool{false, true} {
		for _, pair := range [][3]FunctionalLevel{{6, 7, 7}, {7, 6, 7}, {7, 3, 7}, {7, 10, 10}, {10, 7, 10}} {
			t.Run(fmt.Sprintf("forest%t-%d-%d", forest, pair[0], pair[1]), func(t *testing.T) {
				f := newSettingsFixture()
				dn, rootProperty := operationTestDomain, "domainfunctionality"
				if forest {
					dn, rootProperty = settingsPartitions, "forestfunctionality"
				}
				f.objects[dn]["msds-behavior-version"] = [][]byte{[]byte(strconv.Itoa(int(pair[0])))}
				f.objects[""][rootProperty] = f.objects[dn]["msds-behavior-version"]
				if !forest {
					f.objects[""]["forestfunctionality"] = [][]byte{[]byte("3")}
				}
				f.objects[operationTestTarget]["msds-behavior-version"] = [][]byte{[]byte(strconv.Itoa(int(pair[2])))}
				f.objects[""]["domaincontrollerfunctionality"] = f.objects[operationTestTarget]["msds-behavior-version"]
				f.objects["CN=example,"+settingsPartitions]["msds-behavior-version"] = [][]byte{[]byte(strconv.Itoa(int(pair[2])))}
				result, err := runFunctionalMode(context.Background(), f.client(t), forest, pair[1], true)
				if err != nil || !result.PreflightComplete || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted || len(f.writes) != 1 || result.Unchanged {
					t.Fatal(result, err, f.writes)
				}
				if len(f.writes[0].modifications) != 1 || f.writes[0].modifications[0].operation != 2 || f.writes[0].modifications[0].attribute != "msDS-Behavior-Version" || string(f.writes[0].modifications[0].values[0]) != strconv.Itoa(int(pair[1])) {
					t.Fatal(f.writes)
				}
				if forest && result.Role != OperationMasterSchemaMaster {
					t.Fatal("forest did not use schema master", result)
				}
			})
		}
	}
}

func TestFunctionalLevelPrerequisiteRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		forest bool
		target FunctionalLevel
		change func(*settingsFixture)
		want   error
	}{
		{"unknown", false, 8, func(*settingsFixture) {}, ErrInvalidFunctionalLevel},
		{"schema", false, 7, func(f *settingsFixture) { f.objects[operationTestSchema]["objectversion"] = [][]byte{[]byte("69")} }, ErrFunctionalLevelPrerequisite},
		{"wrong PDC", false, 7, func(f *settingsFixture) {
			f.objects[operationTestDomain]["fsmoroleowner"] = [][]byte{[]byte(operationTestOld)}
		}, ErrFunctionalLevelRoleOwner},
		{"wrong schema owner", true, 7, func(f *settingsFixture) {
			f.objects[operationTestSchema]["fsmoroleowner"] = [][]byte{[]byte(operationTestOld)}
		}, ErrFunctionalLevelRoleOwner},
		{"old controller", false, 7, func(f *settingsFixture) {
			f.objects[operationTestTarget]["msds-behavior-version"] = [][]byte{[]byte("6")}
		}, ErrFunctionalLevelPrerequisite},
		{"old RODC", false, 7, func(f *settingsFixture) {
			f.objects[operationTestOld] = map[string][][]byte{"objectclass": {[]byte("nTDSDSARO")}, "msds-hasdomainncs": {[]byte(operationTestDomain)}, "msds-behavior-version": {[]byte("6")}}
		}, ErrFunctionalLevelPrerequisite},
		{"old domain", true, 7, func(f *settingsFixture) {
			f.objects["CN=example,"+settingsPartitions]["msds-behavior-version"] = [][]byte{[]byte("6")}
		}, ErrFunctionalLevelPrerequisite},
		{"mixed domain", false, 7, func(f *settingsFixture) {
			f.objects[operationTestDomain]["msds-behavior-version"] = [][]byte{[]byte("0")}
			f.objects[""]["domainfunctionality"] = [][]byte{[]byte("0")}
			f.objects[operationTestDomain]["ntmixeddomain"] = [][]byte{[]byte("1")}
		}, ErrFunctionalLevelPrerequisite},
		{"below forest", false, 5, func(*settingsFixture) {}, ErrFunctionalLevelPrerequisite},
		{"below rollback floor", true, 2, func(*settingsFixture) {}, ErrFunctionalLevelPrerequisite},
		{"2025 rollback floor", true, 5, func(f *settingsFixture) {
			f.objects[operationTestTarget]["msds-behavior-version"] = [][]byte{[]byte("10")}
		}, ErrFunctionalLevelPrerequisite},
		{"partial feature search", true, 7, func(f *settingsFixture) { f.featureError = &LDAPError{Code: 50} }, ErrObjectWritePermission},
		{"missing schema", false, 7, func(f *settingsFixture) { delete(f.objects[operationTestSchema], "objectversion") }, ErrAttributeUnavailable},
		{"inconsistent current", false, 7, func(f *settingsFixture) { f.objects[""]["domainfunctionality"] = [][]byte{[]byte("5")} }, ErrFunctionalLevelPrerequisite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettingsFixture()
			tc.change(f)
			result, err := runFunctionalMode(context.Background(), f.client(t), tc.forest, tc.target, true)
			if !errors.Is(err, tc.want) || len(f.writes) != 0 || result.Mutation.State != ObjectWriteNotAttempted || result.PreflightComplete {
				t.Fatal(result, err, f.writes)
			}
		})
	}
}

func TestFunctionalLevelOptionalFeatureAndPasswordRollingGuards(t *testing.T) {
	for _, forest := range []bool{true, false} {
		f := newSettingsFixture()
		attribute, scope := "msds-requireddomainbehaviorversion", operationTestDomain
		if forest {
			attribute, scope = "msds-requiredforestbehaviorversion", settingsPartitions
		}
		feature := map[string][][]byte{"objectclass": {[]byte("msDS-OptionalFeature")}, "objectguid": {objectTestGUID().Bytes()}, "msds-enabledfeaturebl": {[]byte(scope)}, attribute: {[]byte("10")}}
		f.objects["CN=Feature,CN=Directory Service,CN=Windows NT,CN=Services,"+operationTestConfig] = feature
		result, err := runFunctionalMode(context.Background(), f.client(t), forest, 7, true)
		if !errors.Is(err, ErrFunctionalLevelPrerequisite) || len(f.writes) != 0 || len(result.Observations) < 3 {
			t.Fatal(result, err, f.writes)
		}
	}
	f := newSettingsFixture()
	f.objects[operationTestDomain]["msds-expirepasswordsonsmartcardonlyaccounts"] = [][]byte{[]byte("TRUE")}
	f.objects[""]["forestfunctionality"] = [][]byte{[]byte("3")}
	if result, err := runFunctionalMode(context.Background(), f.client(t), false, 5, true); !errors.Is(err, ErrFunctionalLevelPrerequisite) || result.Mutation.State != ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
}

func TestFunctionalLevelNoOpAndExplicitLowering(t *testing.T) {
	f := newSettingsFixture()
	client := f.client(t)
	result, err := client.SetDomainMode(context.Background(), FunctionalLevelTransitionRequest{Identity: settingsIdentity(false), Level: 6, Options: ObjectMutationOptions{Properties: []string{"description"}}})
	if err != nil || !result.Unchanged || !result.Mutation.Verified || result.PreflightComplete || result.Mutation.State != ObjectWriteNotAttempted || len(f.writes) != 0 || result.Mutation.After.Values("description").State != AttributePresent {
		t.Fatal(result, err)
	}
	result, err = runFunctionalMode(context.Background(), client, true, 5, false)
	if !errors.Is(err, ErrFunctionalLevelLowering) || len(f.writes) != 0 {
		t.Fatal(result, err)
	}
}

func TestFunctionalLevelNoOpCannotEnforceExpectedVersion(t *testing.T) {
	for _, usn := range []uint64{7, 6} {
		f := newSettingsFixture()
		f.objects[operationTestDomain]["usnchanged"] = [][]byte{[]byte("7")}
		f.objects[""]["supportedcontrol"] = [][]byte{[]byte("1.3.6.1.1.12")}
		client := f.client(t)
		result, err := client.SetDomainMode(context.Background(), FunctionalLevelTransitionRequest{Identity: settingsIdentity(false), Level: 6, Options: ObjectMutationOptions{ExpectedVersion: &ObjectVersion{Source: client.config.Endpoint, GUID: objectTestGUID(), USNChanged: usn}}})
		if !errors.Is(err, ErrObjectControlUnsupported) || result.Mutation.Verified || result.Unchanged || len(f.writes) != 0 {
			t.Fatal(usn, result, err, f.writes)
		}
	}
}

func TestFunctionalLevelWriteOutcomesNeverReplay(t *testing.T) {
	cleanupFailure := errors.New("synthetic native cleanup failure")
	for _, attempt := range []ldapWriteAttempt{
		{State: ldapWriteRejected, Err: &LDAPError{Code: 10, Diagnostic: "role referral"}},
		{State: ldapWriteRejected, Err: &LDAPError{Code: 50, Diagnostic: "access denied"}},
		{State: ldapWriteUncertain, Err: context.DeadlineExceeded},
		{State: ldapWriteAccepted, Err: cleanupFailure},
	} {
		f := newSettingsFixture()
		f.attempt = attempt
		result, err := runFunctionalMode(context.Background(), f.client(t), false, 7, false)
		if err == nil || len(f.writes) != 1 || !result.PreflightComplete || result.Mutation.Verified {
			t.Fatal(result, err, f.writes)
		}
		if attempt.State == ldapWriteUncertain && (result.Mutation.State != ObjectWriteUncertain || !errors.Is(err, ErrObjectWriteUncertain)) {
			t.Fatal(result, err)
		}
		if attempt.State == ldapWriteAccepted && result.Mutation.State != ObjectWriteAccepted {
			t.Fatal(result, err)
		}
	}
}

func TestFunctionalLevelPartialReadbackRetainsAcceptedState(t *testing.T) {
	f := newSettingsFixture()
	f.write = func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		f.searchErr = &LDAPError{Code: 50}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	}
	result, err := runFunctionalMode(context.Background(), f.client(t), false, 7, false)
	if !errors.Is(err, ErrObjectReadback) || !errors.Is(err, ErrObjectWritePermission) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.After != nil || result.Mutation.ReadbackComplete || result.Mutation.Verified || len(result.Mutation.ReadbackCandidates) != 1 {
		t.Fatal(result, err)
	}
}

type settingsRangeSession struct {
	objectWriteTestSession
	readRange func(context.Context, string, []string) (map[string][][]byte, error)
}

func (s settingsRangeSession) rangedBaseObject(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
	return s.readRange(ctx, dn, properties)
}

func TestFunctionalLevelFeatureScopeRanges(t *testing.T) {
	for _, failure := range []string{"", "replacement", "partial", "gap", "missing"} {
		t.Run(failure, func(t *testing.T) {
			f := newSettingsFixture()
			featureDN := "CN=Feature,CN=Directory Service,CN=Windows NT,CN=Services," + operationTestConfig
			guid, _ := ParseGUID("12345678-1234-5678-90ab-cdef12345678")
			f.objects[featureDN] = map[string][][]byte{"objectguid": {guid.Bytes()}, "msds-enabledfeaturebl": {[]byte(settingsPartitions)}, "msds-requiredforestbehaviorversion": {[]byte("4")}}
			client := f.client(t)
			reads := 0
			client.session = settingsRangeSession{objectWriteTestSession: f.session(), readRange: func(_ context.Context, dn string, properties []string) (map[string][][]byte, error) {
				if dn != featureDN {
					t.Fatal(dn)
				}
				reads++
				attrs := map[string][][]byte{"distinguishedname": {[]byte(featureDN)}, "objectguid": {guid.Bytes()}}
				if reads == 1 {
					if properties[0] != "msDS-EnabledFeatureBL" {
						t.Fatal(properties)
					}
					attrs["msds-enabledfeaturebl;range=0-0"] = [][]byte{[]byte(settingsPartitions)}
					return attrs, nil
				}
				if reads != 2 || properties[0] != "msDS-EnabledFeatureBL;range=1-*" {
					t.Fatal(reads, properties)
				}
				attrs["msds-enabledfeaturebl;range=1-*"] = [][]byte{[]byte(operationTestTarget)}
				switch failure {
				case "replacement":
					attrs["objectguid"] = [][]byte{objectTestGUID().Bytes()}
				case "partial":
					return attrs, &LDAPError{Code: 50}
				case "gap":
					delete(attrs, "msds-enabledfeaturebl;range=1-*")
					attrs["msds-enabledfeaturebl;range=2-*"] = [][]byte{[]byte(operationTestTarget)}
				case "missing":
					delete(attrs, "msds-enabledfeaturebl;range=1-*")
				}
				return attrs, nil
			}}
			result, err := runFunctionalMode(context.Background(), client, true, 7, false)
			if reads != 2 {
				t.Fatal(reads, result, err)
			}
			if failure == "" {
				if err != nil || !result.Mutation.Verified || len(f.writes) != 1 {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, ErrIncompleteResult) || result.PreflightComplete || result.Mutation.State != ObjectWriteNotAttempted || len(f.writes) != 0 {
				t.Fatal(result, err)
			}
			last := result.Observations[len(result.Observations)-1]
			if last.DistinguishedName != featureDN || len(last.Attributes) == 0 {
				t.Fatal("raw failed/successful continuation lost", last)
			}
		})
	}
}
