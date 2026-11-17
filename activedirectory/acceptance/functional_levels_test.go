package acceptance

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_directory_settings "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/directory_settings"
)

func InternalRunFunctionalMode(
	ctx context.Context,
	client *adengine.Client,
	forest bool,
	target admodel.FunctionalLevel,
	lower bool,
) (admodel.FunctionalLevelTransitionResult, error) {
	request := admodel.FunctionalLevelTransitionRequest{
		Identity:      InternalSettingsIdentity(forest),
		Level:         target,
		AllowLowering: lower,
	}
	if forest {
		return adservice_directory_settings.New(client).SetForestMode(ctx, request)
	}
	return adservice_directory_settings.New(client).SetDomainMode(ctx, request)
}

func TestFunctionalLevelsRaiseAndLower(t *testing.T) {
	for _, forest := range []bool{false, true} {
		for _, pair := range [][3]admodel.FunctionalLevel{{6, 7, 7}, {7, 6, 7}, {7, 3, 7}, {7, 10, 10}, {10, 7, 10}} {
			t.Run(fmt.Sprintf("forest%t-%d-%d", forest, pair[0], pair[1]), func(t *testing.T) {
				f := InternalNewSettingsFixture()
				dn, rootProperty := InternalOperationTestDomain, "domainfunctionality"
				if forest {
					dn, rootProperty = InternalSettingsPartitions, "forestfunctionality"
				}
				f.InternalObjects[dn]["msds-behavior-version"] = [][]byte{
					[]byte(strconv.Itoa(int(pair[0]))),
				}
				f.InternalObjects[""][rootProperty] = f.InternalObjects[dn]["msds-behavior-version"]
				if !forest {
					f.InternalObjects[""]["forestfunctionality"] = [][]byte{[]byte("3")}
				}
				f.InternalObjects[InternalOperationTestTarget]["msds-behavior-version"] = [][]byte{
					[]byte(strconv.Itoa(int(pair[2]))),
				}
				f.InternalObjects[""]["domaincontrollerfunctionality"] = f.InternalObjects[InternalOperationTestTarget]["msds-behavior-version"]
				f.InternalObjects["CN=example,"+InternalSettingsPartitions]["msds-behavior-version"] = [][]byte{
					[]byte(strconv.Itoa(int(pair[2]))),
				}
				result, err := InternalRunFunctionalMode(
					context.Background(),
					f.InternalClient(t),
					forest,
					pair[1],
					true,
				)
				if err != nil || !result.PreflightComplete || !result.Mutation.Verified ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					len(f.InternalWrites) != 1 ||
					result.Unchanged {
					t.Fatal(result, err, f.InternalWrites)
				}
				if len(f.InternalWrites[0].InternalModifications) != 1 ||
					f.InternalWrites[0].InternalModifications[0].InternalOperation != 2 ||
					f.InternalWrites[0].InternalModifications[0].InternalAttribute != "msDS-Behavior-Version" ||
					string(
						f.InternalWrites[0].InternalModifications[0].InternalValues[0],
					) != strconv.Itoa(
						int(pair[1]),
					) {
					t.Fatal(f.InternalWrites)
				}
				if forest && result.Role != admodel.OperationMasterSchemaMaster {
					t.Fatal("forest did not use schema master", result)
				}
			})
		}
	}
}

func TestFunctionalLevelPrerequisiteRejections(t *testing.T) {
	for _, tc := range []struct {
		InternalName   string
		InternalForest bool
		InternalTarget admodel.FunctionalLevel
		InternalChange func(*InternalSettingsFixture)
		InternalWant   error
	}{
		{"unknown", false, 8, func(*InternalSettingsFixture) {}, admodel.ErrInvalidFunctionalLevel},
		{"schema", false, 7, func(f *InternalSettingsFixture) {
			f.InternalObjects[InternalOperationTestSchema]["objectversion"] = [][]byte{[]byte("69")}
		}, admodel.ErrFunctionalLevelPrerequisite},
		{"wrong PDC", false, 7, func(f *InternalSettingsFixture) {
			f.InternalObjects[InternalOperationTestDomain]["fsmoroleowner"] = [][]byte{[]byte(InternalOperationTestOld)}
		}, admodel.ErrFunctionalLevelRoleOwner},
		{"wrong schema owner", true, 7, func(f *InternalSettingsFixture) {
			f.InternalObjects[InternalOperationTestSchema]["fsmoroleowner"] = [][]byte{[]byte(InternalOperationTestOld)}
		}, admodel.ErrFunctionalLevelRoleOwner},
		{"old controller", false, 7, func(f *InternalSettingsFixture) {
			f.InternalObjects[InternalOperationTestTarget]["msds-behavior-version"] = [][]byte{[]byte("6")}
		}, admodel.ErrFunctionalLevelPrerequisite},
		{"old RODC", false, 7, func(f *InternalSettingsFixture) {
			f.InternalObjects[InternalOperationTestOld] = map[string][][]byte{"objectclass": {[]byte("nTDSDSARO")}, "msds-hasdomainncs": {[]byte(InternalOperationTestDomain)}, "msds-behavior-version": {[]byte("6")}}
		}, admodel.ErrFunctionalLevelPrerequisite},
		{"old domain", true, 7, func(f *InternalSettingsFixture) {
			f.InternalObjects["CN=example,"+InternalSettingsPartitions]["msds-behavior-version"] = [][]byte{[]byte("6")}
		}, admodel.ErrFunctionalLevelPrerequisite},
		{"mixed domain", false, 7, func(f *InternalSettingsFixture) {
			f.InternalObjects[InternalOperationTestDomain]["msds-behavior-version"] = [][]byte{[]byte("0")}
			f.InternalObjects[""]["domainfunctionality"] = [][]byte{[]byte("0")}
			f.InternalObjects[InternalOperationTestDomain]["ntmixeddomain"] = [][]byte{[]byte("1")}
		}, admodel.ErrFunctionalLevelPrerequisite},
		{"below forest", false, 5, func(*InternalSettingsFixture) {}, admodel.ErrFunctionalLevelPrerequisite},
		{"below rollback floor", true, 2, func(*InternalSettingsFixture) {}, admodel.ErrFunctionalLevelPrerequisite},
		{"2025 rollback floor", true, 5, func(f *InternalSettingsFixture) {
			f.InternalObjects[InternalOperationTestTarget]["msds-behavior-version"] = [][]byte{[]byte("10")}
		}, admodel.ErrFunctionalLevelPrerequisite},
		{"partial feature search", true, 7, func(f *InternalSettingsFixture) { f.InternalFeatureError = &admodel.LDAPError{Code: 50} }, admodel.ErrObjectWritePermission},
		{"missing schema", false, 7, func(f *InternalSettingsFixture) {
			delete(f.InternalObjects[InternalOperationTestSchema], "objectversion")
		}, admodel.ErrAttributeUnavailable},
		{"inconsistent current", false, 7, func(f *InternalSettingsFixture) { f.InternalObjects[""]["domainfunctionality"] = [][]byte{[]byte("5")} }, admodel.ErrFunctionalLevelPrerequisite},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			f := InternalNewSettingsFixture()
			tc.InternalChange(f)
			result, err := InternalRunFunctionalMode(
				context.Background(),
				f.InternalClient(t),
				tc.InternalForest,
				tc.InternalTarget,
				true,
			)
			if !errors.Is(err, tc.InternalWant) || len(f.InternalWrites) != 0 ||
				result.Mutation.State != admodel.ObjectWriteNotAttempted ||
				result.PreflightComplete {
				t.Fatal(result, err, f.InternalWrites)
			}
		})
	}
}

func TestFunctionalLevelOptionalFeatureAndPasswordRollingGuards(t *testing.T) {
	for _, forest := range []bool{true, false} {
		f := InternalNewSettingsFixture()
		attribute, scope := "msds-requireddomainbehaviorversion", InternalOperationTestDomain
		if forest {
			attribute, scope = "msds-requiredforestbehaviorversion", InternalSettingsPartitions
		}
		feature := map[string][][]byte{
			"objectclass":           {[]byte("msDS-OptionalFeature")},
			"objectguid":            {InternalObjectTestGUID().Bytes()},
			"msds-enabledfeaturebl": {[]byte(scope)},
			attribute:               {[]byte("10")},
		}
		f.InternalObjects["CN=Feature,CN=Directory Service,CN=Windows NT,CN=Services,"+InternalOperationTestConfig] = feature
		result, err := InternalRunFunctionalMode(
			context.Background(),
			f.InternalClient(t),
			forest,
			7,
			true,
		)
		if !errors.Is(err, admodel.ErrFunctionalLevelPrerequisite) || len(f.InternalWrites) != 0 ||
			len(result.Observations) < 3 {
			t.Fatal(result, err, f.InternalWrites)
		}
	}
	f := InternalNewSettingsFixture()
	f.InternalObjects[InternalOperationTestDomain]["msds-expirepasswordsonsmartcardonlyaccounts"] = [][]byte{
		[]byte("TRUE"),
	}
	f.InternalObjects[""]["forestfunctionality"] = [][]byte{[]byte("3")}
	if result, err := InternalRunFunctionalMode(
		context.Background(),
		f.InternalClient(t),
		false,
		5,
		true,
	); !errors.Is(err, admodel.ErrFunctionalLevelPrerequisite) ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
}

func TestFunctionalLevelNoOpAndExplicitLowering(t *testing.T) {
	f := InternalNewSettingsFixture()
	client := f.InternalClient(t)
	result, err := adservice_directory_settings.New(client).
		SetDomainMode(context.Background(), admodel.FunctionalLevelTransitionRequest{Identity: InternalSettingsIdentity(false), Level: 6, Options: admodel.ObjectMutationOptions{Properties: []string{"description"}}})
	if err != nil || !result.Unchanged || !result.Mutation.Verified || result.PreflightComplete ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted ||
		len(f.InternalWrites) != 0 ||
		result.Mutation.After.Values("description").State != admodel.AttributePresent {
		t.Fatal(result, err)
	}
	result, err = InternalRunFunctionalMode(context.Background(), client, true, 5, false)
	if !errors.Is(err, admodel.ErrFunctionalLevelLowering) || len(f.InternalWrites) != 0 {
		t.Fatal(result, err)
	}
}

func TestFunctionalLevelNoOpCannotEnforceExpectedVersion(t *testing.T) {
	for _, usn := range []uint64{7, 6} {
		f := InternalNewSettingsFixture()
		f.InternalObjects[InternalOperationTestDomain]["usnchanged"] = [][]byte{[]byte("7")}
		f.InternalObjects[""]["supportedcontrol"] = [][]byte{[]byte("1.3.6.1.1.12")}
		client := f.InternalClient(t)
		result, err := adservice_directory_settings.New(client).
			SetDomainMode(context.Background(), admodel.FunctionalLevelTransitionRequest{Identity: InternalSettingsIdentity(false), Level: 6, Options: admodel.ObjectMutationOptions{ExpectedVersion: &admodel.ObjectVersion{Source: (*adengine.InternalClientConfigPointer(client)).Endpoint, GUID: InternalObjectTestGUID(), USNChanged: usn}}})
		if !errors.Is(err, admodel.ErrObjectControlUnsupported) || result.Mutation.Verified ||
			result.Unchanged ||
			len(f.InternalWrites) != 0 {
			t.Fatal(usn, result, err, f.InternalWrites)
		}
	}
}

func TestFunctionalLevelWriteOutcomesNeverReplay(t *testing.T) {
	cleanupFailure := errors.New("synthetic native cleanup failure")
	for _, attempt := range []admodel.InternalLdapWriteAttempt{
		{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 10, Diagnostic: "role referral"}},
		{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 50, Diagnostic: "access denied"}},
		{State: admodel.InternalLdapWriteUncertain, Err: context.DeadlineExceeded},
		{State: admodel.InternalLdapWriteAccepted, Err: cleanupFailure},
	} {
		f := InternalNewSettingsFixture()
		f.InternalAttempt = attempt
		result, err := InternalRunFunctionalMode(
			context.Background(),
			f.InternalClient(t),
			false,
			7,
			false,
		)
		if err == nil || len(f.InternalWrites) != 1 || !result.PreflightComplete ||
			result.Mutation.Verified {
			t.Fatal(result, err, f.InternalWrites)
		}
		if attempt.State == admodel.InternalLdapWriteUncertain &&
			(result.Mutation.State != admodel.ObjectWriteUncertain || !errors.Is(err, admodel.ErrObjectWriteUncertain)) {
			t.Fatal(result, err)
		}
		if attempt.State == admodel.InternalLdapWriteAccepted &&
			result.Mutation.State != admodel.ObjectWriteAccepted {
			t.Fatal(result, err)
		}
	}
}

func TestFunctionalLevelPartialReadbackRetainsAcceptedState(t *testing.T) {
	f := InternalNewSettingsFixture()
	f.InternalWrite = func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
		f.InternalSearchErr = &admodel.LDAPError{Code: 50}
		return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
	}
	result, err := InternalRunFunctionalMode(
		context.Background(),
		f.InternalClient(t),
		false,
		7,
		false,
	)
	if !errors.Is(err, admodel.ErrObjectReadback) ||
		!errors.Is(err, admodel.ErrObjectWritePermission) ||
		result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.Mutation.After != nil ||
		result.Mutation.ReadbackComplete ||
		result.Mutation.Verified ||
		len(result.Mutation.ReadbackCandidates) != 1 {
		t.Fatal(result, err)
	}
}

type InternalSettingsRangeSession struct {
	InternalObjectWriteTestSession
	InternalReadRange func(context.Context, string, []string) (map[string][][]byte, error)
}

func (s InternalSettingsRangeSession) InternalRangedBaseObject(
	ctx context.Context,
	dn string,
	properties []string,
) (map[string][][]byte, error) {
	return s.InternalReadRange(ctx, dn, properties)
}

func TestFunctionalLevelFeatureScopeRanges(t *testing.T) {
	for _, failure := range []string{"", "replacement", "partial", "gap", "missing"} {
		t.Run(failure, func(t *testing.T) {
			f := InternalNewSettingsFixture()
			featureDN := "CN=Feature,CN=Directory Service,CN=Windows NT,CN=Services," + InternalOperationTestConfig
			guid, _ := admodel.ParseGUID("12345678-1234-5678-90ab-cdef12345678")
			f.InternalObjects[featureDN] = map[string][][]byte{
				"objectguid":                         {guid.Bytes()},
				"msds-enabledfeaturebl":              {[]byte(InternalSettingsPartitions)},
				"msds-requiredforestbehaviorversion": {[]byte("4")},
			}
			client := f.InternalClient(t)
			reads := 0
			(*adengine.InternalClientSessionPointer(client)) = InternalSettingsRangeSession{
				InternalObjectWriteTestSession: f.InternalSession(),
				InternalReadRange: func(_ context.Context, dn string, properties []string) (map[string][][]byte, error) {
					if dn != featureDN {
						t.Fatal(dn)
					}
					reads++
					attrs := map[string][][]byte{
						"distinguishedname": {[]byte(featureDN)},
						"objectguid":        {guid.Bytes()},
					}
					if reads == 1 {
						if properties[0] != "msDS-EnabledFeatureBL" {
							t.Fatal(properties)
						}
						attrs["msds-enabledfeaturebl;range=0-0"] = [][]byte{
							[]byte(InternalSettingsPartitions),
						}
						return attrs, nil
					}
					if reads != 2 || properties[0] != "msDS-EnabledFeatureBL;range=1-*" {
						t.Fatal(reads, properties)
					}
					attrs["msds-enabledfeaturebl;range=1-*"] = [][]byte{
						[]byte(InternalOperationTestTarget),
					}
					switch failure {
					case "replacement":
						attrs["objectguid"] = [][]byte{InternalObjectTestGUID().Bytes()}
					case "partial":
						return attrs, &admodel.LDAPError{Code: 50}
					case "gap":
						delete(attrs, "msds-enabledfeaturebl;range=1-*")
						attrs["msds-enabledfeaturebl;range=2-*"] = [][]byte{
							[]byte(InternalOperationTestTarget),
						}
					case "missing":
						delete(attrs, "msds-enabledfeaturebl;range=1-*")
					}
					return attrs, nil
				},
			}
			result, err := InternalRunFunctionalMode(context.Background(), client, true, 7, false)
			if reads != 2 {
				t.Fatal(reads, result, err)
			}
			if failure == "" {
				if err != nil || !result.Mutation.Verified || len(f.InternalWrites) != 1 {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, admodel.ErrIncompleteResult) || result.PreflightComplete || result.Mutation.State != admodel.ObjectWriteNotAttempted || len(f.InternalWrites) != 0 {
				t.Fatal(result, err)
			}
			last := result.Observations[len(result.Observations)-1]
			if last.DistinguishedName != featureDN || len(last.Attributes) == 0 {
				t.Fatal("raw failed/successful continuation lost", last)
			}
		})
	}
}
