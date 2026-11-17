package acceptance

import (
	"context"
	"errors"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_password_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/password_policies"
)

func InternalFgppRange(name string, values ...string) map[string][][]byte {
	attrs := map[string][][]byte{
		"objectguid": {append([]byte{6}, make([]byte, 15)...)},
		"usnchanged": {[]byte("7")},
	}
	if name != "" {
		attrs[name] = nil
		for _, value := range values {
			attrs[name] = append(attrs[name], []byte(value))
		}
	}
	return attrs
}

func TestFineGrainedPolicySubjectRangesAndVisibility(t *testing.T) {
	for _, mode := range []string{"contiguous", "omitted", "empty", "gap", "count", "duplicate-range", "duplicate-plain", "missing-continuation", "changed", "denied", "cancel", "range-limit", "subject-limit", "byte-limit"} {
		t.Run(mode, func(t *testing.T) {
			client, session := InternalNewFGPPTestClient(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			options := admodel.FineGrainedPolicySubjectsOptions{Properties: []string{"description"}}
			switch mode {
			case "range-limit":
				options.MaxRanges = 1
			case "subject-limit":
				options.MaxSubjects = 1
			case "byte-limit":
				options.MaxBytes = 1
			}
			session.InternalRanges = func(_ context.Context, target string, properties []string) (map[string][][]byte, error) {
				if !strings.HasPrefix(target, "<GUID=") {
					t.Fatal("range target is not GUID-stable", target)
				}
				if session.InternalRangeCalls == 1 {
					if !strings.HasPrefix(properties[0], "msDS-PSOAppliesTo;range=0-") {
						t.Fatal(properties)
					}
					attrs := InternalFgppRange("msds-psoappliesto;range=0-0", "CN=user,DC=example")
					switch mode {
					case "omitted":
						return InternalFgppRange(""), nil
					case "empty":
						return InternalFgppRange("msds-psoappliesto"), nil
					case "gap":
						return InternalFgppRange(
							"msds-psoappliesto;range=1-*",
							"CN=user,DC=example",
						), nil
					case "count":
						return InternalFgppRange(
							"msds-psoappliesto;range=0-1",
							"CN=user,DC=example",
						), nil
					case "duplicate-range":
						attrs["msDS-PSOAppliesTo;range=0-*"] = [][]byte{
							[]byte("CN=group,DC=example"),
						}
					case "duplicate-plain":
						attrs = InternalFgppRange("msds-psoappliesto")
						attrs["msDS-PSOAppliesTo"] = nil
					case "changed":
						attrs["usnchanged"] = [][]byte{[]byte("8")}
					case "denied":
						return attrs, &admodel.LDAPError{Code: 50}
					case "cancel":
						cancel()
					}
					return attrs, nil
				}
				if session.InternalRangeCalls != 2 ||
					!strings.HasPrefix(properties[0], "msDS-PSOAppliesTo;range=1-") {
					t.Fatal(properties, session.InternalRangeCalls)
				}
				if mode == "missing-continuation" {
					return InternalFgppRange(""), nil
				}
				attrs := InternalFgppRange("msds-psoappliesto;range=1-*", "CN=group,DC=example")
				attrs["msds-psoappliesto"] = nil // AD can return an empty requested plain attribute beside a range.
				return attrs, nil
			}
			result, err := adservice_password_policies.New(client).
				FineGrainedPasswordPolicySubjects(ctx, InternalFgppTestIdentity(), options)
			switch mode {
			case "contiguous":
				if err != nil || !result.Complete || !result.AttributeReturned ||
					len(result.Subjects) != 2 ||
					session.InternalRangeCalls != 2 ||
					result.Version == nil {
					t.Fatal(result, err)
				}
				for _, subject := range result.Subjects {
					if subject.Observation.Object == nil ||
						string(subject.Raw.Bytes()) != subject.DistinguishedName {
						t.Fatal(subject)
					}
				}
			case "empty", "omitted":
				if err != nil || !result.Complete ||
					result.AttributeReturned != (mode == "empty") ||
					len(result.Subjects) != 0 {
					t.Fatal(result, err)
				}
			default:
				if err == nil || result.Complete || len(result.Ranges) == 0 {
					t.Fatal(result, err)
				}
				wantCalls := 1
				if mode == "missing-continuation" {
					wantCalls = 2
				}
				if session.InternalRangeCalls != wantCalls {
					t.Fatal("unexpected follow-up", session.InternalRangeCalls)
				}
				if mode == "changed" && !errors.Is(err, admodel.ErrFineGrainedPolicyChanged) {
					t.Fatal(err)
				}
				if mode == "denied" &&
					(len(result.Subjects) != 1 || result.Subjects[0].Observation.Object != nil || result.Ranges[0].Error == nil) {
					t.Fatal("partial raw reply lost", result)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if strings.HasSuffix(mode, "limit") &&
					!errors.Is(err, admodel.ErrFineGrainedPolicyLimit) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFineGrainedPolicyReadFailuresPreserveRawAndAcceptedState(t *testing.T) {
	client, session := InternalNewFGPPTestClient(t)
	user, _ := admodel.IdentityByDN("CN=user,DC=example")
	session.InternalRanges = func(context.Context, string, []string) (map[string][][]byte, error) {
		return InternalFgppRange(
				"msds-psoappliesto;range=0-*",
				"CN=user,DC=example",
			), &admodel.LDAPError{
				Code: 50,
			}
	}
	result, err := adservice_password_policies.New(client).
		AddFineGrainedPasswordPolicySubjects(context.Background(), admodel.FineGrainedPolicySubjectsRequest{Identity: InternalFgppTestIdentity(), Subjects: []admodel.Identity{user}})
	if !errors.Is(err, admodel.ErrObjectReadback) ||
		result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.Mutation.Verified ||
		len(result.After.Subjects) != 1 ||
		len(session.InternalWrites) != 1 {
		t.Fatal(result, err)
	}

	client, session = InternalNewFGPPTestClient(t)
	object := session.InternalObjects[strings.ToLower(InternalFgppTestDN)]
	object.Attributes["msds-psoappliesto"] = [][]byte{[]byte("CN=hidden,DC=example")}
	session.InternalObjects[strings.ToLower(InternalFgppTestDN)] = object
	observed, err := adservice_password_policies.New(client).
		FineGrainedPasswordPolicySubjects(context.Background(), InternalFgppTestIdentity(), admodel.FineGrainedPolicySubjectsOptions{})
	if err == nil || observed.Complete || len(observed.Subjects) != 1 ||
		observed.Subjects[0].Error == nil ||
		len(observed.Subjects[0].Raw.Bytes()) == 0 {
		t.Fatal(observed, err)
	}
}

func TestFineGrainedPolicyLastSubjectRemovalOmissionIsUnverified(t *testing.T) {
	client, session := InternalNewFGPPTestClient(t)
	object := session.InternalObjects[strings.ToLower(InternalFgppTestDN)]
	object.Attributes["msds-psoappliesto"] = [][]byte{[]byte("CN=user,DC=example")}
	user, _ := admodel.IdentityByDN("CN=user,DC=example")
	// LDAP normally omits an attribute after its final value is removed. The
	// same omission can result from ACL visibility, so do not fabricate proof.
	session.InternalRanges = func(context.Context, string, []string) (map[string][][]byte, error) {
		return InternalFgppRange(""), nil
	}
	result, err := adservice_password_policies.New(client).
		RemoveFineGrainedPasswordPolicySubjects(context.Background(), admodel.FineGrainedPolicySubjectsRequest{Identity: InternalFgppTestIdentity(), Subjects: []admodel.Identity{user}})
	if !errors.Is(err, admodel.ErrObjectVerification) ||
		result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.Mutation.Verified ||
		!result.Mutation.ReadbackComplete ||
		!result.After.Complete ||
		result.After.AttributeReturned ||
		len(result.After.Subjects) != 0 ||
		len(session.InternalWrites) != 1 {
		t.Fatal(result, err)
	}
}

func TestFineGrainedPolicyTypedSearchAndExtraProperties(t *testing.T) {
	client, session := InternalNewFGPPTestClient(t)
	search := session.InternalSearch
	session.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if query.Scope == admodel.ScopeOneLevel {
			if query.Filter != "(&(objectClass=msDS-PasswordSettings)(name=a\\2ab))" ||
				query.Base != admodel.InternalFineGrainedPolicyContainer("DC=example") {
				t.Fatal(query)
			}
		}
		return search(ctx, query)
	}
	result, err := adservice_password_policies.New(client).
		FineGrainedPasswordPolicies(context.Background(), admodel.SearchOptions{TypedFilter: admodel.FilterEqual("name", admodel.FilterText("a*b")), Properties: []string{"info"}})
	if err != nil || len(result.Policies) != 1 || !result.Observation.Complete {
		t.Fatal(result, err)
	}
	if _, err := adservice_password_policies.New(client).
		FineGrainedPasswordPolicies(context.Background(), admodel.SearchOptions{TypedFilter: admodel.FilterPresent("name"), Filter: "(name=*)"}); !errors.Is(
		err,
		admodel.ErrConflictingFilters,
	) {
		t.Fatal(err)
	}
	object := session.InternalObjects[strings.ToLower(InternalFgppTestDN)]
	object.Attributes["info"] = [][]byte{{0, 1, 255}}
	session.InternalObjects[strings.ToLower(InternalFgppTestDN)] = object
	read, err := adservice_password_policies.New(client).
		FineGrainedPasswordPolicy(context.Background(), InternalFgppTestIdentity(), admodel.ResolveIdentityOptions{Properties: []string{"info"}})
	if err != nil || len(read.Policy.Raw.Attributes["info"]) != 1 {
		t.Fatal(read, err)
	}
	updated, err := adservice_password_policies.New(client).
		UpdateFineGrainedPasswordPolicy(context.Background(), admodel.UpdateFineGrainedPasswordPolicyRequest{Identity: InternalFgppTestIdentity(), Description: InternalFgppPointer("changed"), Options: admodel.ObjectMutationOptions{Properties: []string{"info"}}})
	if err != nil || !updated.Mutation.Verified || len(updated.Policy.Raw.Attributes["info"]) != 1 {
		t.Fatal(updated, err)
	}
}
