package activedirectory

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fgppRange(name string, values ...string) map[string][][]byte {
	attrs := map[string][][]byte{"objectguid": {append([]byte{6}, make([]byte, 15)...)}, "usnchanged": {[]byte("7")}}
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
			client, session := newFGPPTestClient(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			options := FineGrainedPolicySubjectsOptions{Properties: []string{"description"}}
			switch mode {
			case "range-limit":
				options.MaxRanges = 1
			case "subject-limit":
				options.MaxSubjects = 1
			case "byte-limit":
				options.MaxBytes = 1
			}
			session.ranges = func(_ context.Context, target string, properties []string) (map[string][][]byte, error) {
				if !strings.HasPrefix(target, "<GUID=") {
					t.Fatal("range target is not GUID-stable", target)
				}
				if session.rangeCalls == 1 {
					if !strings.HasPrefix(properties[0], "msDS-PSOAppliesTo;range=0-") {
						t.Fatal(properties)
					}
					attrs := fgppRange("msds-psoappliesto;range=0-0", "CN=user,DC=example")
					switch mode {
					case "omitted":
						return fgppRange(""), nil
					case "empty":
						return fgppRange("msds-psoappliesto"), nil
					case "gap":
						return fgppRange("msds-psoappliesto;range=1-*", "CN=user,DC=example"), nil
					case "count":
						return fgppRange("msds-psoappliesto;range=0-1", "CN=user,DC=example"), nil
					case "duplicate-range":
						attrs["msDS-PSOAppliesTo;range=0-*"] = [][]byte{[]byte("CN=group,DC=example")}
					case "duplicate-plain":
						attrs = fgppRange("msds-psoappliesto")
						attrs["msDS-PSOAppliesTo"] = nil
					case "changed":
						attrs["usnchanged"] = [][]byte{[]byte("8")}
					case "denied":
						return attrs, &LDAPError{Code: 50}
					case "cancel":
						cancel()
					}
					return attrs, nil
				}
				if session.rangeCalls != 2 || !strings.HasPrefix(properties[0], "msDS-PSOAppliesTo;range=1-") {
					t.Fatal(properties, session.rangeCalls)
				}
				if mode == "missing-continuation" {
					return fgppRange(""), nil
				}
				attrs := fgppRange("msds-psoappliesto;range=1-*", "CN=group,DC=example")
				attrs["msds-psoappliesto"] = nil // AD can return an empty requested plain attribute beside a range.
				return attrs, nil
			}
			result, err := client.FineGrainedPasswordPolicySubjects(ctx, fgppTestIdentity(), options)
			switch mode {
			case "contiguous":
				if err != nil || !result.Complete || !result.AttributeReturned || len(result.Subjects) != 2 || session.rangeCalls != 2 || result.Version == nil {
					t.Fatal(result, err)
				}
				for _, subject := range result.Subjects {
					if subject.Observation.Object == nil || string(subject.Raw.Bytes()) != subject.DistinguishedName {
						t.Fatal(subject)
					}
				}
			case "empty", "omitted":
				if err != nil || !result.Complete || result.AttributeReturned != (mode == "empty") || len(result.Subjects) != 0 {
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
				if session.rangeCalls != wantCalls {
					t.Fatal("unexpected follow-up", session.rangeCalls)
				}
				if mode == "changed" && !errors.Is(err, ErrFineGrainedPolicyChanged) {
					t.Fatal(err)
				}
				if mode == "denied" && (len(result.Subjects) != 1 || result.Subjects[0].Observation.Object != nil || result.Ranges[0].Error == nil) {
					t.Fatal("partial raw reply lost", result)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if strings.HasSuffix(mode, "limit") && !errors.Is(err, ErrFineGrainedPolicyLimit) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFineGrainedPolicyReadFailuresPreserveRawAndAcceptedState(t *testing.T) {
	client, session := newFGPPTestClient(t)
	user, _ := IdentityByDN("CN=user,DC=example")
	session.ranges = func(context.Context, string, []string) (map[string][][]byte, error) {
		return fgppRange("msds-psoappliesto;range=0-*", "CN=user,DC=example"), &LDAPError{Code: 50}
	}
	result, err := client.AddFineGrainedPasswordPolicySubjects(context.Background(), FineGrainedPolicySubjectsRequest{Identity: fgppTestIdentity(), Subjects: []Identity{user}})
	if !errors.Is(err, ErrObjectReadback) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || len(result.After.Subjects) != 1 || len(session.writes) != 1 {
		t.Fatal(result, err)
	}

	client, session = newFGPPTestClient(t)
	object := session.objects[strings.ToLower(fgppTestDN)]
	object.Attributes["msds-psoappliesto"] = [][]byte{[]byte("CN=hidden,DC=example")}
	session.objects[strings.ToLower(fgppTestDN)] = object
	observed, err := client.FineGrainedPasswordPolicySubjects(context.Background(), fgppTestIdentity(), FineGrainedPolicySubjectsOptions{})
	if err == nil || observed.Complete || len(observed.Subjects) != 1 || observed.Subjects[0].Error == nil || len(observed.Subjects[0].Raw.Bytes()) == 0 {
		t.Fatal(observed, err)
	}
}

func TestFineGrainedPolicyLastSubjectRemovalOmissionIsUnverified(t *testing.T) {
	client, session := newFGPPTestClient(t)
	object := session.objects[strings.ToLower(fgppTestDN)]
	object.Attributes["msds-psoappliesto"] = [][]byte{[]byte("CN=user,DC=example")}
	user, _ := IdentityByDN("CN=user,DC=example")
	// LDAP normally omits an attribute after its final value is removed. The
	// same omission can result from ACL visibility, so do not fabricate proof.
	session.ranges = func(context.Context, string, []string) (map[string][][]byte, error) { return fgppRange(""), nil }
	result, err := client.RemoveFineGrainedPasswordPolicySubjects(context.Background(), FineGrainedPolicySubjectsRequest{Identity: fgppTestIdentity(), Subjects: []Identity{user}})
	if !errors.Is(err, ErrObjectVerification) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || !result.Mutation.ReadbackComplete || !result.After.Complete || result.After.AttributeReturned || len(result.After.Subjects) != 0 || len(session.writes) != 1 {
		t.Fatal(result, err)
	}
}

func TestFineGrainedPolicyTypedSearchAndExtraProperties(t *testing.T) {
	client, session := newFGPPTestClient(t)
	search := session.search
	session.search = func(ctx context.Context, query SearchOptions) (searchCursor, error) {
		if query.Scope == ScopeOneLevel {
			if query.Filter != "(&(objectClass=msDS-PasswordSettings)(name=a\\2ab))" || query.Base != fineGrainedPolicyContainer("DC=example") {
				t.Fatal(query)
			}
		}
		return search(ctx, query)
	}
	result, err := client.FineGrainedPasswordPolicies(context.Background(), SearchOptions{TypedFilter: FilterEqual("name", FilterText("a*b")), Properties: []string{"info"}})
	if err != nil || len(result.Policies) != 1 || !result.Observation.Complete {
		t.Fatal(result, err)
	}
	if _, err := client.FineGrainedPasswordPolicies(context.Background(), SearchOptions{TypedFilter: FilterPresent("name"), Filter: "(name=*)"}); !errors.Is(err, ErrConflictingFilters) {
		t.Fatal(err)
	}
	object := session.objects[strings.ToLower(fgppTestDN)]
	object.Attributes["info"] = [][]byte{[]byte{0, 1, 255}}
	session.objects[strings.ToLower(fgppTestDN)] = object
	read, err := client.FineGrainedPasswordPolicy(context.Background(), fgppTestIdentity(), ResolveIdentityOptions{Properties: []string{"info"}})
	if err != nil || len(read.Policy.Raw.Attributes["info"]) != 1 {
		t.Fatal(read, err)
	}
	updated, err := client.UpdateFineGrainedPasswordPolicy(context.Background(), UpdateFineGrainedPasswordPolicyRequest{Identity: fgppTestIdentity(), Description: fgppPointer("changed"), Options: ObjectMutationOptions{Properties: []string{"info"}}})
	if err != nil || !updated.Mutation.Verified || len(updated.Policy.Raw.Attributes["info"]) != 1 {
		t.Fatal(updated, err)
	}
}
