package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const siloTestContainer = "CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services," + authTestConfig
const siloTestDN = "CN=Silo," + siloTestContainer

type authenticationSiloFixture struct {
	*authenticationPolicyFixture
	ranges    int
	rangeRead func(context.Context, string, []string) (map[string][][]byte, error)
}

func newAuthenticationSiloFixture() *authenticationSiloFixture {
	f := &authenticationSiloFixture{authenticationPolicyFixture: newAuthenticationPolicyFixture()}
	for i, pair := range [][2]string{{siloTestContainer, "msDS-AuthNPolicySilos"}, {siloTestDN, "msDS-AuthNPolicySilo"}} {
		object := objectTestEntry(pair[0])
		object.Attributes["objectguid"][0][0] = byte(i + 10)
		object.Attributes["objectclass"] = [][]byte{[]byte(pair[1])}
		object.Attributes["name"] = [][]byte{[]byte("Silo")}
		object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(ouTestACE(0, 0, 0x20000))}
		f.objects[pair[0]] = object
	}
	for _, object := range f.objects {
		object.Attributes["usnchanged"] = [][]byte{[]byte("1")}
	}
	f.objects[siloTestDN].Attributes["msds-authnpolicysiloenforced"] = [][]byte{[]byte("FALSE")}
	search := f.search
	f.search = func(ctx context.Context, query SearchOptions) (searchCursor, error) {
		if query.Scope != ScopeBase && strings.Contains(query.Filter, "objectClass=msDS-AuthNPolicySilo)") {
			var found []Object
			for dn, object := range f.objects {
				if dn != siloTestContainer && strings.HasSuffix(dn, ","+siloTestContainer) {
					found = append(found, Object{DistinguishedName: dn, Attributes: authTestProjection(object.Attributes, query.Properties), RequestedProperties: query.Properties})
				}
			}
			return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return found, true, f.searchError }, finish: func() error { return nil }}, nil
		}
		return search(ctx, query)
	}
	return f
}

func (f *authenticationSiloFixture) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	attempt := f.authenticationPolicyFixture.ldapWrite(ctx, request)
	if attempt.State == ldapWriteAccepted {
		for dn, object := range f.objects {
			guid, _ := GUIDFromBytes(object.Attributes["objectguid"][0])
			if dn == request.dn || request.dn == objectGUIDTarget(guid) {
				object.Attributes["usnchanged"] = [][]byte{[]byte(strconv.Itoa(len(f.writes) + 1))}
			}
		}
	}
	return attempt
}

func (f *authenticationSiloFixture) rangedBaseObject(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
	f.ranges++
	if f.rangeRead != nil {
		return f.rangeRead(ctx, dn, properties)
	}
	for _, object := range f.objects {
		guid, _ := GUIDFromBytes(object.Attributes["objectguid"][0])
		if dn != objectGUIDTarget(guid) {
			continue
		}
		result := authTestProjection(object.Attributes, []string{"objectGUID", "uSNChanged"})
		for _, property := range properties {
			name, suffix, ok := strings.Cut(property, ";range=")
			if !ok {
				continue
			}
			startText, _, _ := strings.Cut(suffix, "-")
			start, _ := strconv.Atoi(startText)
			values, present := object.Attributes[strings.ToLower(name)]
			if !present {
				continue
			}
			if len(values) == 0 {
				result[strings.ToLower(name)] = nil
				continue
			}
			if start >= len(values) {
				return nil, ErrInvalidResult
			}
			end := strconv.Itoa(start)
			if start == len(values)-1 {
				end = "*"
			}
			result[fmt.Sprintf("%s;range=%d-%s", strings.ToLower(name), start, end)] = [][]byte{slices.Clone(values[start])}
		}
		return result, nil
	}
	return nil, &LDAPError{Code: 32}
}

func (f *authenticationSiloFixture) client(t *testing.T) *Client {
	t.Helper()
	client := newClient(Config{Endpoint: Endpoint{Host: "dc.example", Port: 389}, Timeout: 5 * time.Second}, f)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func TestAuthenticationSiloLifecycleReferencesAndProjection(t *testing.T) {
	f := newAuthenticationSiloFixture()
	client := f.client(t)
	policy := authTestIdentity(authTestPolicy)
	created, err := client.CreateAuthenticationPolicySilo(context.Background(), CreateAuthenticationPolicySiloRequest{Name: "李, Silo", Properties: AuthenticationPolicySiloProperties{UserAuthenticationPolicy: &policy, ComputerAuthenticationPolicy: &policy, ServiceAuthenticationPolicy: &policy}, Attributes: map[string][]RawValue{"customBinary": {NewRawValue([]byte{0, 255})}}})
	if err != nil || !created.Mutation.Verified || len(created.PolicyObservations) != 3 || *created.Silo.Enforced || len(f.writes) != 1 {
		t.Fatal(created, err)
	}
	if *created.Silo.UserAuthenticationPolicy != authTestPolicy || !strings.Contains(created.Silo.DistinguishedName, `李\, Silo`) {
		t.Fatal(created.Silo)
	}
	id := objectGUIDIdentity(*created.Silo.GUID)
	value := true
	updated, err := client.UpdateAuthenticationPolicySilo(context.Background(), UpdateAuthenticationPolicySiloRequest{Identity: id, Properties: AuthenticationPolicySiloProperties{Enforced: &value}, Options: ObjectMutationOptions{Properties: []string{"customBinary"}}})
	if err != nil || !updated.Mutation.Verified || !*updated.Silo.Enforced {
		t.Fatal(updated, err)
	}
	if value, err := updated.Silo.Raw.Values("customBinary").Single(); err != nil || !slices.Equal(value.Bytes(), []byte{0, 255}) {
		t.Fatal(value, err)
	}
	read, err := client.AuthenticationPolicySilo(context.Background(), id, AuthenticationPolicySiloReadOptions{})
	if err != nil || !read.Members.Complete || read.Members.AttributeReturned || !read.AssignedAccounts.Complete {
		t.Fatal(read, err)
	}
	many, err := client.AuthenticationPolicySilos(context.Background(), AuthenticationPolicySiloSearchOptions{})
	if err != nil || !many.Observation.Complete || len(many.Silos) != 2 {
		t.Fatal(many, err)
	}
	deleted, err := client.DeleteAuthenticationPolicySilo(context.Background(), DeleteAuthenticationPolicySiloRequest{Identity: id})
	if err != nil || !deleted.AbsentAfter || !deleted.Verified {
		t.Fatal(deleted, err)
	}
}

func TestAuthenticationSiloGrantRevokeAndAssignmentsAreDistinct(t *testing.T) {
	f := newAuthenticationSiloFixture()
	client := f.client(t)
	silo, policy := authTestIdentity(siloTestDN), authTestIdentity(authTestPolicy)
	request := SetAccountAuthenticationPolicySiloRequest{Identity: authTestIdentity(authTestAccount), Silo: &silo, Policy: &policy}
	assigned, err := client.SetAccountAuthenticationPolicySilo(context.Background(), request)
	if err != nil || !assigned.Mutation.Verified || len(f.writes) != 1 || len(f.writes[0].modifications) != 2 || f.ranges != 0 {
		t.Fatal(assigned, err, f.writes)
	}
	if _, ok := f.objects[siloTestDN].Attributes[strings.ToLower(siloMembersAttribute)]; ok {
		t.Fatal("assignment granted access")
	}
	request.RequireGranted = true
	denied, err := client.SetAccountAuthenticationPolicySilo(context.Background(), request)
	if !errors.Is(err, ErrAuthenticationSiloGrant) || denied.Mutation.State != ObjectWriteNotAttempted || len(f.writes) != 1 {
		t.Fatal(denied, err)
	}
	unrelated := "CN=Other,DC=example"
	f.objects[siloTestDN].Attributes[strings.ToLower(siloMembersAttribute)] = [][]byte{[]byte(unrelated)}
	acl := slices.Clone(f.objects[siloTestDN].Attributes["ntsecuritydescriptor"][0])
	access := AuthenticationPolicySiloAccessRequest{Identity: silo, Account: authTestIdentity(authTestAccount)}
	granted, err := client.GrantAuthenticationPolicySiloAccess(context.Background(), access)
	if err != nil || !granted.Mutation.Verified || len(granted.Members.DistinguishedNames) != 2 || !granted.Members.Complete {
		t.Fatal(granted, err)
	}
	if !slices.Equal(acl, f.objects[siloTestDN].Attributes["ntsecuritydescriptor"][0]) {
		t.Fatal("grant modified ACL")
	}
	assigned, err = client.SetAccountAuthenticationPolicySilo(context.Background(), request)
	contains, containsErr := authenticationSiloContains(context.Background(), assigned.GrantObservation, authTestAccount)
	if err != nil || containsErr != nil || !assigned.Mutation.Verified || !contains {
		t.Fatal(assigned, err)
	}
	revoked, err := client.RevokeAuthenticationPolicySiloAccess(context.Background(), access)
	if err != nil || !revoked.Mutation.Verified || len(revoked.Members.DistinguishedNames) != 1 || revoked.Members.DistinguishedNames[0] != unrelated {
		t.Fatal(revoked, err)
	}
	if string(f.objects[authTestAccount].Attributes["msds-assignedauthnpolicysilo"][0]) != siloTestDN {
		t.Fatal("revocation cleared assignment")
	}
	cleared, err := client.SetAccountAuthenticationPolicySilo(context.Background(), SetAccountAuthenticationPolicySiloRequest{Identity: authTestIdentity(authTestAccount), ClearSilo: true, ClearPolicy: true})
	if !errors.Is(err, ErrObjectVerification) || cleared.Mutation.State != ObjectWriteAccepted || cleared.Mutation.Verified || len(f.writes[len(f.writes)-1].modifications) != 2 {
		t.Fatal(cleared, err)
	}
}

func TestAuthenticationSiloRangesRetainIncompleteObservations(t *testing.T) {
	for _, mode := range []string{"complete", "limit", "changed", "duplicate", "permission", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthenticationSiloFixture()
			object := f.objects[siloTestDN]
			object.Attributes[strings.ToLower(siloMembersAttribute)] = [][]byte{[]byte("CN=One,DC=example"), []byte("CN=Two,DC=example")}
			limit := 3
			if mode == "limit" {
				limit = 1
			}
			if mode == "duplicate" {
				object.Attributes[strings.ToLower(siloMembersAttribute)][1] = []byte("cn=ONE,dc=example")
			}
			if mode == "malformed" {
				object.Attributes[strings.ToLower(siloMembersAttribute)][1] = []byte{0xff}
			}
			if mode == "changed" || mode == "permission" {
				f.rangeRead = func(_ context.Context, _ string, properties []string) (map[string][][]byte, error) {
					attrs := authTestProjection(object.Attributes, []string{"objectGUID", "uSNChanged"})
					attrs["msds-authnpolicysilomembers;range=0-*"] = [][]byte{[]byte("CN=Partial,DC=example")}
					if mode == "changed" {
						attrs["usnchanged"] = [][]byte{[]byte("2")}
						return attrs, nil
					}
					return attrs, &LDAPError{Code: 50}
				}
			}
			read, err := f.client(t).AuthenticationPolicySilo(context.Background(), authTestIdentity(siloTestDN), AuthenticationPolicySiloReadOptions{MaxMembers: limit})
			if mode == "complete" {
				if err != nil || !read.Members.Complete || len(read.Members.DistinguishedNames) != 2 || len(read.Members.Observations) != 2 {
					t.Fatal(read, err)
				}
				return
			}
			if err == nil || read.Members.Complete || len(read.Members.Observations) == 0 || len(read.Members.DistinguishedNames) == 0 {
				t.Fatal(read, err)
			}
			if mode == "limit" && !read.Members.LimitReached {
				t.Fatal(read)
			}
		})
	}
}

func TestAuthenticationSiloMutationGuardsAndUncertainty(t *testing.T) {
	for _, mode := range []string{"missing policy", "wrong class", "LDS", "RODC", "permission", "uncertain", "partial readback"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthenticationSiloFixture()
			policy := authTestIdentity(authTestPolicy)
			switch mode {
			case "missing policy":
				delete(f.objects, authTestPolicy)
			case "wrong class":
				f.objects[siloTestDN].Attributes["objectclass"] = [][]byte{[]byte("container")}
			case "LDS":
				f.root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "RODC":
				f.root["supportedcapabilities"] = append(f.root["supportedcapabilities"], []byte("1.2.840.113556.1.4.1920"))
			case "permission":
				f.attempt = ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50, Diagnostic: "kept"}}
			case "uncertain":
				f.attempt = ldapWriteAttempt{State: ldapWriteUncertain, Err: context.DeadlineExceeded}
			case "partial readback":
				f.write = func(context.Context, ldapWriteRequest) ldapWriteAttempt {
					f.searchError = &LDAPError{Code: 50}
					return ldapWriteAttempt{State: ldapWriteAccepted}
				}
			}
			result, err := f.client(t).UpdateAuthenticationPolicySilo(context.Background(), UpdateAuthenticationPolicySiloRequest{Identity: authTestIdentity(siloTestDN), Properties: AuthenticationPolicySiloProperties{UserAuthenticationPolicy: &policy}})
			if err == nil || result.Mutation.Verified {
				t.Fatal(result, err)
			}
			switch mode {
			case "permission":
				if result.Mutation.State != ObjectWriteRejected || len(f.writes) != 1 || !errors.Is(err, ErrObjectWritePermission) {
					t.Fatal(result, err)
				}
			case "uncertain":
				if result.Mutation.State != ObjectWriteUncertain || len(f.writes) != 1 || !errors.Is(err, ErrObjectWriteUncertain) {
					t.Fatal(result, err)
				}
			case "partial readback":
				if result.Mutation.State != ObjectWriteAccepted || result.Mutation.After != nil || len(result.Mutation.ReadbackCandidates) != 1 {
					t.Fatal(result, err)
				}
			default:
				if len(f.writes) != 0 {
					t.Fatal(f.writes)
				}
			}
		})
	}
}

func TestAuthenticationSiloRejectsConflictingIntentBeforeIO(t *testing.T) {
	var client *Client
	silo, policy := authTestIdentity(siloTestDN), authTestIdentity(authTestPolicy)
	for _, request := range []SetAccountAuthenticationPolicySiloRequest{{Identity: authTestIdentity(authTestAccount)}, {Identity: authTestIdentity(authTestAccount), Silo: &silo, ClearSilo: true}, {Identity: authTestIdentity(authTestAccount), Policy: &policy, ClearPolicy: true}, {Identity: authTestIdentity(authTestAccount), RequireGranted: true, Policy: &policy}} {
		if _, err := client.SetAccountAuthenticationPolicySilo(context.Background(), request); !errors.Is(err, ErrInvalidAuthenticationSilo) {
			t.Fatal(err)
		}
	}
	_, err := client.UpdateAuthenticationPolicySilo(context.Background(), UpdateAuthenticationPolicySiloRequest{Identity: silo, Properties: AuthenticationPolicySiloProperties{UserAuthenticationPolicy: &policy}, Changes: []AttributeChange{{Attribute: "msDS-UserAuthNPolicy", Kind: AttributeClear}}})
	if err == nil || errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	_, err = client.UpdateAuthenticationPolicySilo(context.Background(), UpdateAuthenticationPolicySiloRequest{Identity: silo, Changes: []AttributeChange{{Attribute: siloMembersAttribute, Kind: AttributeClear}}})
	if !errors.Is(err, ErrInvalidAuthenticationSilo) {
		t.Fatal(err)
	}
}
