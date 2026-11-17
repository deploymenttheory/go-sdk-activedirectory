package acceptance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_authentication_silos "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_silos"
)

const (
	InternalSiloTestContainer = "CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services," + InternalAuthTestConfig
	InternalSiloTestDN        = "CN=Silo," + InternalSiloTestContainer
)

type InternalAuthenticationSiloFixture struct {
	*InternalAuthenticationPolicyFixture
	InternalRanges    int
	InternalRangeRead func(context.Context, string, []string) (map[string][][]byte, error)
}

func InternalNewAuthenticationSiloFixture() *InternalAuthenticationSiloFixture {
	f := &InternalAuthenticationSiloFixture{
		InternalAuthenticationPolicyFixture: InternalNewAuthenticationPolicyFixture(),
	}
	for i, pair := range [][2]string{{InternalSiloTestContainer, "msDS-AuthNPolicySilos"}, {InternalSiloTestDN, "msDS-AuthNPolicySilo"}} {
		object := InternalObjectTestEntry(pair[0])
		object.Attributes["objectguid"][0][0] = byte(i + 10)
		object.Attributes["objectclass"] = [][]byte{[]byte(pair[1])}
		object.Attributes["name"] = [][]byte{[]byte("Silo")}
		object.Attributes["ntsecuritydescriptor"] = [][]byte{
			InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x20000)),
		}
		f.InternalObjects[pair[0]] = object
	}
	for _, object := range f.InternalObjects {
		object.Attributes["usnchanged"] = [][]byte{[]byte("1")}
	}
	f.InternalObjects[InternalSiloTestDN].Attributes["msds-authnpolicysiloenforced"] = [][]byte{
		[]byte("FALSE"),
	}
	search := f.InternalSearch
	f.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if query.Scope != admodel.ScopeBase &&
			strings.Contains(query.Filter, "objectClass=msDS-AuthNPolicySilo)") {
			var found []admodel.Object
			for dn, object := range f.InternalObjects {
				if dn != InternalSiloTestContainer &&
					strings.HasSuffix(dn, ","+InternalSiloTestContainer) {
					found = append(
						found,
						admodel.Object{
							DistinguishedName: dn,
							Attributes: InternalAuthTestProjection(
								object.Attributes,
								query.Properties,
							),
							RequestedProperties: query.Properties,
						},
					)
				}
			}
			return InternalTestSearchCursor{
				InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
					return found, true, f.InternalSearchError
				},
				InternalFinish: func() error { return nil },
			}, nil
		}
		return search(ctx, query)
	}
	return f
}

func (f *InternalAuthenticationSiloFixture) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	attempt := f.InternalAuthenticationPolicyFixture.InternalLdapWrite(ctx, request)
	if attempt.State == admodel.InternalLdapWriteAccepted {
		for dn, object := range f.InternalObjects {
			guid, _ := admodel.GUIDFromBytes(object.Attributes["objectguid"][0])
			if dn == request.InternalDn ||
				request.InternalDn == admodel.InternalObjectGUIDTarget(guid) {
				object.Attributes["usnchanged"] = [][]byte{
					[]byte(strconv.Itoa(len(f.InternalWrites) + 1)),
				}
			}
		}
	}
	return attempt
}

func (f *InternalAuthenticationSiloFixture) InternalRangedBaseObject(
	ctx context.Context,
	dn string,
	properties []string,
) (map[string][][]byte, error) {
	f.InternalRanges++
	if f.InternalRangeRead != nil {
		return f.InternalRangeRead(ctx, dn, properties)
	}
	for _, object := range f.InternalObjects {
		guid, _ := admodel.GUIDFromBytes(object.Attributes["objectguid"][0])
		if dn != admodel.InternalObjectGUIDTarget(guid) {
			continue
		}
		result := InternalAuthTestProjection(
			object.Attributes,
			[]string{"objectGUID", "uSNChanged"},
		)
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
				return nil, admodel.ErrInvalidResult
			}
			end := strconv.Itoa(start)
			if start == len(values)-1 {
				end = "*"
			}
			result[fmt.Sprintf("%s;range=%d-%s", strings.ToLower(name), start, end)] = [][]byte{
				slices.Clone(values[start]),
			}
		}
		return result, nil
	}
	return nil, &admodel.LDAPError{Code: 32}
}

func (f *InternalAuthenticationSiloFixture) InternalClient(t *testing.T) *adengine.Client {
	t.Helper()
	client := adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example", Port: 389},
			Timeout:  5 * time.Second,
		},
		f,
	)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func TestAuthenticationSiloLifecycleReferencesAndProjection(t *testing.T) {
	f := InternalNewAuthenticationSiloFixture()
	client := f.InternalClient(t)
	policy := InternalAuthTestIdentity(InternalAuthTestPolicy)
	created, err := adservice_authentication_silos.New(client).
		CreateAuthenticationPolicySilo(context.Background(), admodel.CreateAuthenticationPolicySiloRequest{Name: "李, Silo", Properties: admodel.AuthenticationPolicySiloProperties{UserAuthenticationPolicy: &policy, ComputerAuthenticationPolicy: &policy, ServiceAuthenticationPolicy: &policy}, Attributes: map[string][]admodel.RawValue{"customBinary": {admodel.NewRawValue([]byte{0, 255})}}})
	if err != nil || !created.Mutation.Verified || len(created.PolicyObservations) != 3 ||
		*created.Silo.Enforced ||
		len(f.InternalWrites) != 1 {
		t.Fatal(created, err)
	}
	if *created.Silo.UserAuthenticationPolicy != InternalAuthTestPolicy ||
		!strings.Contains(created.Silo.DistinguishedName, `李\, Silo`) {
		t.Fatal(created.Silo)
	}
	id := admodel.InternalObjectGUIDIdentity(*created.Silo.GUID)
	value := true
	updated, err := adservice_authentication_silos.New(client).
		UpdateAuthenticationPolicySilo(context.Background(), admodel.UpdateAuthenticationPolicySiloRequest{Identity: id, Properties: admodel.AuthenticationPolicySiloProperties{Enforced: &value}, Options: admodel.ObjectMutationOptions{Properties: []string{"customBinary"}}})
	if err != nil || !updated.Mutation.Verified || !*updated.Silo.Enforced {
		t.Fatal(updated, err)
	}
	if value, err := updated.Silo.Raw.Values("customBinary").
		Single(); err != nil ||
		!slices.Equal(value.Bytes(), []byte{0, 255}) {
		t.Fatal(value, err)
	}
	read, err := adservice_authentication_silos.New(client).
		AuthenticationPolicySilo(context.Background(), id, admodel.AuthenticationPolicySiloReadOptions{})
	if err != nil || !read.Members.Complete || read.Members.AttributeReturned ||
		!read.AssignedAccounts.Complete {
		t.Fatal(read, err)
	}
	many, err := adservice_authentication_silos.New(client).
		AuthenticationPolicySilos(context.Background(), admodel.AuthenticationPolicySiloSearchOptions{})
	if err != nil || !many.Observation.Complete || len(many.Silos) != 2 {
		t.Fatal(many, err)
	}
	deleted, err := adservice_authentication_silos.New(client).
		DeleteAuthenticationPolicySilo(context.Background(), admodel.DeleteAuthenticationPolicySiloRequest{Identity: id})
	if err != nil || !deleted.AbsentAfter || !deleted.Verified {
		t.Fatal(deleted, err)
	}
}

func TestAuthenticationSiloGrantRevokeAndAssignmentsAreDistinct(t *testing.T) {
	f := InternalNewAuthenticationSiloFixture()
	client := f.InternalClient(t)
	silo, policy := InternalAuthTestIdentity(
		InternalSiloTestDN,
	), InternalAuthTestIdentity(
		InternalAuthTestPolicy,
	)
	request := admodel.SetAccountAuthenticationPolicySiloRequest{
		Identity: InternalAuthTestIdentity(InternalAuthTestAccount),
		Silo:     &silo,
		Policy:   &policy,
	}
	assigned, err := adservice_authentication_silos.New(client).
		SetAccountAuthenticationPolicySilo(context.Background(), request)
	if err != nil || !assigned.Mutation.Verified || len(f.InternalWrites) != 1 ||
		len(f.InternalWrites[0].InternalModifications) != 2 ||
		f.InternalRanges != 0 {
		t.Fatal(assigned, err, f.InternalWrites)
	}
	if _, ok := f.InternalObjects[InternalSiloTestDN].Attributes[strings.ToLower(admodel.InternalSiloMembersAttribute)]; ok {
		t.Fatal("assignment granted access")
	}
	request.RequireGranted = true
	denied, err := adservice_authentication_silos.New(client).
		SetAccountAuthenticationPolicySilo(context.Background(), request)
	if !errors.Is(err, admodel.ErrAuthenticationSiloGrant) ||
		denied.Mutation.State != admodel.ObjectWriteNotAttempted ||
		len(f.InternalWrites) != 1 {
		t.Fatal(denied, err)
	}
	unrelated := "CN=Other,DC=example"
	f.InternalObjects[InternalSiloTestDN].Attributes[strings.ToLower(admodel.InternalSiloMembersAttribute)] = [][]byte{
		[]byte(unrelated),
	}
	acl := slices.Clone(f.InternalObjects[InternalSiloTestDN].Attributes["ntsecuritydescriptor"][0])
	access := admodel.AuthenticationPolicySiloAccessRequest{
		Identity: silo,
		Account:  InternalAuthTestIdentity(InternalAuthTestAccount),
	}
	granted, err := adservice_authentication_silos.New(client).
		GrantAuthenticationPolicySiloAccess(context.Background(), access)
	if err != nil || !granted.Mutation.Verified || len(granted.Members.DistinguishedNames) != 2 ||
		!granted.Members.Complete {
		t.Fatal(granted, err)
	}
	if !slices.Equal(
		acl,
		f.InternalObjects[InternalSiloTestDN].Attributes["ntsecuritydescriptor"][0],
	) {
		t.Fatal("grant modified ACL")
	}
	assigned, err = adservice_authentication_silos.New(client).
		SetAccountAuthenticationPolicySilo(context.Background(), request)
	contains, containsErr := admodel.InternalAuthenticationSiloContains(
		context.Background(),
		assigned.GrantObservation,
		InternalAuthTestAccount,
	)
	if err != nil || containsErr != nil || !assigned.Mutation.Verified || !contains {
		t.Fatal(assigned, err)
	}
	revoked, err := adservice_authentication_silos.New(client).
		RevokeAuthenticationPolicySiloAccess(context.Background(), access)
	if err != nil || !revoked.Mutation.Verified || len(revoked.Members.DistinguishedNames) != 1 ||
		revoked.Members.DistinguishedNames[0] != unrelated {
		t.Fatal(revoked, err)
	}
	if string(
		f.InternalObjects[InternalAuthTestAccount].Attributes["msds-assignedauthnpolicysilo"][0],
	) != InternalSiloTestDN {
		t.Fatal("revocation cleared assignment")
	}
	cleared, err := adservice_authentication_silos.New(client).
		SetAccountAuthenticationPolicySilo(context.Background(), admodel.SetAccountAuthenticationPolicySiloRequest{Identity: InternalAuthTestIdentity(InternalAuthTestAccount), ClearSilo: true, ClearPolicy: true})
	if !errors.Is(err, admodel.ErrObjectVerification) ||
		cleared.Mutation.State != admodel.ObjectWriteAccepted ||
		cleared.Mutation.Verified ||
		len(f.InternalWrites[len(f.InternalWrites)-1].InternalModifications) != 2 {
		t.Fatal(cleared, err)
	}
}

func TestAuthenticationSiloRangesRetainIncompleteObservations(t *testing.T) {
	for _, mode := range []string{"complete", "limit", "changed", "duplicate", "permission", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewAuthenticationSiloFixture()
			object := f.InternalObjects[InternalSiloTestDN]
			object.Attributes[strings.ToLower(admodel.InternalSiloMembersAttribute)] = [][]byte{
				[]byte("CN=One,DC=example"),
				[]byte("CN=Two,DC=example"),
			}
			limit := 3
			if mode == "limit" {
				limit = 1
			}
			if mode == "duplicate" {
				object.Attributes[strings.ToLower(admodel.InternalSiloMembersAttribute)][1] = []byte(
					"cn=ONE,dc=example",
				)
			}
			if mode == "malformed" {
				object.Attributes[strings.ToLower(admodel.InternalSiloMembersAttribute)][1] = []byte{
					0xff,
				}
			}
			if mode == "changed" || mode == "permission" {
				f.InternalRangeRead = func(_ context.Context, _ string, properties []string) (map[string][][]byte, error) {
					attrs := InternalAuthTestProjection(
						object.Attributes,
						[]string{"objectGUID", "uSNChanged"},
					)
					attrs["msds-authnpolicysilomembers;range=0-*"] = [][]byte{
						[]byte("CN=Partial,DC=example"),
					}
					if mode == "changed" {
						attrs["usnchanged"] = [][]byte{[]byte("2")}
						return attrs, nil
					}
					return attrs, &admodel.LDAPError{Code: 50}
				}
			}
			read, err := adservice_authentication_silos.New(f.InternalClient(t)).
				AuthenticationPolicySilo(context.Background(), InternalAuthTestIdentity(InternalSiloTestDN), admodel.AuthenticationPolicySiloReadOptions{MaxMembers: limit})
			if mode == "complete" {
				if err != nil || !read.Members.Complete ||
					len(read.Members.DistinguishedNames) != 2 ||
					len(read.Members.Observations) != 2 {
					t.Fatal(read, err)
				}
				return
			}
			if err == nil || read.Members.Complete || len(read.Members.Observations) == 0 ||
				len(read.Members.DistinguishedNames) == 0 {
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
			f := InternalNewAuthenticationSiloFixture()
			policy := InternalAuthTestIdentity(InternalAuthTestPolicy)
			switch mode {
			case "missing policy":
				delete(f.InternalObjects, InternalAuthTestPolicy)
			case "wrong class":
				f.InternalObjects[InternalSiloTestDN].Attributes["objectclass"] = [][]byte{
					[]byte("container"),
				}
			case "LDS":
				f.InternalRoot["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
			case "RODC":
				f.InternalRoot["supportedcapabilities"] = append(
					f.InternalRoot["supportedcapabilities"],
					[]byte("1.2.840.113556.1.4.1920"),
				)
			case "permission":
				f.InternalAttempt = admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: 50, Diagnostic: "kept"},
				}
			case "uncertain":
				f.InternalAttempt = admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteUncertain,
					Err:   context.DeadlineExceeded,
				}
			case "partial readback":
				f.InternalWrite = func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					f.InternalSearchError = &admodel.LDAPError{Code: 50}
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				}
			}
			result, err := adservice_authentication_silos.New(f.InternalClient(t)).
				UpdateAuthenticationPolicySilo(context.Background(), admodel.UpdateAuthenticationPolicySiloRequest{Identity: InternalAuthTestIdentity(InternalSiloTestDN), Properties: admodel.AuthenticationPolicySiloProperties{UserAuthenticationPolicy: &policy}})
			if err == nil || result.Mutation.Verified {
				t.Fatal(result, err)
			}
			switch mode {
			case "permission":
				if result.Mutation.State != admodel.ObjectWriteRejected ||
					len(f.InternalWrites) != 1 ||
					!errors.Is(err, admodel.ErrObjectWritePermission) {
					t.Fatal(result, err)
				}
			case "uncertain":
				if result.Mutation.State != admodel.ObjectWriteUncertain ||
					len(f.InternalWrites) != 1 ||
					!errors.Is(err, admodel.ErrObjectWriteUncertain) {
					t.Fatal(result, err)
				}
			case "partial readback":
				if result.Mutation.State != admodel.ObjectWriteAccepted ||
					result.Mutation.After != nil ||
					len(result.Mutation.ReadbackCandidates) != 1 {
					t.Fatal(result, err)
				}
			default:
				if len(f.InternalWrites) != 0 {
					t.Fatal(f.InternalWrites)
				}
			}
		})
	}
}

func TestAuthenticationSiloRejectsConflictingIntentBeforeIO(t *testing.T) {
	var client *adengine.Client
	silo, policy := InternalAuthTestIdentity(
		InternalSiloTestDN,
	), InternalAuthTestIdentity(
		InternalAuthTestPolicy,
	)
	for _, request := range []admodel.SetAccountAuthenticationPolicySiloRequest{{Identity: InternalAuthTestIdentity(InternalAuthTestAccount)}, {Identity: InternalAuthTestIdentity(InternalAuthTestAccount), Silo: &silo, ClearSilo: true}, {Identity: InternalAuthTestIdentity(InternalAuthTestAccount), Policy: &policy, ClearPolicy: true}, {Identity: InternalAuthTestIdentity(InternalAuthTestAccount), RequireGranted: true, Policy: &policy}} {
		if _, err := adservice_authentication_silos.New(client).
			SetAccountAuthenticationPolicySilo(context.Background(), request); !errors.Is(
			err,
			admodel.ErrInvalidAuthenticationSilo,
		) {
			t.Fatal(err)
		}
	}
	_, err := adservice_authentication_silos.New(client).
		UpdateAuthenticationPolicySilo(context.Background(), admodel.UpdateAuthenticationPolicySiloRequest{Identity: silo, Properties: admodel.AuthenticationPolicySiloProperties{UserAuthenticationPolicy: &policy}, Changes: []admodel.AttributeChange{{Attribute: "msDS-UserAuthNPolicy", Kind: admodel.AttributeClear}}})
	if err == nil || errors.Is(err, admodel.ErrClosed) {
		t.Fatal(err)
	}
	_, err = adservice_authentication_silos.New(client).
		UpdateAuthenticationPolicySilo(context.Background(), admodel.UpdateAuthenticationPolicySiloRequest{Identity: silo, Changes: []admodel.AttributeChange{{Attribute: admodel.InternalSiloMembersAttribute, Kind: admodel.AttributeClear}}})
	if !errors.Is(err, admodel.ErrInvalidAuthenticationSilo) {
		t.Fatal(err)
	}
}
