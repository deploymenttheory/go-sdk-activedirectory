package acceptance

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_authentication_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
)

const (
	InternalAuthTestConfig    = "CN=Configuration,DC=example"
	InternalAuthTestSchema    = "CN=Schema," + InternalAuthTestConfig
	InternalAuthTestContainer = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services," + InternalAuthTestConfig
	InternalAuthTestPolicy    = "CN=Policy," + InternalAuthTestContainer
	InternalAuthTestAccount   = "CN=Account,DC=example"
	InternalAuthTestDSA       = "CN=NTDS Settings,CN=DC,CN=Servers,CN=Site,CN=Sites," + InternalAuthTestConfig
)

type InternalAuthenticationPolicyFixture struct {
	InternalTestSession
	InternalRoot        map[string][][]byte
	InternalObjects     map[string]admodel.Object
	InternalWrites      []admodel.InternalLdapWriteRequest
	InternalAttempt     admodel.InternalLdapWriteAttempt
	InternalWrite       func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt
	InternalSearchError error
}

func InternalNewAuthenticationPolicyFixture() *InternalAuthenticationPolicyFixture {
	f := &InternalAuthenticationPolicyFixture{
		InternalRoot:    InternalIdentityTestRoot(admodel.CapabilityActiveDirectory),
		InternalObjects: map[string]admodel.Object{},
		InternalAttempt: admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted},
	}
	f.InternalRoot["configurationnamingcontext"] = [][]byte{[]byte(InternalAuthTestConfig)}
	f.InternalRoot["schemanamingcontext"] = [][]byte{[]byte(InternalAuthTestSchema)}
	f.InternalRoot["domaincontrollerfunctionality"], f.InternalRoot["domainfunctionality"] = [][]byte{
		[]byte("7"),
	}, [][]byte{
		[]byte("7"),
	}
	f.InternalRoot["issynchronized"], f.InternalRoot["dsservicename"] = [][]byte{
		[]byte("TRUE"),
	}, [][]byte{
		[]byte(InternalAuthTestDSA),
	}
	f.InternalRoot["supportedcontrol"] = [][]byte{[]byte(admodel.InternalDirectorySDFlagsControl)}
	for i, pair := range [][2]string{{InternalAuthTestContainer, "msDS-AuthNPolicies"}, {InternalAuthTestPolicy, "msDS-AuthNPolicy"}, {InternalAuthTestAccount, "user"}} {
		object := InternalObjectTestEntry(pair[0])
		object.Attributes["objectguid"][0][0] = byte(i + 1)
		object.Attributes["objectclass"] = [][]byte{[]byte(pair[1])}
		object.Attributes["name"], object.Attributes["description"] = [][]byte{
			[]byte("Policy"),
		}, [][]byte{
			[]byte("unchanged"),
		}
		object.Attributes["ntsecuritydescriptor"] = [][]byte{
			InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x20000)),
		}
		f.InternalObjects[pair[0]] = object
	}
	f.InternalObjects[InternalAuthTestPolicy].Attributes["msds-authnpolicyenforced"] = [][]byte{
		[]byte("FALSE"),
	}
	f.InternalObjects[InternalAuthTestAccount].Attributes["objectsid"] = [][]byte{
		{1, 1, 0, 0, 0, 0, 0, 5, 42, 0, 0, 0},
	}
	f.InternalObjects[InternalAuthTestAccount].Attributes["samaccountname"] = [][]byte{
		[]byte("account"),
	}
	f.InternalObjects[InternalAuthTestAccount].Attributes["msds-assignedauthnpolicysilo"] = [][]byte{
		[]byte("CN=ExistingSilo," + InternalAuthTestConfig),
	}
	f.InternalBase = func(_ context.Context, dn string, properties []string) (map[string][][]byte, error) {
		switch dn {
		case "":
			return InternalAuthTestProjection(f.InternalRoot, properties), nil
		case InternalAuthTestDSA:
			return map[string][][]byte{
				"objectclass": {[]byte("nTDSDSA")},
				"msds-isrodc": {[]byte("FALSE")},
			}, nil
		case InternalAuthTestSchema:
			return map[string][][]byte{"objectversion": {[]byte("87")}}, nil
		}
		object, ok := f.InternalObjects[dn]
		if !ok {
			return nil, &admodel.LDAPError{Code: 32}
		}
		return InternalAuthTestProjection(object.Attributes, properties), nil
	}
	f.InternalSearch = func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		if strings.Contains(query.Filter, "classSchema") {
			return InternalObjectTestCursor(
				admodel.Object{
					DistinguishedName: "CN=ms-DS-AuthN-Policy," + InternalAuthTestSchema,
					Attributes: map[string][][]byte{
						"rdnattid":            {[]byte("cn")},
						"objectclasscategory": {[]byte("1")},
					},
				},
			), nil
		}
		var found []admodel.Object
		for dn, object := range f.InternalObjects {
			match := false
			switch {
			case query.Scope == admodel.ScopeBase:
				match = admodel.InternalSameAuthenticationDN(query.Base, dn)
			case strings.Contains(query.Filter, "objectGUID="):
				match = strings.Contains(
					query.Filter,
					admodel.InternalIdentityBinaryLiteral(object.Attributes["objectguid"][0]),
				)
			case strings.Contains(query.Filter, "sAMAccountName="):
				match = dn == InternalAuthTestAccount
			case strings.Contains(query.Filter, "msDS-AuthNPolicy"):
				match = dn != InternalAuthTestContainer &&
					strings.HasSuffix(dn, ","+InternalAuthTestContainer)
			}
			if match {
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
	f.InternalFinish = func() error { return nil }
	return f
}

func InternalAuthTestProjection(
	attrs map[string][][]byte,
	properties []string,
) map[string][][]byte {
	result := map[string][][]byte{}
	for _, name := range properties {
		key := strings.ToLower(name)
		if values, ok := attrs[key]; ok {
			result[key] = make([][]byte, len(values))
			for i, value := range values {
				result[key][i] = slices.Clone(value)
			}
		}
	}
	return result
}

func (f *InternalAuthenticationPolicyFixture) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	f.InternalWrites = append(f.InternalWrites, request)
	attempt := f.InternalAttempt
	if f.InternalWrite != nil {
		attempt = f.InternalWrite(ctx, request)
	}
	if attempt.State != admodel.InternalLdapWriteAccepted {
		return attempt
	}
	if request.InternalOperation == admodel.InternalLdapWriteAdd {
		object := InternalObjectTestEntry(request.InternalDn)
		object.Attributes["objectguid"][0][0] = 100
		object.Attributes["ntsecuritydescriptor"] = [][]byte{
			InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x20000)),
		}
		for _, mod := range request.InternalModifications {
			object.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
			if strings.EqualFold(mod.InternalAttribute, "cn") {
				object.Attributes["name"] = mod.InternalValues
			}
		}
		f.InternalObjects[request.InternalDn] = object
		return attempt
	}
	for dn, object := range f.InternalObjects {
		guid, _ := admodel.GUIDFromBytes(object.Attributes["objectguid"][0])
		if request.InternalDn != admodel.InternalObjectGUIDTarget(guid) {
			continue
		}
		if request.InternalOperation == admodel.InternalLdapWriteDelete {
			delete(f.InternalObjects, dn)
			return attempt
		}
		for _, mod := range request.InternalModifications {
			name := strings.ToLower(mod.InternalAttribute)
			switch mod.InternalOperation {
			case 2:
				object.Attributes[name] = mod.InternalValues
			case 0:
				object.Attributes[name] = append(object.Attributes[name], mod.InternalValues...)
			case 1:
				if len(mod.InternalValues) == 0 {
					delete(object.Attributes, name)
				} else {
					object.Attributes[name] = slices.DeleteFunc(
						object.Attributes[name],
						func(value []byte) bool {
							return slices.ContainsFunc(
								mod.InternalValues,
								func(old []byte) bool { return slices.Equal(value, old) },
							)
						},
					)
				}
			}
		}
	}
	return attempt
}

func (f *InternalAuthenticationPolicyFixture) InternalReadOUDACL(
	_ context.Context,
	dn string,
) (admodel.Object, error) {
	for _, object := range f.InternalObjects {
		guid, _ := admodel.GUIDFromBytes(object.Attributes["objectguid"][0])
		if dn == object.DistinguishedName || dn == admodel.InternalObjectGUIDTarget(guid) {
			return admodel.Object{
				DistinguishedName: object.DistinguishedName,
				Attributes: InternalAuthTestProjection(
					object.Attributes,
					[]string{"objectGUID", "uSNChanged", "nTSecurityDescriptor"},
				),
				SecurityDescriptorSections: 4,
			}, nil
		}
	}
	return admodel.Object{}, &admodel.LDAPError{Code: 32}
}

func (*InternalAuthenticationPolicyFixture) InternalEditOUDACL(
	raw []byte,
	mask uint32,
	protect bool,
) ([]byte, bool, error) {
	acl, err := admodel.InternalDecodeOUDACL(raw)
	if err != nil {
		return nil, false, err
	}
	aces, changed := admodel.InternalChangeOUACEs(acl, mask, protect)
	return InternalOuTestDescriptor(aces...), changed, nil
}

func (f *InternalAuthenticationPolicyFixture) InternalClient(t *testing.T) *adengine.Client {
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

func InternalAuthTestIdentity(dn string) admodel.Identity {
	identity, _ := admodel.IdentityByDN(dn)
	return identity
}

func TestAuthenticationPolicyCreateUpdateReadDelete(t *testing.T) {
	f := InternalNewAuthenticationPolicyFixture()
	client := f.InternalClient(t)
	zero := admodel.Interval100ns(0)
	exact := admodel.Interval100ns(600000001)
	enforced := true
	rolling := admodel.StrongNTLMOptional
	result, err := adservice_authentication_policies.New(client).
		CreateAuthenticationPolicy(context.Background(), admodel.CreateAuthenticationPolicyRequest{Name: "Cymru, 李", Properties: admodel.AuthenticationPolicyProperties{UserTGTLifetime: &exact, ComputerTGTLifetime: &zero, ServiceTGTLifetime: &exact, UserAllowedNTLMNetworkAuthentication: &enforced, RollingNTLMSecret: &rolling}, Attributes: map[string][]admodel.RawValue{"extensionBinary": {admodel.NewRawValue([]byte{0, 255}), admodel.NewRawValue([]byte{})}}})
	if err != nil || !result.Mutation.Verified || result.Policy == nil ||
		result.Policy.Enforced == nil ||
		*result.Policy.Enforced ||
		*result.Policy.UserTGTLifetime != exact ||
		len(f.InternalWrites) != 1 {
		t.Fatal(result, err, f.InternalWrites)
	}
	for _, mod := range f.InternalWrites[0].InternalModifications {
		if mod.InternalOperation != 0 {
			t.Fatal("Add used Modify opcode", mod)
		}
	}
	if !strings.Contains(result.Mutation.TargetDN, `cn=Cymru\, 李,`) {
		t.Fatal(result.Mutation.TargetDN)
	}
	identity := admodel.InternalObjectGUIDIdentity(*result.Mutation.TargetGUID)
	updated, err := adservice_authentication_policies.New(client).
		UpdateAuthenticationPolicy(context.Background(), admodel.UpdateAuthenticationPolicyRequest{Identity: identity, Properties: admodel.AuthenticationPolicyProperties{Enforced: &enforced}})
	if err != nil || !updated.Mutation.Verified || !*updated.Policy.Enforced ||
		*updated.Policy.UserTGTLifetime != exact {
		t.Fatal(updated, err)
	}
	read, err := adservice_authentication_policies.New(client).
		AuthenticationPolicy(context.Background(), identity, admodel.ResolveIdentityOptions{Properties: []string{"extensionBinary"}})
	if err != nil || read.Policy.Raw.Values("extensionBinary").State != admodel.AttributePresent {
		t.Fatal(read, err)
	}
	deleted, err := adservice_authentication_policies.New(client).
		DeleteAuthenticationPolicy(context.Background(), admodel.DeleteAuthenticationPolicyRequest{Identity: identity})
	if err != nil || !deleted.AbsentAfter || deleted.State != admodel.ObjectWriteAccepted {
		t.Fatal(deleted, err)
	}
}

func TestAuthenticationPolicyAssignmentsPreserveSiloAndClearExplicitly(t *testing.T) {
	for _, class := range []string{"user", "computer", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"} {
		t.Run(class, func(t *testing.T) {
			f := InternalNewAuthenticationPolicyFixture()
			f.InternalObjects[InternalAuthTestAccount].Attributes["objectclass"] = [][]byte{
				[]byte("user"),
				[]byte(class),
			}
			client := f.InternalClient(t)
			account, _ := admodel.IdentityByAccountName("account")
			policy := InternalAuthTestIdentity(InternalAuthTestPolicy)
			result, err := adservice_authentication_policies.New(client).
				SetAccountAuthenticationPolicy(context.Background(), admodel.SetAccountAuthenticationPolicyRequest{Identity: account, Policy: &policy})
			if err != nil || !result.Mutation.Verified || result.Policy == nil ||
				len(f.InternalWrites) != 1 ||
				len(f.InternalWrites[0].InternalModifications) != 1 {
				t.Fatal(result, err, f.InternalWrites)
			}
			if result.Mutation.After.Values(
				"msDS-AssignedAuthNPolicySilo",
			).State != admodel.AttributePresent {
				t.Fatal("silo projection lost")
			}
			result, err = adservice_authentication_policies.New(client).
				SetAccountAuthenticationPolicy(context.Background(), admodel.SetAccountAuthenticationPolicyRequest{Identity: account, Clear: true})
			if !errors.Is(err, admodel.ErrObjectUnverifiable) ||
				result.Mutation.State != admodel.ObjectWriteAccepted ||
				result.Mutation.Verified ||
				f.InternalWrites[1].InternalModifications[0].InternalOperation != 1 ||
				len(f.InternalWrites[1].InternalModifications[0].InternalValues) != 0 {
				t.Fatal(result, err, f.InternalWrites)
			}
		})
	}
}

func TestAuthenticationPolicyProtectionHasSeparateOutcomes(t *testing.T) {
	f := InternalNewAuthenticationPolicyFixture()
	// This owned fixture models an assertion-capable server, not AD support.
	f.InternalRoot["supportedcontrol"] = append(f.InternalRoot["supportedcontrol"], []byte(admodel.InternalObjectAssertionControl))
	protect := true
	count := 0
	f.InternalWrite = func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
		count++
		if count == 3 {
			return admodel.InternalLdapWriteAttempt{
				State: admodel.InternalLdapWriteUncertain,
				Err:   context.DeadlineExceeded,
			}
		}
		return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
	}
	result, err := adservice_authentication_policies.New(f.InternalClient(t)).
		CreateAuthenticationPolicy(context.Background(), admodel.CreateAuthenticationPolicyRequest{Name: "Protected", ProtectedFromAccidentalDeletion: &protect})
	if !errors.Is(err, admodel.ErrObjectWriteUncertain) ||
		result.Mutation.State != admodel.ObjectWriteAccepted ||
		len(result.Protection.Steps) != 2 ||
		result.Protection.Steps[0].State != admodel.ObjectWriteAccepted ||
		result.Protection.Steps[1].State != admodel.ObjectWriteUncertain ||
		len(f.InternalWrites) != 3 {
		t.Fatal(result, err, f.InternalWrites)
	}
}

func TestAuthenticationPolicyInputConflictsBeforeIO(t *testing.T) {
	var client *adengine.Client
	enforce := true
	negative := admodel.Interval100ns(-1)
	for _, request := range []admodel.UpdateAuthenticationPolicyRequest{
		{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy)},
		{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy), Properties: admodel.AuthenticationPolicyProperties{Enforced: &enforce}, Changes: []admodel.AttributeChange{admodel.InternalAuthenticationSetting("msDS-AuthNPolicyEnforced", "FALSE")}},
		{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy), Properties: admodel.AuthenticationPolicyProperties{UserTGTLifetime: &negative}},
		{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy), Changes: []admodel.AttributeChange{admodel.InternalAuthenticationSetting("msDS-UserAllowedToAuthenticateFrom", "not binary")}},
	} {
		if _, err := adservice_authentication_policies.New(client).
			UpdateAuthenticationPolicy(context.Background(), request); err == nil ||
			errors.Is(err, admodel.ErrClosed) {
			t.Fatal(err)
		}
	}
	for _, request := range []admodel.SetAccountAuthenticationPolicyRequest{{Identity: InternalAuthTestIdentity(InternalAuthTestAccount)}, {Identity: InternalAuthTestIdentity(InternalAuthTestAccount), Clear: true, Policy: func() *admodel.Identity { x := InternalAuthTestIdentity(InternalAuthTestPolicy); return &x }()}} {
		if _, err := adservice_authentication_policies.New(client).
			SetAccountAuthenticationPolicy(context.Background(), request); !errors.Is(
			err,
			admodel.ErrInvalidAuthenticationPolicy,
		) {
			t.Fatal(err)
		}
	}
}

func TestAuthenticationPolicyWholeWorkflowTimeout(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := InternalNewAuthenticationPolicyFixture()
			original := f.InternalBase
			reads := 0
			var deadline time.Time
			f.InternalBase = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
				if dn == "" {
					reads++
					current, ok := ctx.Deadline()
					if !ok {
						t.Fatal("no timeout")
					}
					if reads == 1 {
						// The first stage records the deadline and returns at
						// once. It deliberately burns none of the budget: the
						// second stage's equality check is what proves the
						// timeout is shared, and a stall here only risks the
						// budget expiring before the second stage is reached on
						// a loaded runner, which aborts after one read.
						deadline = current
					} else {
						if !current.Equal(deadline) {
							t.Fatal("second stage reset timeout", deadline, current)
						}
						<-ctx.Done()
						return nil, context.Cause(ctx)
					}
				}
				return original(ctx, dn, properties)
			}
			client := f.InternalClient(t)
			// Generous enough that reaching the second stage cannot race the
			// deadline; the second stage still waits for a real expiry.
			(*adengine.InternalClientConfigPointer(client)).Timeout = 400 * time.Millisecond
			var err error
			switch operation {
			case "create":
				_, err = adservice_authentication_policies.New(client).
					CreateAuthenticationPolicy(context.Background(), admodel.CreateAuthenticationPolicyRequest{Name: "new"})
			case "update":
				value := true
				_, err = adservice_authentication_policies.New(client).
					UpdateAuthenticationPolicy(context.Background(), admodel.UpdateAuthenticationPolicyRequest{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy), Properties: admodel.AuthenticationPolicyProperties{Enforced: &value}})
			case "delete":
				_, err = adservice_authentication_policies.New(client).
					DeleteAuthenticationPolicy(context.Background(), admodel.DeleteAuthenticationPolicyRequest{Identity: InternalAuthTestIdentity(InternalAuthTestPolicy)})
			}
			if !errors.Is(err, context.DeadlineExceeded) || len(f.InternalWrites) != 0 ||
				reads != 2 {
				t.Fatal(err, reads, f.InternalWrites)
			}
		})
	}
}

func TestAuthenticationPolicyPrerequisitesAndReadbackFailures(t *testing.T) {
	for _, mode := range []string{"LDS", "old DC", "old domain", "GC", "wrong class", "wrong container", "permission", "uncertain", "readback"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewAuthenticationPolicyFixture()
			client := f.InternalClient(t)
			identity := InternalAuthTestIdentity(InternalAuthTestPolicy)
			switch mode {
			case "LDS":
				f.InternalRoot["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
			case "old DC":
				f.InternalRoot["domaincontrollerfunctionality"] = [][]byte{[]byte("5")}
			case "old domain":
				f.InternalRoot["domainfunctionality"] = [][]byte{[]byte("5")}
			case "GC":
				(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268
			case "wrong class":
				f.InternalObjects[InternalAuthTestPolicy].Attributes["objectclass"] = [][]byte{
					[]byte("container"),
				}
			case "wrong container":
				identity = InternalAuthTestIdentity(InternalAuthTestContainer)
			case "permission":
				f.InternalAttempt = admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: 50, Diagnostic: "retained diagnostic"},
				}
			case "uncertain":
				f.InternalAttempt = admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteUncertain,
					Err:   context.DeadlineExceeded,
				}
			case "readback":
				f.InternalWrite = func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					f.InternalSearchError = &admodel.LDAPError{Code: 50}
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				}
			}
			value := true
			result, err := adservice_authentication_policies.New(client).
				UpdateAuthenticationPolicy(context.Background(), admodel.UpdateAuthenticationPolicyRequest{Identity: identity, Properties: admodel.AuthenticationPolicyProperties{Enforced: &value}})
			if err == nil || result.Mutation.Verified {
				t.Fatal(result, err)
			}
			switch mode {
			case "permission":
				if !errors.Is(err, admodel.ErrObjectWritePermission) ||
					result.Mutation.State != admodel.ObjectWriteRejected ||
					len(f.InternalWrites) != 1 {
					t.Fatal(result, err)
				}
			case "uncertain":
				if !errors.Is(err, admodel.ErrObjectWriteUncertain) ||
					result.Mutation.State != admodel.ObjectWriteUncertain ||
					len(f.InternalWrites) != 1 {
					t.Fatal(result, err)
				}
			case "readback":
				if !errors.Is(err, admodel.ErrObjectReadback) ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					len(result.Mutation.ReadbackCandidates) != 1 ||
					result.Mutation.After != nil {
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

func TestAuthenticationPolicyRawMissingUnknownAndPartialReads(t *testing.T) {
	f := InternalNewAuthenticationPolicyFixture()
	delete(f.InternalObjects[InternalAuthTestPolicy].Attributes, "msds-authnpolicyenforced")
	f.InternalObjects[InternalAuthTestPolicy].Attributes["msds-strongntlmpolicy"] = [][]byte{
		[]byte("99"),
	}
	f.InternalObjects[InternalAuthTestPolicy].Attributes["msds-usertgtlifetime"] = [][]byte{
		[]byte("-9223372036854775808"),
	}
	f.InternalObjects[InternalAuthTestPolicy].Attributes["msds-userallowedtoauthenticatefrom"] = [][]byte{
		{0, 255},
	}
	result, err := adservice_authentication_policies.New(f.InternalClient(t)).
		AuthenticationPolicy(context.Background(), InternalAuthTestIdentity(InternalAuthTestPolicy), admodel.ResolveIdentityOptions{})
	if err != nil || result.Policy.Enforced != nil || *result.Policy.RollingNTLMSecret != 99 ||
		result.Policy.UserTGTLifetime == nil ||
		!slices.Equal(result.Policy.UserAllowedToAuthenticateFrom.Bytes(), []byte{0, 255}) {
		t.Fatal(result, err)
	}
	f.InternalSearchError = &admodel.LDAPError{Code: 50}
	many, err := adservice_authentication_policies.New(f.InternalClient(t)).
		AuthenticationPolicies(context.Background(), admodel.SearchOptions{})
	if err == nil || many.Observation.Complete || len(many.Policies) != 1 ||
		len(many.Observation.Objects) != 1 {
		t.Fatal(many, err)
	}
}

func TestAuthenticationPolicyDescriptorBoundsAndRights(t *testing.T) {
	for _, raw := range [][]byte{nil, {1, 2, 3}, InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x20000)), InternalOuTestDescriptor(InternalOuTestACE(0, 8, 0x100))} {
		if err := admodel.InternalValidateAuthenticationDescriptor(
			raw,
		); !errors.Is(
			err,
			admodel.ErrAuthenticationPolicyDescriptor,
		) {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range [][]byte{InternalOuTestDescriptor(), InternalOuTestDescriptor(InternalOuTestACE(1, 0, 0x100), InternalOuTestACE(0, 0, 0x20000)), InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x10000000))} {
		if err := admodel.InternalValidateAuthenticationDescriptor(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
}

func FuzzAuthenticationPolicyDescriptor(f *testing.F) {
	f.Add(InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x100)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 132097 {
			return
		}
		_ = admodel.InternalValidateAuthenticationDescriptor(raw)
	})
}
