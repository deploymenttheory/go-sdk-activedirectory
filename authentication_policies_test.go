package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	authTestConfig    = "CN=Configuration,DC=example"
	authTestSchema    = "CN=Schema," + authTestConfig
	authTestContainer = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services," + authTestConfig
	authTestPolicy    = "CN=Policy," + authTestContainer
	authTestAccount   = "CN=Account,DC=example"
	authTestDSA       = "CN=NTDS Settings,CN=DC,CN=Servers,CN=Site,CN=Sites," + authTestConfig
)

type authenticationPolicyFixture struct {
	testSession
	root        map[string][][]byte
	objects     map[string]Object
	writes      []ldapWriteRequest
	attempt     ldapWriteAttempt
	write       func(context.Context, ldapWriteRequest) ldapWriteAttempt
	searchError error
}

func newAuthenticationPolicyFixture() *authenticationPolicyFixture {
	f := &authenticationPolicyFixture{root: identityTestRoot(CapabilityActiveDirectory), objects: map[string]Object{}, attempt: ldapWriteAttempt{State: ldapWriteAccepted}}
	f.root["configurationnamingcontext"] = [][]byte{[]byte(authTestConfig)}
	f.root["schemanamingcontext"] = [][]byte{[]byte(authTestSchema)}
	f.root["domaincontrollerfunctionality"], f.root["domainfunctionality"] = [][]byte{[]byte("7")}, [][]byte{[]byte("7")}
	f.root["issynchronized"], f.root["dsservicename"] = [][]byte{[]byte("TRUE")}, [][]byte{[]byte(authTestDSA)}
	f.root["supportedcontrol"] = [][]byte{[]byte(directorySDFlagsControl)}
	for i, pair := range [][2]string{{authTestContainer, "msDS-AuthNPolicies"}, {authTestPolicy, "msDS-AuthNPolicy"}, {authTestAccount, "user"}} {
		object := objectTestEntry(pair[0])
		object.Attributes["objectguid"][0][0] = byte(i + 1)
		object.Attributes["objectclass"] = [][]byte{[]byte(pair[1])}
		object.Attributes["name"], object.Attributes["description"] = [][]byte{[]byte("Policy")}, [][]byte{[]byte("unchanged")}
		object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(ouTestACE(0, 0, 0x20000))}
		f.objects[pair[0]] = object
	}
	f.objects[authTestPolicy].Attributes["msds-authnpolicyenforced"] = [][]byte{[]byte("FALSE")}
	f.objects[authTestAccount].Attributes["objectsid"] = [][]byte{{1, 1, 0, 0, 0, 0, 0, 5, 42, 0, 0, 0}}
	f.objects[authTestAccount].Attributes["samaccountname"] = [][]byte{[]byte("account")}
	f.objects[authTestAccount].Attributes["msds-assignedauthnpolicysilo"] = [][]byte{[]byte("CN=ExistingSilo," + authTestConfig)}
	f.base = func(_ context.Context, dn string, properties []string) (map[string][][]byte, error) {
		switch dn {
		case "":
			return authTestProjection(f.root, properties), nil
		case authTestDSA:
			return map[string][][]byte{"objectclass": {[]byte("nTDSDSA")}, "msds-isrodc": {[]byte("FALSE")}}, nil
		case authTestSchema:
			return map[string][][]byte{"objectversion": {[]byte("87")}}, nil
		}
		object, ok := f.objects[dn]
		if !ok {
			return nil, &LDAPError{Code: 32}
		}
		return authTestProjection(object.Attributes, properties), nil
	}
	f.search = func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if strings.Contains(query.Filter, "classSchema") {
			return objectTestCursor(Object{DistinguishedName: "CN=ms-DS-AuthN-Policy," + authTestSchema, Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		var found []Object
		for dn, object := range f.objects {
			match := false
			switch {
			case query.Scope == ScopeBase:
				match = sameAuthenticationDN(query.Base, dn)
			case strings.Contains(query.Filter, "objectGUID="):
				match = strings.Contains(query.Filter, identityBinaryLiteral(object.Attributes["objectguid"][0]))
			case strings.Contains(query.Filter, "sAMAccountName="):
				match = dn == authTestAccount
			case strings.Contains(query.Filter, "msDS-AuthNPolicy"):
				match = dn != authTestContainer && strings.HasSuffix(dn, ","+authTestContainer)
			}
			if match {
				found = append(found, Object{DistinguishedName: dn, Attributes: authTestProjection(object.Attributes, query.Properties), RequestedProperties: query.Properties})
			}
		}
		return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return found, true, f.searchError }, finish: func() error { return nil }}, nil
	}
	f.finish = func() error { return nil }
	return f
}

func authTestProjection(attrs map[string][][]byte, properties []string) map[string][][]byte {
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

func (f *authenticationPolicyFixture) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	f.writes = append(f.writes, request)
	attempt := f.attempt
	if f.write != nil {
		attempt = f.write(ctx, request)
	}
	if attempt.State != ldapWriteAccepted {
		return attempt
	}
	if request.operation == ldapWriteAdd {
		object := objectTestEntry(request.dn)
		object.Attributes["objectguid"][0][0] = 100
		object.Attributes["ntsecuritydescriptor"] = [][]byte{ouTestDescriptor(ouTestACE(0, 0, 0x20000))}
		for _, mod := range request.modifications {
			object.Attributes[strings.ToLower(mod.attribute)] = mod.values
			if strings.EqualFold(mod.attribute, "cn") {
				object.Attributes["name"] = mod.values
			}
		}
		f.objects[request.dn] = object
		return attempt
	}
	for dn, object := range f.objects {
		guid, _ := GUIDFromBytes(object.Attributes["objectguid"][0])
		if request.dn != objectGUIDTarget(guid) {
			continue
		}
		if request.operation == ldapWriteDelete {
			delete(f.objects, dn)
			return attempt
		}
		for _, mod := range request.modifications {
			name := strings.ToLower(mod.attribute)
			switch mod.operation {
			case 2:
				object.Attributes[name] = mod.values
			case 0:
				object.Attributes[name] = append(object.Attributes[name], mod.values...)
			case 1:
				if len(mod.values) == 0 {
					delete(object.Attributes, name)
				} else {
					object.Attributes[name] = slices.DeleteFunc(object.Attributes[name], func(value []byte) bool {
						return slices.ContainsFunc(mod.values, func(old []byte) bool { return slices.Equal(value, old) })
					})
				}
			}
		}
	}
	return attempt
}

func (f *authenticationPolicyFixture) readOUDACL(_ context.Context, dn string) (Object, error) {
	for _, object := range f.objects {
		guid, _ := GUIDFromBytes(object.Attributes["objectguid"][0])
		if dn == object.DistinguishedName || dn == objectGUIDTarget(guid) {
			return Object{DistinguishedName: object.DistinguishedName, Attributes: authTestProjection(object.Attributes, []string{"objectGUID", "nTSecurityDescriptor"})}, nil
		}
	}
	return Object{}, &LDAPError{Code: 32}
}
func (*authenticationPolicyFixture) editOUDACL(raw []byte, mask uint32, protect bool) ([]byte, bool, error) {
	acl, err := decodeOUDACL(raw)
	if err != nil {
		return nil, false, err
	}
	aces, changed := changeOUACEs(acl, mask, protect)
	return ouTestDescriptor(aces...), changed, nil
}

func (f *authenticationPolicyFixture) client(t *testing.T) *Client {
	t.Helper()
	client := newClient(Config{Endpoint: Endpoint{Host: "dc.example", Port: 389}, Timeout: 5 * time.Second}, f)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}
func authTestIdentity(dn string) Identity { identity, _ := IdentityByDN(dn); return identity }

func TestAuthenticationPolicyCreateUpdateReadDelete(t *testing.T) {
	f := newAuthenticationPolicyFixture()
	client := f.client(t)
	zero := Interval100ns(0)
	exact := Interval100ns(600000001)
	enforced := true
	rolling := StrongNTLMOptional
	result, err := client.CreateAuthenticationPolicy(context.Background(), CreateAuthenticationPolicyRequest{Name: "Cymru, 李", Properties: AuthenticationPolicyProperties{UserTGTLifetime: &exact, ComputerTGTLifetime: &zero, ServiceTGTLifetime: &exact, UserAllowedNTLMNetworkAuthentication: &enforced, RollingNTLMSecret: &rolling}, Attributes: map[string][]RawValue{"extensionBinary": {NewRawValue([]byte{0, 255}), NewRawValue([]byte{})}}})
	if err != nil || !result.Mutation.Verified || result.Policy == nil || result.Policy.Enforced == nil || *result.Policy.Enforced || *result.Policy.UserTGTLifetime != exact || len(f.writes) != 1 {
		t.Fatal(result, err, f.writes)
	}
	for _, mod := range f.writes[0].modifications {
		if mod.operation != 0 {
			t.Fatal("Add used Modify opcode", mod)
		}
	}
	if !strings.Contains(result.Mutation.TargetDN, `cn=Cymru\, 李,`) {
		t.Fatal(result.Mutation.TargetDN)
	}
	identity := objectGUIDIdentity(*result.Mutation.TargetGUID)
	updated, err := client.UpdateAuthenticationPolicy(context.Background(), UpdateAuthenticationPolicyRequest{Identity: identity, Properties: AuthenticationPolicyProperties{Enforced: &enforced}})
	if err != nil || !updated.Mutation.Verified || !*updated.Policy.Enforced || *updated.Policy.UserTGTLifetime != exact {
		t.Fatal(updated, err)
	}
	read, err := client.AuthenticationPolicy(context.Background(), identity, ResolveIdentityOptions{Properties: []string{"extensionBinary"}})
	if err != nil || read.Policy.Raw.Values("extensionBinary").State != AttributePresent {
		t.Fatal(read, err)
	}
	deleted, err := client.DeleteAuthenticationPolicy(context.Background(), DeleteAuthenticationPolicyRequest{Identity: identity})
	if err != nil || !deleted.AbsentAfter || deleted.State != ObjectWriteAccepted {
		t.Fatal(deleted, err)
	}
}

func TestAuthenticationPolicyAssignmentsPreserveSiloAndClearExplicitly(t *testing.T) {
	for _, class := range []string{"user", "computer", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"} {
		t.Run(class, func(t *testing.T) {
			f := newAuthenticationPolicyFixture()
			f.objects[authTestAccount].Attributes["objectclass"] = [][]byte{[]byte("user"), []byte(class)}
			client := f.client(t)
			account, _ := IdentityByAccountName("account")
			policy := authTestIdentity(authTestPolicy)
			result, err := client.SetAccountAuthenticationPolicy(context.Background(), SetAccountAuthenticationPolicyRequest{Identity: account, Policy: &policy})
			if err != nil || !result.Mutation.Verified || result.Policy == nil || len(f.writes) != 1 || len(f.writes[0].modifications) != 1 {
				t.Fatal(result, err, f.writes)
			}
			if result.Mutation.After.Values("msDS-AssignedAuthNPolicySilo").State != AttributePresent {
				t.Fatal("silo projection lost")
			}
			result, err = client.SetAccountAuthenticationPolicy(context.Background(), SetAccountAuthenticationPolicyRequest{Identity: account, Clear: true})
			if !errors.Is(err, ErrObjectVerification) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || f.writes[1].modifications[0].operation != 1 || len(f.writes[1].modifications[0].values) != 0 {
				t.Fatal(result, err, f.writes)
			}
		})
	}
}

func TestAuthenticationPolicyProtectionHasSeparateOutcomes(t *testing.T) {
	f := newAuthenticationPolicyFixture()
	protect := true
	count := 0
	f.write = func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		count++
		if count == 3 {
			return ldapWriteAttempt{State: ldapWriteUncertain, Err: context.DeadlineExceeded}
		}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	}
	result, err := f.client(t).CreateAuthenticationPolicy(context.Background(), CreateAuthenticationPolicyRequest{Name: "Protected", ProtectedFromAccidentalDeletion: &protect})
	if !errors.Is(err, ErrObjectWriteUncertain) || result.Mutation.State != ObjectWriteAccepted || len(result.Protection.Steps) != 2 || result.Protection.Steps[0].State != ObjectWriteAccepted || result.Protection.Steps[1].State != ObjectWriteUncertain || len(f.writes) != 3 {
		t.Fatal(result, err, f.writes)
	}
}

func TestAuthenticationPolicyInputConflictsBeforeIO(t *testing.T) {
	var client *Client
	enforce := true
	negative := Interval100ns(-1)
	for _, request := range []UpdateAuthenticationPolicyRequest{
		{Identity: authTestIdentity(authTestPolicy)},
		{Identity: authTestIdentity(authTestPolicy), Properties: AuthenticationPolicyProperties{Enforced: &enforce}, Changes: []AttributeChange{authenticationSetting("msDS-AuthNPolicyEnforced", "FALSE")}},
		{Identity: authTestIdentity(authTestPolicy), Properties: AuthenticationPolicyProperties{UserTGTLifetime: &negative}},
		{Identity: authTestIdentity(authTestPolicy), Changes: []AttributeChange{authenticationSetting("msDS-UserAllowedToAuthenticateFrom", "not binary")}},
	} {
		if _, err := client.UpdateAuthenticationPolicy(context.Background(), request); err == nil || errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
	for _, request := range []SetAccountAuthenticationPolicyRequest{{Identity: authTestIdentity(authTestAccount)}, {Identity: authTestIdentity(authTestAccount), Clear: true, Policy: func() *Identity { x := authTestIdentity(authTestPolicy); return &x }()}} {
		if _, err := client.SetAccountAuthenticationPolicy(context.Background(), request); !errors.Is(err, ErrInvalidAuthenticationPolicy) {
			t.Fatal(err)
		}
	}
}

func TestAuthenticationPolicyWholeWorkflowTimeout(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := newAuthenticationPolicyFixture()
			original := f.base
			reads := 0
			var deadline time.Time
			f.base = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
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
			client := f.client(t)
			// Generous enough that reaching the second stage cannot race the
			// deadline; the second stage still waits for a real expiry.
			client.config.Timeout = 400 * time.Millisecond
			var err error
			switch operation {
			case "create":
				_, err = client.CreateAuthenticationPolicy(context.Background(), CreateAuthenticationPolicyRequest{Name: "new"})
			case "update":
				value := true
				_, err = client.UpdateAuthenticationPolicy(context.Background(), UpdateAuthenticationPolicyRequest{Identity: authTestIdentity(authTestPolicy), Properties: AuthenticationPolicyProperties{Enforced: &value}})
			case "delete":
				_, err = client.DeleteAuthenticationPolicy(context.Background(), DeleteAuthenticationPolicyRequest{Identity: authTestIdentity(authTestPolicy)})
			}
			if !errors.Is(err, context.DeadlineExceeded) || len(f.writes) != 0 || reads != 2 {
				t.Fatal(err, reads, f.writes)
			}
		})
	}
}

func TestAuthenticationPolicyPrerequisitesAndReadbackFailures(t *testing.T) {
	for _, mode := range []string{"LDS", "old DC", "old domain", "GC", "wrong class", "wrong container", "permission", "uncertain", "readback"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthenticationPolicyFixture()
			client := f.client(t)
			identity := authTestIdentity(authTestPolicy)
			switch mode {
			case "LDS":
				f.root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "old DC":
				f.root["domaincontrollerfunctionality"] = [][]byte{[]byte("5")}
			case "old domain":
				f.root["domainfunctionality"] = [][]byte{[]byte("5")}
			case "GC":
				client.config.Endpoint.Port = 3268
			case "wrong class":
				f.objects[authTestPolicy].Attributes["objectclass"] = [][]byte{[]byte("container")}
			case "wrong container":
				identity = authTestIdentity(authTestContainer)
			case "permission":
				f.attempt = ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50, Diagnostic: "retained diagnostic"}}
			case "uncertain":
				f.attempt = ldapWriteAttempt{State: ldapWriteUncertain, Err: context.DeadlineExceeded}
			case "readback":
				f.write = func(context.Context, ldapWriteRequest) ldapWriteAttempt {
					f.searchError = &LDAPError{Code: 50}
					return ldapWriteAttempt{State: ldapWriteAccepted}
				}
			}
			value := true
			result, err := client.UpdateAuthenticationPolicy(context.Background(), UpdateAuthenticationPolicyRequest{Identity: identity, Properties: AuthenticationPolicyProperties{Enforced: &value}})
			if err == nil || result.Mutation.Verified {
				t.Fatal(result, err)
			}
			switch mode {
			case "permission":
				if !errors.Is(err, ErrObjectWritePermission) || result.Mutation.State != ObjectWriteRejected || len(f.writes) != 1 {
					t.Fatal(result, err)
				}
			case "uncertain":
				if !errors.Is(err, ErrObjectWriteUncertain) || result.Mutation.State != ObjectWriteUncertain || len(f.writes) != 1 {
					t.Fatal(result, err)
				}
			case "readback":
				if !errors.Is(err, ErrObjectReadback) || result.Mutation.State != ObjectWriteAccepted || len(result.Mutation.ReadbackCandidates) != 1 || result.Mutation.After != nil {
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

func TestAuthenticationPolicyRawMissingUnknownAndPartialReads(t *testing.T) {
	f := newAuthenticationPolicyFixture()
	delete(f.objects[authTestPolicy].Attributes, "msds-authnpolicyenforced")
	f.objects[authTestPolicy].Attributes["msds-strongntlmpolicy"] = [][]byte{[]byte("99")}
	f.objects[authTestPolicy].Attributes["msds-usertgtlifetime"] = [][]byte{[]byte("-9223372036854775808")}
	f.objects[authTestPolicy].Attributes["msds-userallowedtoauthenticatefrom"] = [][]byte{{0, 255}}
	result, err := f.client(t).AuthenticationPolicy(context.Background(), authTestIdentity(authTestPolicy), ResolveIdentityOptions{})
	if err != nil || result.Policy.Enforced != nil || *result.Policy.RollingNTLMSecret != 99 || result.Policy.UserTGTLifetime == nil || !slices.Equal(result.Policy.UserAllowedToAuthenticateFrom.Bytes(), []byte{0, 255}) {
		t.Fatal(result, err)
	}
	f.searchError = &LDAPError{Code: 50}
	many, err := f.client(t).AuthenticationPolicies(context.Background(), SearchOptions{})
	if err == nil || many.Observation.Complete || len(many.Policies) != 1 || len(many.Observation.Objects) != 1 {
		t.Fatal(many, err)
	}
}

func TestAuthenticationPolicyDescriptorBoundsAndRights(t *testing.T) {
	for _, raw := range [][]byte{nil, {1, 2, 3}, ouTestDescriptor(ouTestACE(0, 0, 0x20000)), ouTestDescriptor(ouTestACE(0, 8, 0x100))} {
		if err := validateAuthenticationDescriptor(raw); !errors.Is(err, ErrAuthenticationPolicyDescriptor) {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range [][]byte{ouTestDescriptor(), ouTestDescriptor(ouTestACE(1, 0, 0x100), ouTestACE(0, 0, 0x20000)), ouTestDescriptor(ouTestACE(0, 0, 0x10000000))} {
		if err := validateAuthenticationDescriptor(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
}

func FuzzAuthenticationPolicyDescriptor(f *testing.F) {
	f.Add(ouTestDescriptor(ouTestACE(0, 0, 0x100)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 132097 {
			return
		}
		_ = validateAuthenticationDescriptor(raw)
	})
}
