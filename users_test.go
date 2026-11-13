package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func userTestEntry(flags Flags32) Object {
	entry := objectTestEntry("CN=sample,DC=example")
	entry.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("person"), []byte("user")}
	entry.Attributes["useraccountcontrol"] = [][]byte{[]byte(flags.LDAPString())}
	entry.Attributes["name"] = [][]byte{[]byte("sample")}
	return entry
}

func TestUserDecodeMappingsSentinelsAndAttributeStates(t *testing.T) {
	entry := userTestEntry(0x40010220)
	entry.Attributes["sn"] = [][]byte{[]byte("李")}
	entry.Attributes["mail"] = [][]byte{[]byte("user@example.test")}
	entry.Attributes["accountexpires"] = [][]byte{[]byte("9223372036854775807")}
	entry.Attributes["pwdlastset"] = [][]byte{[]byte("0")}
	entry.Attributes["serviceprincipalname;range=0-0"] = [][]byte{[]byte("HOST/example")}
	entry.RequestedProperties = userProperties(nil)
	user, err := decodeUser(entry)
	if err != nil || user.Surname == nil || *user.Surname != "李" || user.EmailAddress == nil || *user.EmailAddress != "user@example.test" || user.Description != nil || user.Enabled == nil || !*user.Enabled || !*user.PasswordNotRequired || !*user.PasswordNeverExpires || user.UserAccountControl == nil || *user.UserAccountControl != 0x40010220 || user.AccountExpires == nil || uint64(*user.AccountExpires) != 9223372036854775807 || user.PasswordLastSet == nil || *user.PasswordLastSet != 0 || user.ServicePrincipalNames.State != AttributePartial || user.Certificates.State != AttributeAbsent {
		t.Fatal(user, err)
	}
	delete(entry.Attributes, "useraccountcontrol")
	entry.Attributes["msds-useraccountdisabled"] = [][]byte{[]byte("TRUE")}
	entry.Attributes["ms-ds-userpasswordnotrequired"] = [][]byte{[]byte("FALSE")}
	user, err = decodeUser(entry)
	if err != nil || user.UserAccountControl != nil || user.Enabled == nil || *user.Enabled || user.PasswordNotRequired == nil || *user.PasswordNotRequired || user.PasswordNeverExpires != nil || user.SmartcardLogonRequired != nil {
		t.Fatal(user, err)
	}
	entry.Attributes["objectclass"] = append(entry.Attributes["objectclass"], []byte("computer"))
	if _, err := decodeUser(entry); !errors.Is(err, ErrNotUser) {
		t.Fatal(err)
	}
}

func TestUserReadsSharedIdentityFiltersAndPartialResults(t *testing.T) {
	account, _ := IdentityByAccountName("sample")
	permission := &LDAPError{Code: 50}
	for _, many := range []bool{false, true} {
		client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
			if many {
				if !strings.Contains(query.Filter, "(!(objectClass=computer))") || !strings.Contains(query.Filter, "(sn=李)") {
					t.Fatal(query.Filter)
				}
			} else if query.Filter != "(&(objectSid=*)(sAMAccountName=sample))" {
				t.Fatal(query.Filter)
			}
			return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
				return []Object{userTestEntry(512)}, false, permission
			}, finish: func() error { return nil }}, nil
		}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
			t.Fatal("read wrote")
			return ldapWriteAttempt{}
		})
		if many {
			result, err := client.Users(context.Background(), SearchOptions{Scope: ScopeSubtree, TypedFilter: FilterEqual("sn", FilterText("李"))})
			if !errors.Is(err, permission) || result.Observation.Complete || len(result.Users) != 1 {
				t.Fatal(result, err)
			}
		} else {
			result, err := client.User(context.Background(), account, ResolveIdentityOptions{})
			if !errors.Is(err, permission) || result.User != nil || len(result.Observation.Candidates) != 1 {
				t.Fatal(result, err)
			}
		}
	}
}

func TestUpdateUserStrictFlagsAndRawMultivalue(t *testing.T) {
	enabled, neverExpires := true, true
	old, next := Flags32(0x40000202), Flags32(0x40010200)
	for _, code := range []uint32{0, 16, 50} {
		reads, writes := 0, 0
		client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
			reads++
			flags := old
			if reads > 1 {
				flags = next
			}
			entry := userTestEntry(flags)
			entry.Attributes["pwdlastset"] = [][]byte{[]byte("123456")}
			entry.Attributes["serviceprincipalname"] = [][]byte{[]byte("HOST/a"), []byte("HOST/b")}
			return objectTestCursor(entry), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			mods := request.modifications
			if request.dn != objectGUIDTarget(objectTestGUID()) || len(mods) != 3 || mods[1].operation != 1 || mods[2].operation != 0 || string(mods[1].values[0]) != old.LDAPString() || string(mods[2].values[0]) != next.LDAPString() || len(mods[0].values) != 2 {
				t.Fatal(request)
			}
			if code != 0 {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: code}}
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		result, err := client.UpdateUser(context.Background(), UpdateUserRequest{Identity: objectTestIdentity(), Properties: UserProperties{Enabled: &enabled, PasswordNeverExpires: &neverExpires}, Changes: []AttributeChange{{Attribute: "servicePrincipalName", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte("HOST/a")), NewRawValue([]byte("HOST/b"))}}}})
		if writes != 1 {
			t.Fatal(writes)
		}
		if code == 0 {
			if err != nil || !result.Mutation.Verified || result.User == nil || *result.User.UserAccountControl != next {
				t.Fatal(result, err)
			}
		} else {
			var native *LDAPError
			if !errors.As(err, &native) || native.Code != code || reads != 1 || result.Mutation.State != ObjectWriteRejected {
				t.Fatal(result, err)
			}
		}
	}
}

func TestUserPropertyConflictsAndManagedAttributesReject(t *testing.T) {
	value := "value"
	client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
		t.Fatal("invalid request read")
		return nil, nil
	}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		t.Fatal("invalid request wrote")
		return ldapWriteAttempt{}
	})
	for _, change := range []AttributeChange{{Attribute: "unicodePwd", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte("public"))}}, {Attribute: "userAccountControl", Kind: AttributeClear}, {Attribute: "ms-DS-UserPasswordNotRequired", Kind: AttributeClear}, {Attribute: "MAIL", Kind: AttributeClear}} {
		_, err := client.UpdateUser(context.Background(), UpdateUserRequest{Identity: objectTestIdentity(), Properties: UserProperties{EmailAddress: &value}, Changes: []AttributeChange{change}})
		if err == nil {
			t.Fatal("accepted conflicting or managed attribute")
		}
	}
	request := CreateUserRequest{InitialPassword: []byte("PUBLIC-password")}
	encoded, err := json.Marshal(request)
	if err != nil || string(encoded) != `{"redacted":true}` || strings.Contains(fmt.Sprintf("%+v %#v", request, request), "PUBLIC") {
		t.Fatal("creation password was not redacted")
	}
}

func TestUpdateUserNeverExpiresConflictStopsAllPropertyChanges(t *testing.T) {
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%t", kind, missing), func(t *testing.T) {
				reads, writes := 0, 0
				client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
					reads++
					if !slices.Contains(query.Properties, "pwdLastSet") {
						t.Fatal("password timestamp was not requested", query.Properties)
					}
					entry := userTestEntry(512)
					entry.Attributes["displayname"] = [][]byte{[]byte("Before")}
					entry.Attributes["description"] = [][]byte{[]byte("original")}
					if !missing {
						entry.Attributes["pwdlastset"] = [][]byte{[]byte("0")}
					}
					if kind == CapabilityADLDS {
						delete(entry.Attributes, "useraccountcontrol")
						entry.Attributes["msds-userdontexpirepassword"] = [][]byte{[]byte("FALSE")}
					}
					return objectTestCursor(entry), nil
				}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
					writes++
					t.Fatal("conflicting account option dispatched accompanying property changes")
					return ldapWriteAttempt{}
				})
				session := client.session.(objectWriteTestSession)
				session.read = func(context.Context, []string) (map[string][][]byte, error) { return identityTestRoot(kind), nil }
				client.session = session
				name, neverExpires := "After", true
				result, err := client.UpdateUser(context.Background(), UpdateUserRequest{
					Identity:   objectTestIdentity(),
					Properties: UserProperties{DisplayName: &name, PasswordNeverExpires: &neverExpires},
					Changes:    []AttributeChange{{Attribute: "description", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte("changed"))}}},
				})
				want := ErrInvalidAccountControl
				if missing {
					want = ErrAttributeUnavailable
				}
				if !errors.Is(err, want) || writes != 0 || reads != 1 || result.Mutation.State != ObjectWriteNotAttempted || result.Mutation.Verified || result.Mutation.After != nil || result.User != nil || result.Mutation.Before == nil {
					t.Fatal(result, err, reads, writes)
				}
				if string(result.Mutation.Before.Attributes["displayname"][0]) != "Before" || string(result.Mutation.Before.Attributes["description"][0]) != "original" {
					t.Fatal("preflight values were changed locally", result.Mutation.Before)
				}
			})
		}
	}
}

func TestUpdateUserNoOpRetainsRequestedProperties(t *testing.T) {
	reads := 0
	client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
		reads++
		entry := userTestEntry(512)
		entry.RequestedProperties = slices.Clone(query.Properties)
		if slices.Contains(query.Properties, "employeeID") {
			entry.Attributes["employeeid"] = [][]byte{[]byte("12345")}
		}
		return objectTestCursor(entry), nil
	}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		t.Fatal("already-satisfied flag update wrote")
		return ldapWriteAttempt{}
	})
	enabled := true
	result, err := client.UpdateUser(context.Background(), UpdateUserRequest{Identity: objectTestIdentity(), Properties: UserProperties{Enabled: &enabled}, Options: ObjectMutationOptions{Properties: []string{"employeeID"}}})
	if err != nil || reads != 1 || result.Mutation.State != ObjectWriteNotAttempted || !result.Mutation.Verified || !result.Mutation.ReadbackComplete || result.User == nil {
		t.Fatal(result, err)
	}
	value, err := result.User.Raw.Values("employeeID").Single()
	if err != nil || string(value.Bytes()) != "12345" {
		t.Fatal("requested property lost on no-op", value, err)
	}
}

type userCreationFixture struct {
	kind, mode string
	entry      Object
	stages     []string
	password   bool
}

func newUserCreationFixture(t *testing.T, kind, mode string) (*Client, *userCreationFixture) {
	t.Helper()
	fixture := &userCreationFixture{kind: kind, mode: mode}
	client := passwordTestClient(t, kind, passwordTestProtection, func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if strings.Contains(query.Filter, "classSchema") {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		if fixture.entry.DistinguishedName == "" {
			return objectTestCursor(objectTestEntry("CN=Users,DC=example")), nil
		}
		if mode == "creation readback" && len(fixture.stages) == 1 {
			return nil, &LDAPError{Code: 50}
		}
		entry := fixture.entry
		entry.Attributes = make(map[string][][]byte, len(fixture.entry.Attributes))
		for name, values := range fixture.entry.Attributes {
			for _, value := range values {
				entry.Attributes[name] = append(entry.Attributes[name], slices.Clone(value))
			}
		}
		return objectTestCursor(entry), nil
	}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
		if request.operation == ldapWriteAdd {
			fixture.stages = append(fixture.stages, "create")
			if mode == "creation uncertain" {
				return ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}
			}
			if mode == "duplicate" {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 68}}
			}
			fixture.entry = objectTestEntry(request.dn)
			for _, mod := range request.modifications {
				fixture.entry.Attributes[strings.ToLower(mod.attribute)] = mod.values
			}
			fixture.entry.Attributes["name"] = fixture.entry.Attributes["cn"]
			if kind == CapabilityActiveDirectory {
				if string(fixture.entry.Attributes["useraccountcontrol"][0]) != "514" && string(fixture.entry.Attributes["useraccountcontrol"][0]) != "546" {
					t.Fatal("user not created disabled")
				}
			} else if string(fixture.entry.Attributes["msds-useraccountdisabled"][0]) != "TRUE" {
				t.Fatal("LDS user not disabled")
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		}
		if request.modifications[0].attribute == "unicodePwd" {
			fixture.stages = append(fixture.stages, "password")
			if mode == "password denied" {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 19}}
			}
			if mode == "password uncertain" {
				return ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}
			}
			fixture.password = true
			fixture.entry.Attributes["pwdlastset"] = [][]byte{[]byte("1234")}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		}
		fixture.stages = append(fixture.stages, "enable")
		if !fixture.password && mode != "password not required" {
			t.Fatal("enabled before successful password stage")
		}
		if mode == "enable denied" {
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50}}
		}
		for _, mod := range request.modifications {
			if mod.operation == 0 || mod.operation == 2 {
				fixture.entry.Attributes[strings.ToLower(mod.attribute)] = mod.values
			}
		}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	})
	session := client.session.(passwordTestSession)
	base := session.base
	session.base = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
		attributes, err := base(ctx, dn, properties)
		if dn == "" {
			attributes["schemanamingcontext"] = [][]byte{[]byte("CN=Schema,CN=Configuration,DC=example")}
		}
		return attributes, err
	}
	client.session = session
	return client, fixture
}

func TestCreateUserStagesStopAfterRejectedUncertainOrUnreadableState(t *testing.T) {
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		for _, mode := range []string{"success", "duplicate", "creation uncertain", "creation readback", "password denied", "password uncertain", "enable denied", "password not required"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				client, fixture := newUserCreationFixture(t, kind, mode)
				parent, _ := IdentityByDN("CN=Users,DC=example")
				enabled := true
				request := CreateUserRequest{Parent: parent, Name: "Jörg, 李", Properties: UserProperties{Enabled: &enabled}, InitialPassword: []byte("PUBLIC-initial-password")}
				if mode == "password not required" {
					yes := true
					request.InitialPassword = nil
					request.Properties.PasswordNotRequired = &yes
				}
				result, err := client.CreateUser(context.Background(), request)
				want := []string{"create", "password", "enable"}
				switch mode {
				case "duplicate", "creation uncertain", "creation readback":
					want = []string{"create"}
				case "password denied", "password uncertain":
					want = []string{"create", "password"}
				case "password not required":
					want = []string{"create", "enable"}
				}
				if !reflect.DeepEqual(fixture.stages, want) {
					t.Fatal(fixture.stages, want)
				}
				if mode == "success" || mode == "password not required" {
					if err != nil || !result.Complete || result.User == nil || result.User.Enabled == nil || !*result.User.Enabled || result.Enable == nil || !result.Enable.Verified {
						t.Fatal(result, err)
					}
				} else {
					if !errors.Is(err, ErrUserCreationIncomplete) || result.Complete {
						t.Fatal(result, err)
					}
					if mode != "duplicate" && mode != "creation uncertain" && result.Creation.State != ObjectWriteAccepted {
						t.Fatal("lost accepted creation")
					}
					if mode == "creation uncertain" && (result.Creation.State != ObjectWriteUncertain || result.Password != nil || result.Enable != nil) {
						t.Fatal("continued after uncertain creation")
					}
					if mode == "password uncertain" && (result.Password == nil || result.Password.State != ObjectWriteUncertain || result.Enable != nil) {
						t.Fatal("uncertain password replayed or enabled")
					}
				}
				if !bytes.Equal(request.InitialPassword, []byte("PUBLIC-initial-password")) && mode != "password not required" {
					t.Fatal("caller secret changed")
				}
			})
		}
	}
}

func TestCreateUserRejectsImplicitPasswordExemption(t *testing.T) {
	client, fixture := newUserCreationFixture(t, CapabilityActiveDirectory, "success")
	parent, _ := IdentityByDN("CN=Users,DC=example")
	enabled := true
	result, err := client.CreateUser(context.Background(), CreateUserRequest{Parent: parent, Name: "sample", Properties: UserProperties{Enabled: &enabled}})
	if !errors.Is(err, ErrInvalidUser) || result.Creation.State != ObjectWriteNotAttempted || len(fixture.stages) != 0 {
		t.Fatal(result, err)
	}
}

func TestCreateUserDisabledDefaultAndPasswordObservation(t *testing.T) {
	for _, password := range []bool{false, true} {
		client, fixture := newUserCreationFixture(t, CapabilityActiveDirectory, "success")
		parent, _ := IdentityByDN("CN=Users,DC=example")
		request := CreateUserRequest{Parent: parent, Name: "disabled"}
		if password {
			request.InitialPassword = []byte("PUBLIC-disabled-password")
		}
		result, err := client.CreateUser(context.Background(), request)
		if err != nil || !result.Complete || result.Enable != nil || result.User == nil || result.User.Enabled == nil || *result.User.Enabled || result.User.PasswordNotRequired == nil || *result.User.PasswordNotRequired {
			t.Fatal(result, err)
		}
		if password {
			if !reflect.DeepEqual(fixture.stages, []string{"create", "password"}) || result.Observation == nil || result.User.PasswordLastSet == nil || *result.User.PasswordLastSet != 1234 {
				t.Fatal("password observation or ordering lost", fixture.stages, result)
			}
		} else if !reflect.DeepEqual(fixture.stages, []string{"create"}) || result.Password != nil || result.Observation != nil {
			t.Fatal(fixture.stages, result)
		}
	}
}

func TestCreateUserRejectsInsecurePasswordBeforeAdd(t *testing.T) {
	client, fixture := newUserCreationFixture(t, CapabilityActiveDirectory, "success")
	session := client.session.(passwordTestSession)
	session.protect = func(context.Context, Transport) (PasswordProtection, error) {
		return PasswordProtection{Transport: client.config.Transport, CipherBits: 56}, nil
	}
	client.session = session
	parent, _ := IdentityByDN("CN=Users,DC=example")
	result, err := client.CreateUser(context.Background(), CreateUserRequest{Parent: parent, Name: "sample", InitialPassword: []byte("PUBLIC-password")})
	if !errors.Is(err, ErrPasswordProtection) || result.Creation.State != ObjectWriteNotAttempted || len(fixture.stages) != 0 {
		t.Fatal(result, err)
	}
}

func TestDeleteUserClassGuardLeafAndAbsentReadback(t *testing.T) {
	for _, computer := range []bool{false, true} {
		reads, writes := 0, 0
		client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
			reads++
			if writes != 0 {
				return objectTestCursor(), nil
			}
			entry := userTestEntry(512)
			if computer {
				entry.Attributes["objectclass"] = append(entry.Attributes["objectclass"], []byte("computer"))
			}
			return objectTestCursor(entry), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if request.operation != ldapWriteDelete || request.dn != objectGUIDTarget(objectTestGUID()) || len(request.controls) != 0 {
				t.Fatal(request)
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		result, err := client.DeleteUser(context.Background(), DeleteUserRequest{Identity: objectTestIdentity()})
		if computer {
			if !errors.Is(err, ErrNotUser) || writes != 0 || reads != 1 {
				t.Fatal(result, err)
			}
		} else if err != nil || writes != 1 || reads != 2 || !result.Mutation.Verified || !result.Mutation.AbsentAfter {
			t.Fatal(result, err)
		}
	}
}
