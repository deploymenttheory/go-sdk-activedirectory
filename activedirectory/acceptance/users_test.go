package acceptance

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

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

func InternalUserTestEntry(flags admodel.Flags32) admodel.Object {
	entry := InternalObjectTestEntry("CN=sample,DC=example")
	entry.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("person"), []byte("user")}
	entry.Attributes["useraccountcontrol"] = [][]byte{[]byte(flags.LDAPString())}
	entry.Attributes["name"] = [][]byte{[]byte("sample")}
	return entry
}

func TestUserDecodeMappingsSentinelsAndAttributeStates(t *testing.T) {
	entry := InternalUserTestEntry(0x40010220)
	entry.Attributes["sn"] = [][]byte{[]byte("李")}
	entry.Attributes["mail"] = [][]byte{[]byte("user@example.test")}
	entry.Attributes["accountexpires"] = [][]byte{[]byte("9223372036854775807")}
	entry.Attributes["pwdlastset"] = [][]byte{[]byte("0")}
	entry.Attributes["serviceprincipalname;range=0-0"] = [][]byte{[]byte("HOST/example")}
	entry.RequestedProperties = admodel.InternalUserProperties(nil)
	user, err := admodel.InternalDecodeUser(entry)
	if err != nil || user.Surname == nil || *user.Surname != "李" || user.EmailAddress == nil ||
		*user.EmailAddress != "user@example.test" ||
		user.Description != nil ||
		user.Enabled == nil ||
		!*user.Enabled ||
		!*user.PasswordNotRequired ||
		!*user.PasswordNeverExpires ||
		user.UserAccountControl == nil ||
		*user.UserAccountControl != 0x40010220 ||
		user.AccountExpires == nil ||
		uint64(*user.AccountExpires) != 9223372036854775807 ||
		user.PasswordLastSet == nil ||
		*user.PasswordLastSet != 0 ||
		user.ServicePrincipalNames.State != admodel.AttributePartial ||
		user.Certificates.State != admodel.AttributeAbsent {
		t.Fatal(user, err)
	}
	delete(entry.Attributes, "useraccountcontrol")
	entry.Attributes["msds-useraccountdisabled"] = [][]byte{[]byte("TRUE")}
	entry.Attributes["ms-ds-userpasswordnotrequired"] = [][]byte{[]byte("FALSE")}
	user, err = admodel.InternalDecodeUser(entry)
	if err != nil || user.UserAccountControl != nil || user.Enabled == nil || *user.Enabled ||
		user.PasswordNotRequired == nil ||
		*user.PasswordNotRequired ||
		user.PasswordNeverExpires != nil ||
		user.SmartcardLogonRequired != nil {
		t.Fatal(user, err)
	}
	entry.Attributes["objectclass"] = append(entry.Attributes["objectclass"], []byte("computer"))
	if _, err := admodel.InternalDecodeUser(entry); !errors.Is(err, admodel.ErrNotUser) {
		t.Fatal(err)
	}
}

func TestUserReadsSharedIdentityFiltersAndPartialResults(t *testing.T) {
	account, _ := admodel.IdentityByAccountName("sample")
	permission := &admodel.LDAPError{Code: 50}
	for _, many := range []bool{false, true} {
		client := InternalObjectTestClient(
			t,
			nil,
			func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				if many {
					if !strings.Contains(query.Filter, "(!(objectClass=computer))") ||
						!strings.Contains(query.Filter, "(sn=李)") {
						t.Fatal(query.Filter)
					}
				} else if query.Filter != "(&(objectSid=*)(sAMAccountName=sample))" {
					t.Fatal(query.Filter)
				}
				return InternalTestSearchCursor{
					InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
						return []admodel.Object{InternalUserTestEntry(512)}, false, permission
					},
					InternalFinish: func() error { return nil },
				}, nil
			},
			func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				t.Fatal("read wrote")
				return admodel.InternalLdapWriteAttempt{}
			},
		)
		if many {
			result, err := adservice_users.New(client).
				Users(context.Background(), admodel.SearchOptions{Scope: admodel.ScopeSubtree, TypedFilter: admodel.FilterEqual("sn", admodel.FilterText("李"))})
			if !errors.Is(err, permission) || result.Observation.Complete ||
				len(result.Users) != 1 {
				t.Fatal(result, err)
			}
		} else {
			result, err := adservice_users.New(client).
				User(context.Background(), account, admodel.ResolveIdentityOptions{})
			if !errors.Is(err, permission) || result.User != nil ||
				len(result.Observation.Candidates) != 1 {
				t.Fatal(result, err)
			}
		}
	}
}

func TestUpdateUserStrictFlagsAndRawMultivalue(t *testing.T) {
	enabled, neverExpires := true, true
	old, next := admodel.Flags32(0x40000202), admodel.Flags32(0x40010200)
	for _, code := range []uint32{0, 16, 50} {
		reads, writes := 0, 0
		client := InternalObjectTestClient(
			t,
			nil,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				reads++
				flags := old
				if reads > 1 {
					flags = next
				}
				entry := InternalUserTestEntry(flags)
				entry.Attributes["pwdlastset"] = [][]byte{[]byte("123456")}
				entry.Attributes["serviceprincipalname"] = [][]byte{
					[]byte("HOST/a"),
					[]byte("HOST/b"),
				}
				return InternalObjectTestCursor(entry), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				mods := request.InternalModifications
				if request.InternalDn != admodel.InternalObjectGUIDTarget(
					InternalObjectTestGUID(),
				) ||
					len(mods) != 3 ||
					mods[1].InternalOperation != 1 ||
					mods[2].InternalOperation != 0 ||
					string(mods[1].InternalValues[0]) != old.LDAPString() ||
					string(mods[2].InternalValues[0]) != next.LDAPString() ||
					len(mods[0].InternalValues) != 2 {
					t.Fatal(request)
				}
				if code != 0 {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteRejected,
						Err:   &admodel.LDAPError{Code: code},
					}
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		result, err := adservice_users.New(client).
			UpdateUser(context.Background(), admodel.UpdateUserRequest{Identity: InternalObjectTestIdentity(), Properties: admodel.UserProperties{Enabled: &enabled, PasswordNeverExpires: &neverExpires}, Changes: []admodel.AttributeChange{{Attribute: "servicePrincipalName", Kind: admodel.AttributeSet, Values: []admodel.RawValue{admodel.NewRawValue([]byte("HOST/a")), admodel.NewRawValue([]byte("HOST/b"))}}}})
		if writes != 1 {
			t.Fatal(writes)
		}
		if code == 0 {
			if err != nil || !result.Mutation.Verified || result.User == nil ||
				*result.User.UserAccountControl != next {
				t.Fatal(result, err)
			}
		} else {
			var native *admodel.LDAPError
			if !errors.As(err, &native) || native.Code != code || reads != 1 ||
				result.Mutation.State != admodel.ObjectWriteRejected {
				t.Fatal(result, err)
			}
		}
	}
}

func TestUserPropertyConflictsAndManagedAttributesReject(t *testing.T) {
	value := "value"
	client := InternalObjectTestClient(
		t,
		nil,
		func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			t.Fatal("invalid request read")
			return nil, nil
		},
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			t.Fatal("invalid request wrote")
			return admodel.InternalLdapWriteAttempt{}
		},
	)
	for _, change := range []admodel.AttributeChange{{Attribute: "unicodePwd", Kind: admodel.AttributeSet, Values: []admodel.RawValue{admodel.NewRawValue([]byte("public"))}}, {Attribute: "userAccountControl", Kind: admodel.AttributeClear}, {Attribute: "ms-DS-UserPasswordNotRequired", Kind: admodel.AttributeClear}, {Attribute: "MAIL", Kind: admodel.AttributeClear}} {
		_, err := adservice_users.New(client).
			UpdateUser(context.Background(), admodel.UpdateUserRequest{Identity: InternalObjectTestIdentity(), Properties: admodel.UserProperties{EmailAddress: &value}, Changes: []admodel.AttributeChange{change}})
		if err == nil {
			t.Fatal("accepted conflicting or managed attribute")
		}
	}
	request := admodel.CreateUserRequest{InitialPassword: []byte("PUBLIC-password")}
	encoded, err := json.Marshal(request)
	if err != nil || string(encoded) != `{"redacted":true}` ||
		strings.Contains(fmt.Sprintf("%+v %#v", request, request), "PUBLIC") {
		t.Fatal("creation password was not redacted")
	}
}

func TestUpdateUserNeverExpiresConflictStopsAllPropertyChanges(t *testing.T) {
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%t", kind, missing), func(t *testing.T) {
				reads, writes := 0, 0
				client := InternalObjectTestClient(
					t,
					nil,
					func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						reads++
						if !slices.Contains(query.Properties, "pwdLastSet") {
							t.Fatal("password timestamp was not requested", query.Properties)
						}
						entry := InternalUserTestEntry(512)
						entry.Attributes["displayname"] = [][]byte{[]byte("Before")}
						entry.Attributes["description"] = [][]byte{[]byte("original")}
						if !missing {
							entry.Attributes["pwdlastset"] = [][]byte{[]byte("0")}
						}
						if kind == admodel.CapabilityADLDS {
							delete(entry.Attributes, "useraccountcontrol")
							entry.Attributes["msds-userdontexpirepassword"] = [][]byte{
								[]byte("FALSE"),
							}
						}
						return InternalObjectTestCursor(entry), nil
					},
					func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						writes++
						t.Fatal(
							"conflicting account option dispatched accompanying property changes",
						)
						return admodel.InternalLdapWriteAttempt{}
					},
				)
				session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
				session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
					return InternalIdentityTestRoot(kind), nil
				}
				(*adengine.InternalClientSessionPointer(client)) = session
				name, neverExpires := "After", true
				result, err := adservice_users.New(client).
					UpdateUser(context.Background(), admodel.UpdateUserRequest{
						Identity: InternalObjectTestIdentity(),
						Properties: admodel.UserProperties{
							DisplayName:          &name,
							PasswordNeverExpires: &neverExpires,
						},
						Changes: []admodel.AttributeChange{
							{
								Attribute: "description",
								Kind:      admodel.AttributeSet,
								Values: []admodel.RawValue{
									admodel.NewRawValue([]byte("changed")),
								},
							},
						},
					})
				want := admodel.ErrInvalidAccountControl
				if missing {
					want = admodel.ErrAttributeUnavailable
				}
				if !errors.Is(err, want) || writes != 0 || reads != 1 ||
					result.Mutation.State != admodel.ObjectWriteNotAttempted ||
					result.Mutation.Verified ||
					result.Mutation.After != nil ||
					result.User != nil ||
					result.Mutation.Before == nil {
					t.Fatal(result, err, reads, writes)
				}
				if string(result.Mutation.Before.Attributes["displayname"][0]) != "Before" ||
					string(result.Mutation.Before.Attributes["description"][0]) != "original" {
					t.Fatal("preflight values were changed locally", result.Mutation.Before)
				}
			})
		}
	}
}

func TestUpdateUserNoOpRetainsRequestedProperties(t *testing.T) {
	reads := 0
	client := InternalObjectTestClient(
		t,
		nil,
		func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			reads++
			entry := InternalUserTestEntry(512)
			entry.RequestedProperties = slices.Clone(query.Properties)
			if slices.Contains(query.Properties, "employeeID") {
				entry.Attributes["employeeid"] = [][]byte{[]byte("12345")}
			}
			return InternalObjectTestCursor(entry), nil
		},
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			t.Fatal("already-satisfied flag update wrote")
			return admodel.InternalLdapWriteAttempt{}
		},
	)
	enabled := true
	result, err := adservice_users.New(client).
		UpdateUser(context.Background(), admodel.UpdateUserRequest{Identity: InternalObjectTestIdentity(), Properties: admodel.UserProperties{Enabled: &enabled}, Options: admodel.ObjectMutationOptions{Properties: []string{"employeeID"}}})
	if err != nil || reads != 1 || result.Mutation.State != admodel.ObjectWriteNotAttempted ||
		!result.Mutation.Verified ||
		!result.Mutation.ReadbackComplete ||
		result.User == nil {
		t.Fatal(result, err)
	}
	value, err := result.User.Raw.Values("employeeID").Single()
	if err != nil || string(value.Bytes()) != "12345" {
		t.Fatal("requested property lost on no-op", value, err)
	}
}

type InternalUserCreationFixture struct {
	InternalKind, InternalMode string
	InternalEntry              admodel.Object
	InternalStages             []string
	InternalPassword           bool
}

func InternalNewUserCreationFixture(
	t *testing.T,
	kind, mode string,
) (*adengine.Client, *InternalUserCreationFixture) {
	t.Helper()
	fixture := &InternalUserCreationFixture{InternalKind: kind, InternalMode: mode}
	client := InternalPasswordTestClient(
		t,
		kind,
		InternalPasswordTestProtection,
		func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			if strings.Contains(query.Filter, "classSchema") {
				return InternalObjectTestCursor(
					admodel.Object{
						Attributes: map[string][][]byte{
							"rdnattid":            {[]byte("cn")},
							"objectclasscategory": {[]byte("1")},
						},
					},
				), nil
			}
			if fixture.InternalEntry.DistinguishedName == "" {
				return InternalObjectTestCursor(InternalObjectTestEntry("CN=Users,DC=example")), nil
			}
			if mode == "creation readback" && len(fixture.InternalStages) == 1 {
				return nil, &admodel.LDAPError{Code: 50}
			}
			entry := fixture.InternalEntry
			entry.Attributes = make(map[string][][]byte, len(fixture.InternalEntry.Attributes))
			for name, values := range fixture.InternalEntry.Attributes {
				for _, value := range values {
					entry.Attributes[name] = append(entry.Attributes[name], slices.Clone(value))
				}
			}
			return InternalObjectTestCursor(entry), nil
		},
		func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			if request.InternalOperation == admodel.InternalLdapWriteAdd {
				fixture.InternalStages = append(fixture.InternalStages, "create")
				if mode == "creation uncertain" {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteUncertain,
						Err:   admodel.InternalLDAPWriteUncertainError(),
					}
				}
				if mode == "duplicate" {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteRejected,
						Err:   &admodel.LDAPError{Code: 68},
					}
				}
				fixture.InternalEntry = InternalObjectTestEntry(request.InternalDn)
				for _, mod := range request.InternalModifications {
					fixture.InternalEntry.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
				}
				fixture.InternalEntry.Attributes["name"] = fixture.InternalEntry.Attributes["cn"]
				if kind == admodel.CapabilityActiveDirectory {
					if string(fixture.InternalEntry.Attributes["useraccountcontrol"][0]) != "514" &&
						string(fixture.InternalEntry.Attributes["useraccountcontrol"][0]) != "546" {
						t.Fatal("user not created disabled")
					}
				} else if string(fixture.InternalEntry.Attributes["msds-useraccountdisabled"][0]) != "TRUE" {
					t.Fatal("LDS user not disabled")
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			}
			if request.InternalModifications[0].InternalAttribute == "unicodePwd" {
				fixture.InternalStages = append(fixture.InternalStages, "password")
				if mode == "password denied" {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteRejected,
						Err:   &admodel.LDAPError{Code: 19},
					}
				}
				if mode == "password uncertain" {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteUncertain,
						Err:   admodel.InternalLDAPWriteUncertainError(),
					}
				}
				fixture.InternalPassword = true
				fixture.InternalEntry.Attributes["pwdlastset"] = [][]byte{[]byte("1234")}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			}
			fixture.InternalStages = append(fixture.InternalStages, "enable")
			if !fixture.InternalPassword && mode != "password not required" {
				t.Fatal("enabled before successful password stage")
			}
			if mode == "enable denied" {
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: 50},
				}
			}
			for _, mod := range request.InternalModifications {
				if mod.InternalOperation == 0 || mod.InternalOperation == 2 {
					fixture.InternalEntry.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
				}
			}
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
		},
	)
	session := adengine.InternalClientSession(client).(InternalPasswordTestSession)
	base := session.InternalBase
	session.InternalBase = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
		attributes, err := base(ctx, dn, properties)
		if dn == "" {
			attributes["schemanamingcontext"] = [][]byte{
				[]byte("CN=Schema,CN=Configuration,DC=example"),
			}
		}
		return attributes, err
	}
	(*adengine.InternalClientSessionPointer(client)) = session
	return client, fixture
}

func TestCreateUserStagesStopAfterRejectedUncertainOrUnreadableState(t *testing.T) {
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		for _, mode := range []string{"success", "duplicate", "creation uncertain", "creation readback", "password denied", "password uncertain", "enable denied", "password not required"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				client, fixture := InternalNewUserCreationFixture(t, kind, mode)
				parent, _ := admodel.IdentityByDN("CN=Users,DC=example")
				enabled := true
				request := admodel.CreateUserRequest{
					Parent:          parent,
					Name:            "Jörg, 李",
					Properties:      admodel.UserProperties{Enabled: &enabled},
					InitialPassword: []byte("PUBLIC-initial-password"),
				}
				if mode == "password not required" {
					yes := true
					request.InitialPassword = nil
					request.Properties.PasswordNotRequired = &yes
				}
				result, err := adservice_users.New(client).CreateUser(context.Background(), request)
				want := []string{"create", "password", "enable"}
				switch mode {
				case "duplicate", "creation uncertain", "creation readback":
					want = []string{"create"}
				case "password denied", "password uncertain":
					want = []string{"create", "password"}
				case "password not required":
					want = []string{"create", "enable"}
				}
				if !reflect.DeepEqual(fixture.InternalStages, want) {
					t.Fatal(fixture.InternalStages, want)
				}
				if mode == "success" || mode == "password not required" {
					if err != nil || !result.Complete || result.User == nil ||
						result.User.Enabled == nil ||
						!*result.User.Enabled ||
						result.Enable == nil ||
						!result.Enable.Verified {
						t.Fatal(result, err)
					}
				} else {
					// A duplicate name is rejected with nothing written, so it
					// must report as already-exists rather than as a partly
					// finished creation; every other failure here did reach
					// the directory.
					if mode == "duplicate" {
						if errors.Is(err, admodel.ErrUserCreationIncomplete) ||
							!admodel.IsAlreadyExists(err) ||
							result.Complete {
							t.Fatal(result, err)
						}
					} else if !errors.Is(err, admodel.ErrUserCreationIncomplete) || result.Complete {
						t.Fatal(result, err)
					}
					if mode != "duplicate" && mode != "creation uncertain" &&
						result.Creation.State != admodel.ObjectWriteAccepted {
						t.Fatal("lost accepted creation")
					}
					if mode == "creation uncertain" &&
						(result.Creation.State != admodel.ObjectWriteUncertain || result.Password != nil || result.Enable != nil) {
						t.Fatal("continued after uncertain creation")
					}
					if mode == "password uncertain" &&
						(result.Password == nil || result.Password.State != admodel.ObjectWriteUncertain || result.Enable != nil) {
						t.Fatal("uncertain password replayed or enabled")
					}
				}
				if !bytes.Equal(request.InitialPassword, []byte("PUBLIC-initial-password")) &&
					mode != "password not required" {
					t.Fatal("caller secret changed")
				}
			})
		}
	}
}

func TestCreateUserRejectsImplicitPasswordExemption(t *testing.T) {
	client, fixture := InternalNewUserCreationFixture(
		t,
		admodel.CapabilityActiveDirectory,
		"success",
	)
	parent, _ := admodel.IdentityByDN("CN=Users,DC=example")
	enabled := true
	result, err := adservice_users.New(client).
		CreateUser(context.Background(), admodel.CreateUserRequest{Parent: parent, Name: "sample", Properties: admodel.UserProperties{Enabled: &enabled}})
	if !errors.Is(err, admodel.ErrInvalidUser) ||
		result.Creation.State != admodel.ObjectWriteNotAttempted ||
		len(fixture.InternalStages) != 0 {
		t.Fatal(result, err)
	}
}

func TestCreateUserDisabledDefaultAndPasswordObservation(t *testing.T) {
	for _, password := range []bool{false, true} {
		client, fixture := InternalNewUserCreationFixture(
			t,
			admodel.CapabilityActiveDirectory,
			"success",
		)
		parent, _ := admodel.IdentityByDN("CN=Users,DC=example")
		request := admodel.CreateUserRequest{Parent: parent, Name: "disabled"}
		if password {
			request.InitialPassword = []byte("PUBLIC-disabled-password")
		}
		result, err := adservice_users.New(client).CreateUser(context.Background(), request)
		if err != nil || !result.Complete || result.Enable != nil || result.User == nil ||
			result.User.Enabled == nil ||
			*result.User.Enabled ||
			result.User.PasswordNotRequired == nil ||
			*result.User.PasswordNotRequired {
			t.Fatal(result, err)
		}
		if password {
			if !reflect.DeepEqual(fixture.InternalStages, []string{"create", "password"}) ||
				result.Observation == nil ||
				result.User.PasswordLastSet == nil ||
				*result.User.PasswordLastSet != 1234 {
				t.Fatal("password observation or ordering lost", fixture.InternalStages, result)
			}
		} else if !reflect.DeepEqual(fixture.InternalStages, []string{"create"}) || result.Password != nil || result.Observation != nil {
			t.Fatal(fixture.InternalStages, result)
		}
	}
}

func TestCreateUserRejectsInsecurePasswordBeforeAdd(t *testing.T) {
	client, fixture := InternalNewUserCreationFixture(
		t,
		admodel.CapabilityActiveDirectory,
		"success",
	)
	session := adengine.InternalClientSession(client).(InternalPasswordTestSession)
	session.InternalProtect = func(context.Context, admodel.Transport) (admodel.PasswordProtection, error) {
		return admodel.PasswordProtection{
			Transport:  adengine.InternalClientConfig(client).Transport,
			CipherBits: 56,
		}, nil
	}
	(*adengine.InternalClientSessionPointer(client)) = session
	parent, _ := admodel.IdentityByDN("CN=Users,DC=example")
	result, err := adservice_users.New(client).
		CreateUser(context.Background(), admodel.CreateUserRequest{Parent: parent, Name: "sample", InitialPassword: []byte("PUBLIC-password")})
	if !errors.Is(err, admodel.ErrPasswordProtection) ||
		result.Creation.State != admodel.ObjectWriteNotAttempted ||
		len(fixture.InternalStages) != 0 {
		t.Fatal(result, err)
	}
}

func TestDeleteUserClassGuardLeafAndAbsentReadback(t *testing.T) {
	for _, computer := range []bool{false, true} {
		reads, writes := 0, 0
		client := InternalObjectTestClient(
			t,
			nil,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				reads++
				if writes != 0 {
					return InternalObjectTestCursor(), nil
				}
				entry := InternalUserTestEntry(512)
				if computer {
					entry.Attributes["objectclass"] = append(
						entry.Attributes["objectclass"],
						[]byte("computer"),
					)
				}
				return InternalObjectTestCursor(entry), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if request.InternalOperation != admodel.InternalLdapWriteDelete ||
					request.InternalDn != admodel.InternalObjectGUIDTarget(
						InternalObjectTestGUID(),
					) ||
					len(request.InternalControls) != 0 {
					t.Fatal(request)
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		result, err := adservice_users.New(client).
			DeleteUser(context.Background(), admodel.DeleteUserRequest{Identity: InternalObjectTestIdentity()})
		if computer {
			if !errors.Is(err, admodel.ErrNotUser) || writes != 0 || reads != 1 {
				t.Fatal(result, err)
			}
		} else if err != nil || writes != 1 || reads != 2 || !result.Mutation.Verified || !result.Mutation.AbsentAfter {
			t.Fatal(result, err)
		}
	}
}
