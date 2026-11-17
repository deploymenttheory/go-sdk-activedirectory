package acceptance

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_groups "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
)

func InternalGroupTestEntry(flags admodel.Flags32) admodel.Object {
	object := InternalObjectTestEntry("CN=sample,DC=example")
	object.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("group")}
	object.Attributes["name"] = [][]byte{[]byte("sample")}
	object.Attributes["grouptype"] = [][]byte{[]byte(flags.LDAPString())}
	object.Attributes["samaccountname"] = [][]byte{[]byte("sample")}
	sid, _ := admodel.ParseSID("S-1-5-21-42")
	object.Attributes["objectsid"] = [][]byte{sid.Bytes()}
	return object
}

func TestGroupDecodeRetainsUnknownBitsAndAttributeState(t *testing.T) {
	for _, tc := range []struct {
		InternalFlags    admodel.Flags32
		InternalScope    admodel.GroupScope
		InternalCategory admodel.GroupCategory
		InternalBuiltin  bool
	}{
		{0x80000002, admodel.GroupGlobal, admodel.GroupSecurity, false},
		{4, admodel.GroupDomainLocal, admodel.GroupDistribution, false},
		{0x80000005, admodel.GroupDomainLocal, admodel.GroupSecurity, true},
		{0x40000008, admodel.GroupUniversal, admodel.GroupDistribution, false},
		{0x10, admodel.GroupScopeUnknown, admodel.GroupDistribution, false},
	} {
		object := InternalGroupTestEntry(tc.InternalFlags)
		object.Attributes["member;range=0-1"] = [][]byte{
			[]byte("CN=a,DC=example"),
			[]byte("CN=b,DC=example"),
		}
		group, err := admodel.InternalDecodeGroup(object)
		if err != nil || group.Type == nil || *group.Type != tc.InternalFlags ||
			*group.Scope != tc.InternalScope ||
			*group.Category != tc.InternalCategory ||
			*group.Builtin != tc.InternalBuiltin ||
			group.Description != nil ||
			group.GUID == nil ||
			group.SID == nil {
			t.Fatalf("flags=%x: %+v %v", tc.InternalFlags, group, err)
		}
		if group.Raw.Values("member").State != admodel.AttributePartial {
			t.Fatal("ranged membership represented as complete")
		}
	}
	object := InternalGroupTestEntry(2)
	delete(object.Attributes, "grouptype")
	group, err := admodel.InternalDecodeGroup(object)
	if err != nil || group.Type != nil || group.Scope != nil || group.Category != nil {
		t.Fatal(group, err)
	}
	object.Attributes["grouptype"] = [][]byte{[]byte("4294967296")}
	if group, err := admodel.InternalDecodeGroup(
		object,
	); err == nil || group.Type != nil ||
		!reflect.DeepEqual(group.Raw, object) {
		t.Fatal(group, err)
	}
}

func TestGroupIdentityClassAndPartialResolution(t *testing.T) {
	account, _ := admodel.IdentityByAccountName("sample")
	for _, mode := range []string{"group", "user", "partial"} {
		t.Run(mode, func(t *testing.T) {
			denied := &admodel.LDAPError{Code: 50, Diagnostic: "retained"}
			client := InternalObjectTestClient(
				t,
				nil,
				func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if query.Filter != "(&(objectSid=*)(sAMAccountName=sample))" {
						t.Fatal(query.Filter)
					}
					entry := InternalGroupTestEntry(2)
					if mode == "user" {
						entry.Attributes["objectclass"] = [][]byte{[]byte("user")}
					}
					if mode == "partial" {
						return InternalTestSearchCursor{
							InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
								return []admodel.Object{entry}, false, denied
							},
							InternalFinish: func() error { return nil },
						}, nil
					}
					return InternalObjectTestCursor(entry), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					t.Fatal("read submitted write")
					return admodel.InternalLdapWriteAttempt{}
				},
			)
			result, err := adservice_groups.New(client).
				Group(context.Background(), account, admodel.ResolveIdentityOptions{})
			switch mode {
			case "group":
				if err != nil || result.Group == nil || !result.Observation.Complete {
					t.Fatal(result, err)
				}
			case "user":
				if !errors.Is(err, admodel.ErrNotGroup) {
					t.Fatal(err)
				}
			case "partial":
				if !errors.Is(err, denied) || result.Group != nil ||
					len(result.Observation.Candidates) != 1 ||
					result.Observation.Complete {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestGroupsComposeSharedFiltersAndRetainPartialResults(t *testing.T) {
	for _, typed := range []bool{false, true} {
		permission := &admodel.LDAPError{Code: 50}
		closed := 0
		client := InternalObjectTestClient(
			t,
			nil,
			func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				if query.Base != "DC=example" || query.Scope != admodel.ScopeSubtree ||
					query.Filter != "(&(objectClass=group)(name=sample))" ||
					query.PageSize != 2 {
					t.Fatalf("%+v", query)
				}
				return InternalTestSearchCursor{
					InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
						return []admodel.Object{InternalGroupTestEntry(2)}, false, permission
					},
					InternalFinish: func() error { closed++; return nil },
				}, nil
			},
			func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				t.Fatal("write")
				return admodel.InternalLdapWriteAttempt{}
			},
		)
		options := admodel.SearchOptions{
			Scope:    admodel.ScopeSubtree,
			PageSize: 2,
			Filter:   "(name=sample)",
		}
		if typed {
			options.Filter = ""
			options.TypedFilter = admodel.FilterEqual("name", admodel.FilterText("sample"))
		}
		result, err := adservice_groups.New(client).Groups(context.Background(), options)
		if !errors.Is(err, permission) || result.Observation.Complete || len(result.Groups) != 1 ||
			len(result.Observation.Objects) != 1 ||
			closed != 1 {
			t.Fatal(result, err, closed)
		}
	}
	var client *adengine.Client
	if _, err := adservice_groups.New(client).
		Groups(context.Background(), admodel.SearchOptions{Filter: "(name=x)", TypedFilter: admodel.FilterPresent("name")}); !errors.Is(
		err,
		admodel.ErrConflictingFilters,
	) {
		t.Fatal(err)
	}
}

func TestCreateGroupLiteralNamesAndProperties(t *testing.T) {
	parent, _ := admodel.IdentityByDN("DC=example")
	name := "Dŵr, 李"
	sam, description := "literal$", "description"
	writes := 0
	client := InternalObjectTestClient(
		t,
		nil,
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
			if writes == 0 {
				return InternalObjectTestCursor(InternalObjectTestEntry("DC=example")), nil
			}
			entry := InternalGroupTestEntry(0x80000008)
			entry.DistinguishedName = `cn=Dŵr\, 李,DC=example`
			entry.Attributes["cn"] = [][]byte{[]byte(name)}
			entry.Attributes["description"] = [][]byte{[]byte(description)}
			entry.Attributes["samaccountname"] = [][]byte{[]byte(sam)}
			return InternalObjectTestCursor(entry), nil
		},
		func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			writes++
			if request.InternalOperation != admodel.InternalLdapWriteAdd ||
				request.InternalDn != `cn=Dŵr\, 李,DC=example` {
				t.Fatal(request)
			}
			values := map[string]string{}
			for _, mod := range request.InternalModifications {
				values[strings.ToLower(mod.InternalAttribute)] = string(mod.InternalValues[0])
			}
			if values["grouptype"] != "-2147483640" || values["samaccountname"] != sam ||
				values["description"] != description {
				t.Fatal(values)
			}
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
		},
	)
	result, err := adservice_groups.New(client).
		CreateGroup(context.Background(), admodel.CreateGroupRequest{Parent: parent, Name: name, Category: admodel.GroupSecurity, Scope: admodel.GroupUniversal, SAMAccountName: &sam, Description: &description})
	if err != nil || writes != 1 || result.Group == nil || !result.Mutation.Verified ||
		result.Mutation.State != admodel.ObjectWriteAccepted {
		t.Fatal(result, err, writes)
	}
}

func TestGroupUpdateAtomicTypePreservesUnrelatedBits(t *testing.T) {
	category, scope := admodel.GroupDistribution, admodel.GroupUniversal
	old := admodel.Flags32(0xc0000002)
	newFlags := admodel.Flags32(0x40000008)
	for _, outcome := range []string{"accepted", "denied", "concurrent", "uncertain", "readback"} {
		t.Run(outcome, func(t *testing.T) {
			reads, writes := 0, 0
			permission := &admodel.LDAPError{Code: 50, Diagnostic: "private"}
			client := InternalObjectTestClient(
				t,
				nil,
				func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					reads++
					flags := old
					if reads > 1 {
						flags = newFlags
						if outcome == "readback" {
							return nil, permission
						}
					}
					return InternalObjectTestCursor(InternalGroupTestEntry(flags)), nil
				},
				func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					if request.InternalOperation != admodel.InternalLdapWriteModify ||
						request.InternalDn != admodel.InternalObjectGUIDTarget(
							InternalObjectTestGUID(),
						) ||
						len(request.InternalModifications) != 2 {
						t.Fatal(request)
					}
					remove, add := request.InternalModifications[0], request.InternalModifications[1]
					if remove.InternalOperation != 1 || add.InternalOperation != 0 ||
						remove.InternalAttribute != "groupType" ||
						add.InternalAttribute != "groupType" ||
						string(remove.InternalValues[0]) != old.LDAPString() ||
						string(add.InternalValues[0]) != newFlags.LDAPString() {
						t.Fatal(request.InternalModifications)
					}
					switch outcome {
					case "denied":
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteRejected,
							Err:   permission,
						}
					case "concurrent":
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteRejected,
							Err:   &admodel.LDAPError{Code: 16},
						}
					case "uncertain":
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteUncertain,
							Err:   context.DeadlineExceeded,
						}
					}
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			result, err := adservice_groups.New(client).
				UpdateGroup(context.Background(), admodel.UpdateGroupRequest{Identity: InternalObjectTestIdentity(), Category: &category, Scope: &scope})
			if writes != 1 {
				t.Fatal(writes)
			}
			switch outcome {
			case "accepted":
				if err != nil || !result.Mutation.Verified || result.Group == nil ||
					*result.Group.Type != newFlags ||
					reads != 2 {
					t.Fatal(result, err, reads)
				}
			case "denied":
				if !errors.Is(err, admodel.ErrObjectWritePermission) ||
					!errors.Is(err, permission) ||
					result.Mutation.State != admodel.ObjectWriteRejected ||
					reads != 1 {
					t.Fatal(result, err, reads)
				}
			case "concurrent":
				var native *admodel.LDAPError
				if !errors.As(err, &native) || native.Code != 16 || reads != 1 {
					t.Fatal(result, err, reads)
				}
			case "uncertain":
				if !errors.Is(err, admodel.ErrObjectWriteUncertain) ||
					result.Mutation.State != admodel.ObjectWriteUncertain ||
					reads != 1 {
					t.Fatal(result, err, reads)
				}
			case "readback":
				if !errors.Is(err, admodel.ErrObjectReadback) ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					result.Mutation.Verified {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestGroupMutationRejectsWrongClassBeforeWriting(t *testing.T) {
	description := "new"
	client := InternalObjectTestClient(
		t,
		nil,
		func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			entry := InternalGroupTestEntry(2)
			entry.Attributes["objectclass"] = [][]byte{[]byte("user")}
			return InternalObjectTestCursor(entry), nil
		},
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			t.Fatal("wrote non-group")
			return admodel.InternalLdapWriteAttempt{}
		},
	)
	if result, err := adservice_groups.New(client).
		UpdateGroup(context.Background(), admodel.UpdateGroupRequest{Identity: InternalObjectTestIdentity(), Description: &description}); !errors.Is(err, admodel.ErrNotGroup) ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
	if result, err := adservice_groups.New(client).
		DeleteGroup(context.Background(), admodel.DeleteGroupRequest{Identity: InternalObjectTestIdentity()}); !errors.Is(err, admodel.ErrNotGroup) ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
}

func TestGroupNoChangeAndVersionCannotBePretendedEnforced(t *testing.T) {
	category := admodel.GroupSecurity
	client := InternalObjectTestClient(
		t,
		nil,
		func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			if !slices.Contains(query.Properties, "extensionAttribute1") {
				t.Fatal("no-op omitted requested property", query.Properties)
			}
			entry := InternalGroupTestEntry(0x80000002)
			entry.Attributes["extensionattribute1"] = [][]byte{[]byte("extra")}
			return InternalObjectTestCursor(entry), nil
		},
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			t.Fatal("no-op wrote")
			return admodel.InternalLdapWriteAttempt{}
		},
	)
	request := admodel.UpdateGroupRequest{
		Identity: InternalObjectTestIdentity(),
		Category: &category,
		Options:  admodel.ObjectMutationOptions{Properties: []string{"extensionAttribute1"}},
	}
	result, err := adservice_groups.New(client).UpdateGroup(context.Background(), request)
	if err != nil || result.Mutation.State != admodel.ObjectWriteNotAttempted ||
		!result.Mutation.Verified {
		t.Fatal(result, err)
	}
	if value, valueErr := result.Group.Raw.Values("extensionAttribute1").
		Single(); valueErr != nil ||
		string(value.Bytes()) != "extra" {
		t.Fatal(value, valueErr)
	}
	request.Options.ExpectedVersion = &admodel.ObjectVersion{GUID: InternalObjectTestGUID()}
	result, err = adservice_groups.New(client).UpdateGroup(context.Background(), request)
	if !errors.Is(err, admodel.ErrObjectControlUnsupported) || result.Mutation.Verified {
		t.Fatal(result, err)
	}
}

func TestGroupInvalidInputsDoNotReachSession(t *testing.T) {
	var client *adengine.Client
	category := admodel.GroupCategoryUnknown
	text := "x"
	for _, request := range []admodel.UpdateGroupRequest{
		{Identity: InternalObjectTestIdentity(), Category: &category},
		{Identity: InternalObjectTestIdentity(), Changes: []admodel.AttributeChange{{Attribute: "groupType", Kind: admodel.AttributeClear}}},
		{Identity: InternalObjectTestIdentity(), Description: &text, Changes: []admodel.AttributeChange{{Attribute: "DESCRIPTION", Kind: admodel.AttributeClear}}},
		{Identity: InternalObjectTestIdentity(), ManagedByDN: &text},
	} {
		if _, err := adservice_groups.New(client).
			UpdateGroup(context.Background(), request); err == nil ||
			errors.Is(err, admodel.ErrClosed) {
			t.Fatal(err)
		}
	}
	for _, request := range []admodel.CreateGroupRequest{
		{Category: admodel.GroupCategoryUnknown, Scope: admodel.GroupGlobal},
		{Category: admodel.GroupSecurity, Scope: admodel.GroupScopeUnknown},
		{Category: admodel.GroupSecurity, Scope: admodel.GroupGlobal, Attributes: map[string][]admodel.RawValue{"GROUPTYPE": {admodel.NewRawValue([]byte("2"))}}},
		{Category: admodel.GroupSecurity, Scope: admodel.GroupGlobal, Description: &text, Attributes: map[string][]admodel.RawValue{"DESCRIPTION": {admodel.NewRawValue([]byte("other"))}}},
	} {
		if _, err := adservice_groups.New(client).
			CreateGroup(context.Background(), request); err == nil ||
			errors.Is(err, admodel.ErrClosed) {
			t.Fatal(err)
		}
	}
}

func TestDeleteGroupOnlyDeletesResolvedGUID(t *testing.T) {
	reads, writes := 0, 0
	client := InternalObjectTestClient(
		t,
		nil,
		func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			reads++
			if reads > 1 {
				return InternalObjectTestCursor(), nil
			}
			return InternalObjectTestCursor(InternalGroupTestEntry(2)), nil
		},
		func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			writes++
			if request.InternalOperation != admodel.InternalLdapWriteDelete ||
				request.InternalDn != admodel.InternalObjectGUIDTarget(InternalObjectTestGUID()) ||
				len(request.InternalControls) != 0 {
				t.Fatal(request)
			}
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
		},
	)
	result, err := adservice_groups.New(client).
		DeleteGroup(context.Background(), admodel.DeleteGroupRequest{Identity: InternalObjectTestIdentity()})
	if err != nil || writes != 1 || !result.Mutation.Verified || !result.Mutation.AbsentAfter ||
		result.Mutation.PartialEffectsPossible {
		t.Fatal(result, err)
	}
}
