package activedirectory

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func groupTestEntry(flags Flags32) Object {
	object := objectTestEntry("CN=sample,DC=example")
	object.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("group")}
	object.Attributes["name"] = [][]byte{[]byte("sample")}
	object.Attributes["grouptype"] = [][]byte{[]byte(flags.LDAPString())}
	object.Attributes["samaccountname"] = [][]byte{[]byte("sample")}
	sid, _ := ParseSID("S-1-5-21-42")
	object.Attributes["objectsid"] = [][]byte{sid.Bytes()}
	return object
}

func TestGroupDecodeRetainsUnknownBitsAndAttributeState(t *testing.T) {
	for _, tc := range []struct {
		flags    Flags32
		scope    GroupScope
		category GroupCategory
		builtin  bool
	}{
		{0x80000002, GroupGlobal, GroupSecurity, false},
		{4, GroupDomainLocal, GroupDistribution, false},
		{0x80000005, GroupDomainLocal, GroupSecurity, true},
		{0x40000008, GroupUniversal, GroupDistribution, false},
		{0x10, GroupScopeUnknown, GroupDistribution, false},
	} {
		object := groupTestEntry(tc.flags)
		object.Attributes["member;range=0-1"] = [][]byte{[]byte("CN=a,DC=example"), []byte("CN=b,DC=example")}
		group, err := decodeGroup(object)
		if err != nil || group.Type == nil || *group.Type != tc.flags || *group.Scope != tc.scope || *group.Category != tc.category || *group.Builtin != tc.builtin || group.Description != nil || group.GUID == nil || group.SID == nil {
			t.Fatalf("flags=%x: %+v %v", tc.flags, group, err)
		}
		if group.Raw.Values("member").State != AttributePartial {
			t.Fatal("ranged membership represented as complete")
		}
	}
	object := groupTestEntry(2)
	delete(object.Attributes, "grouptype")
	group, err := decodeGroup(object)
	if err != nil || group.Type != nil || group.Scope != nil || group.Category != nil {
		t.Fatal(group, err)
	}
	object.Attributes["grouptype"] = [][]byte{[]byte("4294967296")}
	if group, err := decodeGroup(object); err == nil || group.Type != nil || !reflect.DeepEqual(group.Raw, object) {
		t.Fatal(group, err)
	}
}

func TestGroupIdentityClassAndPartialResolution(t *testing.T) {
	account, _ := IdentityByAccountName("sample")
	for _, mode := range []string{"group", "user", "partial"} {
		t.Run(mode, func(t *testing.T) {
			denied := &LDAPError{Code: 50, Diagnostic: "retained"}
			client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
				if query.Filter != "(&(objectSid=*)(sAMAccountName=sample))" {
					t.Fatal(query.Filter)
				}
				entry := groupTestEntry(2)
				if mode == "user" {
					entry.Attributes["objectclass"] = [][]byte{[]byte("user")}
				}
				if mode == "partial" {
					return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return []Object{entry}, false, denied }, finish: func() error { return nil }}, nil
				}
				return objectTestCursor(entry), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				t.Fatal("read submitted write")
				return ldapWriteAttempt{}
			})
			result, err := client.Group(context.Background(), account, ResolveIdentityOptions{})
			switch mode {
			case "group":
				if err != nil || result.Group == nil || !result.Observation.Complete {
					t.Fatal(result, err)
				}
			case "user":
				if !errors.Is(err, ErrNotGroup) {
					t.Fatal(err)
				}
			case "partial":
				if !errors.Is(err, denied) || result.Group != nil || len(result.Observation.Candidates) != 1 || result.Observation.Complete {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestGroupsComposeSharedFiltersAndRetainPartialResults(t *testing.T) {
	for _, typed := range []bool{false, true} {
		permission := &LDAPError{Code: 50}
		closed := 0
		client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
			if query.Base != "DC=example" || query.Scope != ScopeSubtree || query.Filter != "(&(objectClass=group)(name=sample))" || query.PageSize != 2 {
				t.Fatalf("%+v", query)
			}
			return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
				return []Object{groupTestEntry(2)}, false, permission
			}, finish: func() error { closed++; return nil }}, nil
		}, func(context.Context, ldapWriteRequest) ldapWriteAttempt { t.Fatal("write"); return ldapWriteAttempt{} })
		options := SearchOptions{Scope: ScopeSubtree, PageSize: 2, Filter: "(name=sample)"}
		if typed {
			options.Filter = ""
			options.TypedFilter = FilterEqual("name", FilterText("sample"))
		}
		result, err := client.Groups(context.Background(), options)
		if !errors.Is(err, permission) || result.Observation.Complete || len(result.Groups) != 1 || len(result.Observation.Objects) != 1 || closed != 1 {
			t.Fatal(result, err, closed)
		}
	}
	var client *Client
	if _, err := client.Groups(context.Background(), SearchOptions{Filter: "(name=x)", TypedFilter: FilterPresent("name")}); !errors.Is(err, ErrConflictingFilters) {
		t.Fatal(err)
	}
}

func TestCreateGroupLiteralNamesAndProperties(t *testing.T) {
	parent, _ := IdentityByDN("DC=example")
	name := "Dŵr, 李"
	sam, description := "literal$", "description"
	writes := 0
	client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if strings.Contains(query.Filter, "classSchema") {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		if writes == 0 {
			return objectTestCursor(objectTestEntry("DC=example")), nil
		}
		entry := groupTestEntry(0x80000008)
		entry.DistinguishedName = `cn=Dŵr\, 李,DC=example`
		entry.Attributes["cn"] = [][]byte{[]byte(name)}
		entry.Attributes["description"] = [][]byte{[]byte(description)}
		entry.Attributes["samaccountname"] = [][]byte{[]byte(sam)}
		return objectTestCursor(entry), nil
	}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
		writes++
		if request.operation != ldapWriteAdd || request.dn != `cn=Dŵr\, 李,DC=example` {
			t.Fatal(request)
		}
		values := map[string]string{}
		for _, mod := range request.modifications {
			values[strings.ToLower(mod.attribute)] = string(mod.values[0])
		}
		if values["grouptype"] != "-2147483640" || values["samaccountname"] != sam || values["description"] != description {
			t.Fatal(values)
		}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	})
	result, err := client.CreateGroup(context.Background(), CreateGroupRequest{Parent: parent, Name: name, Category: GroupSecurity, Scope: GroupUniversal, SAMAccountName: &sam, Description: &description})
	if err != nil || writes != 1 || result.Group == nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted {
		t.Fatal(result, err, writes)
	}
}

func TestGroupUpdateAtomicTypePreservesUnrelatedBits(t *testing.T) {
	category, scope := GroupDistribution, GroupUniversal
	old := Flags32(0xc0000002)
	newFlags := Flags32(0x40000008)
	for _, outcome := range []string{"accepted", "denied", "concurrent", "uncertain", "readback"} {
		t.Run(outcome, func(t *testing.T) {
			reads, writes := 0, 0
			permission := &LDAPError{Code: 50, Diagnostic: "private"}
			client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
				reads++
				flags := old
				if reads > 1 {
					flags = newFlags
					if outcome == "readback" {
						return nil, permission
					}
				}
				return objectTestCursor(groupTestEntry(flags)), nil
			}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
				writes++
				if request.operation != ldapWriteModify || request.dn != objectGUIDTarget(objectTestGUID()) || len(request.modifications) != 2 {
					t.Fatal(request)
				}
				remove, add := request.modifications[0], request.modifications[1]
				if remove.operation != 1 || add.operation != 0 || remove.attribute != "groupType" || add.attribute != "groupType" || string(remove.values[0]) != old.LDAPString() || string(add.values[0]) != newFlags.LDAPString() {
					t.Fatal(request.modifications)
				}
				switch outcome {
				case "denied":
					return ldapWriteAttempt{State: ldapWriteRejected, Err: permission}
				case "concurrent":
					return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 16}}
				case "uncertain":
					return ldapWriteAttempt{State: ldapWriteUncertain, Err: context.DeadlineExceeded}
				}
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			result, err := client.UpdateGroup(context.Background(), UpdateGroupRequest{Identity: objectTestIdentity(), Category: &category, Scope: &scope})
			if writes != 1 {
				t.Fatal(writes)
			}
			switch outcome {
			case "accepted":
				if err != nil || !result.Mutation.Verified || result.Group == nil || *result.Group.Type != newFlags || reads != 2 {
					t.Fatal(result, err, reads)
				}
			case "denied":
				if !errors.Is(err, ErrObjectWritePermission) || !errors.Is(err, permission) || result.Mutation.State != ObjectWriteRejected || reads != 1 {
					t.Fatal(result, err, reads)
				}
			case "concurrent":
				var native *LDAPError
				if !errors.As(err, &native) || native.Code != 16 || reads != 1 {
					t.Fatal(result, err, reads)
				}
			case "uncertain":
				if !errors.Is(err, ErrObjectWriteUncertain) || result.Mutation.State != ObjectWriteUncertain || reads != 1 {
					t.Fatal(result, err, reads)
				}
			case "readback":
				if !errors.Is(err, ErrObjectReadback) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestGroupMutationRejectsWrongClassBeforeWriting(t *testing.T) {
	description := "new"
	client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
		entry := groupTestEntry(2)
		entry.Attributes["objectclass"] = [][]byte{[]byte("user")}
		return objectTestCursor(entry), nil
	}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		t.Fatal("wrote non-group")
		return ldapWriteAttempt{}
	})
	if result, err := client.UpdateGroup(context.Background(), UpdateGroupRequest{Identity: objectTestIdentity(), Description: &description}); !errors.Is(err, ErrNotGroup) || result.Mutation.State != ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
	if result, err := client.DeleteGroup(context.Background(), DeleteGroupRequest{Identity: objectTestIdentity()}); !errors.Is(err, ErrNotGroup) || result.Mutation.State != ObjectWriteNotAttempted {
		t.Fatal(result, err)
	}
}

func TestGroupNoChangeAndVersionCannotBePretendedEnforced(t *testing.T) {
	category := GroupSecurity
	client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if !slices.Contains(query.Properties, "extensionAttribute1") {
			t.Fatal("no-op omitted requested property", query.Properties)
		}
		entry := groupTestEntry(0x80000002)
		entry.Attributes["extensionattribute1"] = [][]byte{[]byte("extra")}
		return objectTestCursor(entry), nil
	}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		t.Fatal("no-op wrote")
		return ldapWriteAttempt{}
	})
	request := UpdateGroupRequest{Identity: objectTestIdentity(), Category: &category, Options: ObjectMutationOptions{Properties: []string{"extensionAttribute1"}}}
	result, err := client.UpdateGroup(context.Background(), request)
	if err != nil || result.Mutation.State != ObjectWriteNotAttempted || !result.Mutation.Verified {
		t.Fatal(result, err)
	}
	if value, valueErr := result.Group.Raw.Values("extensionAttribute1").Single(); valueErr != nil || string(value.Bytes()) != "extra" {
		t.Fatal(value, valueErr)
	}
	request.Options.ExpectedVersion = &ObjectVersion{GUID: objectTestGUID()}
	result, err = client.UpdateGroup(context.Background(), request)
	if !errors.Is(err, ErrObjectControlUnsupported) || result.Mutation.Verified {
		t.Fatal(result, err)
	}
}

func TestGroupInvalidInputsDoNotReachSession(t *testing.T) {
	var client *Client
	category := GroupCategoryUnknown
	text := "x"
	for _, request := range []UpdateGroupRequest{
		{Identity: objectTestIdentity(), Category: &category},
		{Identity: objectTestIdentity(), Changes: []AttributeChange{{Attribute: "groupType", Kind: AttributeClear}}},
		{Identity: objectTestIdentity(), Description: &text, Changes: []AttributeChange{{Attribute: "DESCRIPTION", Kind: AttributeClear}}},
		{Identity: objectTestIdentity(), ManagedByDN: &text},
	} {
		if _, err := client.UpdateGroup(context.Background(), request); err == nil || errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
	for _, request := range []CreateGroupRequest{
		{Category: GroupCategoryUnknown, Scope: GroupGlobal},
		{Category: GroupSecurity, Scope: GroupScopeUnknown},
		{Category: GroupSecurity, Scope: GroupGlobal, Attributes: map[string][]RawValue{"GROUPTYPE": {NewRawValue([]byte("2"))}}},
		{Category: GroupSecurity, Scope: GroupGlobal, Description: &text, Attributes: map[string][]RawValue{"DESCRIPTION": {NewRawValue([]byte("other"))}}},
	} {
		if _, err := client.CreateGroup(context.Background(), request); err == nil || errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
}

func TestDeleteGroupOnlyDeletesResolvedGUID(t *testing.T) {
	reads, writes := 0, 0
	client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
		reads++
		if reads > 1 {
			return objectTestCursor(), nil
		}
		return objectTestCursor(groupTestEntry(2)), nil
	}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
		writes++
		if request.operation != ldapWriteDelete || request.dn != objectGUIDTarget(objectTestGUID()) || len(request.controls) != 0 {
			t.Fatal(request)
		}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	})
	result, err := client.DeleteGroup(context.Background(), DeleteGroupRequest{Identity: objectTestIdentity()})
	if err != nil || writes != 1 || !result.Mutation.Verified || !result.Mutation.AbsentAfter || result.Mutation.PartialEffectsPossible {
		t.Fatal(result, err)
	}
}
