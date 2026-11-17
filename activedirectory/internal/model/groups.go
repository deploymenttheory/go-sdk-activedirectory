package model

import (
	"errors"
	"slices"
	"strings"
)

var (
	ErrNotGroup     = errors.New("directory object is not a group")
	ErrInvalidGroup = errors.New("invalid group request")
)

type GroupCategory uint8

const (
	GroupCategoryUnknown GroupCategory = iota
	GroupSecurity
	GroupDistribution
)

type GroupScope uint8

const (
	GroupScopeUnknown GroupScope = iota
	GroupGlobal
	GroupDomainLocal
	GroupUniversal
)

const (
	InternalGroupBuiltinBit  Flags32 = 1
	InternalGroupScopeBits   Flags32 = 2 | 4 | 8
	InternalGroupSecurityBit Flags32 = 0x80000000
)

// Group preserves the original object, including unknown flags and ranged
// values. Nil fields were not returned. ScopeUnknown denotes returned flags
// with no recognized unambiguous scope. Members are not implicitly loaded.
type Group struct {
	DistinguishedName                                                     string
	GUID                                                                  *GUID
	SID                                                                   *SID
	Name, SAMAccountName, Description, DisplayName, HomePage, ManagedByDN *string
	Type                                                                  *Flags32
	Category                                                              *GroupCategory
	Scope                                                                 *GroupScope
	Builtin                                                               *bool
	Raw                                                                   Object
}

type GroupResult struct {
	Group       *Group
	Observation IdentityResult
}

type GroupsResult struct {
	Groups      []Group
	Observation SearchResult
}

type GroupMutationResult struct {
	Group    *Group
	Mutation ObjectMutationResult
}

// CreateGroupRequest requires category and scope; omitted Parent selects the
// configured Users container (the Roles container on applicable AD LDS). The
// server enforces schema, uniqueness, naming and directory-specific constraints.
// An omitted SAMAccountName is left to the server; Name is never rewritten.
type CreateGroupRequest struct {
	Parent                                                          Identity
	Name                                                            string
	Category                                                        GroupCategory
	Scope                                                           GroupScope
	SAMAccountName, Description, DisplayName, HomePage, ManagedByDN *string
	Attributes                                                      map[string][]RawValue
	Options                                                         ObjectMutationOptions
}

// UpdateGroupRequest changes only supplied properties. Use Changes with
// AttributeClear to clear a text property; a non-nil string is a literal value.
// A typed property and a raw change for the same attribute are rejected.
// groupType must be changed through Category/Scope, preserving unrelated bits.
type UpdateGroupRequest struct {
	Identity                                                        Identity
	Category                                                        *GroupCategory
	Scope                                                           *GroupScope
	SAMAccountName, Description, DisplayName, HomePage, ManagedByDN *string
	Changes                                                         []AttributeChange
	Options                                                         ObjectMutationOptions
}

// DeleteGroupRequest performs a leaf delete. Deleting a group does not delete
// its members. Tree deletion is available only through explicit DeleteObject.
type DeleteGroupRequest struct {
	Identity Identity
	Options  ObjectMutationOptions
}

func InternalGroupProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectClass",
		"objectGUID",
		"objectSid",
		"groupType",
		"name",
		"sAMAccountName",
		"description",
		"displayName",
		"wWWHomePage",
		"managedBy",
	)
}

func InternalGroupIdentityOptions(
	identity Identity,
	partition string,
	properties []string,
) ResolveIdentityOptions {
	target := IdentityTargetObject
	if identity.Form() == IdentityFormSID || identity.Form() == IdentityFormAccountName {
		target = IdentityTargetAccount
	}
	return ResolveIdentityOptions{
		Target:     target,
		Partition:  partition,
		Properties: InternalGroupProperties(properties),
	}
}

func InternalGroupClass(object Object) error {
	values, state := object.Attribute("objectClass")
	if state != AttributePresent {
		return errors.Join(ErrNotGroup, ErrAttributeUnavailable)
	}
	for _, value := range values {
		text, err := NewRawValue(value).Text()
		if err != nil {
			return errors.Join(ErrNotGroup, err)
		}
		if strings.EqualFold(text, "group") {
			return nil
		}
	}
	return ErrNotGroup
}

func InternalDecodeGroup(object Object) (Group, error) {
	group := Group{DistinguishedName: object.DistinguishedName, Raw: object}
	if err := InternalGroupClass(object); err != nil {
		return group, err
	}
	decoder := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	for attribute, field := range map[string]**string{
		"name": &group.Name, "sAMAccountName": &group.SAMAccountName,
		"description": &group.Description, "displayName": &group.DisplayName,
		"wWWHomePage": &group.HomePage, "managedBy": &group.ManagedByDN,
	} {
		*field = decoder.InternalText(attribute)
	}
	for _, attribute := range []string{"objectGUID", "objectSid", "groupType"} {
		values := object.Values(attribute)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			decoder.InternalErrors = append(decoder.InternalErrors, err)
			continue
		}
		switch attribute {
		case "objectGUID":
			guid, err := value.GUID()
			if err == nil {
				group.GUID = &guid
			} else {
				decoder.InternalErrors = append(decoder.InternalErrors, err)
			}
		case "objectSid":
			sid, err := value.SID()
			if err == nil {
				group.SID = &sid
			} else {
				decoder.InternalErrors = append(decoder.InternalErrors, err)
			}
		case "groupType":
			flags, err := value.Flags32()
			if err != nil {
				decoder.InternalErrors = append(decoder.InternalErrors, err)
				continue
			}
			category, scope := GroupDistribution, GroupScopeUnknown
			if flags.Has(InternalGroupSecurityBit) {
				category = GroupSecurity
			}
			switch flags & InternalGroupScopeBits {
			case 2:
				scope = GroupGlobal
			case 4:
				scope = GroupDomainLocal
			case 8:
				scope = GroupUniversal
			}
			builtin := flags.Has(InternalGroupBuiltinBit)
			if builtin {
				scope = GroupDomainLocal
			}
			group.Type, group.Category, group.Scope, group.Builtin = &flags, &category, &scope, &builtin
		}
	}
	return group, errors.Join(decoder.InternalErrors...)
}

func InternalGroupFlags(category GroupCategory, scope GroupScope) (Flags32, error) {
	if category != GroupSecurity && category != GroupDistribution {
		return 0, ErrInvalidGroup
	}
	var flags Flags32
	switch scope {
	case GroupGlobal:
		flags = 2
	case GroupDomainLocal:
		flags = 4
	case GroupUniversal:
		flags = 8
	default:
		return 0, ErrInvalidGroup
	}
	return flags.With(InternalGroupSecurityBit, category == GroupSecurity), nil
}

func InternalGroupTextFields(sam, description, display, home, managedBy *string) []AttributeChange {
	fields := []struct {
		InternalAttribute string
		InternalValue     *string
	}{
		{"sAMAccountName", sam},
		{"description", description},
		{"displayName", display},
		{"wWWHomePage", home},
		{"managedBy", managedBy},
	}
	var changes []AttributeChange
	for _, field := range fields {
		if field.InternalValue != nil {
			changes = append(
				changes,
				AttributeChange{
					Attribute: field.InternalAttribute,
					Kind:      AttributeSet,
					Values:    []RawValue{NewRawValue([]byte(*field.InternalValue))},
				},
			)
		}
	}
	return changes
}

func InternalValidateGroupText(changes []AttributeChange) error {
	for _, change := range changes {
		value, err := change.Values[0].Text()
		if err != nil {
			return errors.Join(ErrInvalidGroup, err)
		}
		if change.Attribute == "managedBy" {
			if _, err := IdentityByDN(value); err != nil {
				return errors.Join(ErrInvalidGroup, err)
			}
		}
	}
	return nil
}

func InternalGroupMutationResult(
	mutation ObjectMutationResult,
	err error,
) (GroupMutationResult, error) {
	result := GroupMutationResult{Mutation: mutation}
	if mutation.After != nil {
		group, decodeErr := InternalDecodeGroup(*mutation.After)
		result.Group = &group
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func InternalValidateGroupMutation(identity Identity, options ObjectMutationOptions) error {
	if err := InternalValidateIdentityOperation(
		identity,
		InternalGroupIdentityOptions(identity, options.Partition, options.Properties),
	); err != nil {
		return err
	}
	for _, name := range options.Properties {
		if name == "1.1" {
			return ErrInvalidProperty
		}
	}
	return nil
}
