package activedirectory

import (
	"context"
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
	groupBuiltinBit  Flags32 = 1
	groupScopeBits   Flags32 = 2 | 4 | 8
	groupSecurityBit Flags32 = 0x80000000
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

// CreateGroupRequest requires an explicit parent, category and scope. The
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

func groupProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectClass", "objectGUID", "objectSid", "groupType", "name", "sAMAccountName", "description", "displayName", "wWWHomePage", "managedBy")
}

func groupIdentityOptions(identity Identity, partition string, properties []string) ResolveIdentityOptions {
	target := IdentityTargetObject
	if identity.Form() == IdentityFormSID || identity.Form() == IdentityFormAccountName {
		target = IdentityTargetAccount
	}
	return ResolveIdentityOptions{Target: target, Partition: partition, Properties: groupProperties(properties)}
}

func groupClass(object Object) error {
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

func decodeGroup(object Object) (Group, error) {
	group := Group{DistinguishedName: object.DistinguishedName, Raw: object}
	if err := groupClass(object); err != nil {
		return group, err
	}
	decoder := rootDSEDecoder{attributes: object.Attributes}
	for attribute, field := range map[string]**string{
		"name": &group.Name, "sAMAccountName": &group.SAMAccountName,
		"description": &group.Description, "displayName": &group.DisplayName,
		"wWWHomePage": &group.HomePage, "managedBy": &group.ManagedByDN,
	} {
		*field = decoder.text(attribute)
	}
	for _, attribute := range []string{"objectGUID", "objectSid", "groupType"} {
		values := object.Values(attribute)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			decoder.errors = append(decoder.errors, err)
			continue
		}
		switch attribute {
		case "objectGUID":
			guid, err := value.GUID()
			if err == nil {
				group.GUID = &guid
			} else {
				decoder.errors = append(decoder.errors, err)
			}
		case "objectSid":
			sid, err := value.SID()
			if err == nil {
				group.SID = &sid
			} else {
				decoder.errors = append(decoder.errors, err)
			}
		case "groupType":
			flags, err := value.Flags32()
			if err != nil {
				decoder.errors = append(decoder.errors, err)
				continue
			}
			category, scope := GroupDistribution, GroupScopeUnknown
			if flags.Has(groupSecurityBit) {
				category = GroupSecurity
			}
			switch flags & groupScopeBits {
			case 2:
				scope = GroupGlobal
			case 4:
				scope = GroupDomainLocal
			case 8:
				scope = GroupUniversal
			}
			builtin := flags.Has(groupBuiltinBit)
			if builtin {
				scope = GroupDomainLocal
			}
			group.Type, group.Category, group.Scope, group.Builtin = &flags, &category, &scope, &builtin
		}
	}
	return group, errors.Join(decoder.errors...)
}

// Group supports explicit DN/GUID identities in AD DS and AD LDS. AD DS also
// supports SID and literal unqualified SAM account names. The resolved object's
// class is checked, including when its identity matches another account type.
func (c *Client) Group(ctx context.Context, identity Identity, options ResolveIdentityOptions) (GroupResult, error) {
	if options.Target > IdentityTargetAccount {
		return GroupResult{}, ErrInvalidIdentity
	}
	options = groupIdentityOptions(identity, options.Partition, options.Properties)
	observation, err := c.ResolveIdentity(ctx, identity, options)
	result := GroupResult{Observation: observation}
	if observation.Object != nil {
		group, decodeErr := decodeGroup(*observation.Object)
		result.Group = &group
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// Groups intersects the caller's typed or raw LDAP filter with the group class.
// Empty Base uses Config.Partition or the server's default naming context.
// Scope, paging and caller limits retain SearchOptions semantics. Partial raw
// results and decode failures are returned; group membership is not expanded.
func (c *Client) Groups(ctx context.Context, options SearchOptions) (GroupsResult, error) {
	var result GroupsResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	options.Properties = groupProperties(options.Properties)
	class := FilterEqual("objectClass", FilterText("group"))
	if !options.TypedFilter.unset() {
		options.TypedFilter = FilterAnd(class, options.TypedFilter)
	} else if options.Filter != "" {
		options.Filter = "(&(objectClass=group)" + options.Filter + ")"
	} else {
		options.TypedFilter = class
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == DirectoryUnknown {
			return ErrUnsupported
		}
		if options.Base == "" {
			options.Base = c.config.Partition
			if options.Base == "" && root.DefaultNamingContext != nil {
				options.Base = *root.DefaultNamingContext
			}
			if options.Base == "" {
				return ErrNoDefaultPartition
			}
		}
		identity, err := IdentityByDN(options.Base)
		if err != nil {
			return err
		}
		if _, _, err := identityPartition(identity, c.config.Partition, root); err != nil {
			return err
		}
		result.Observation, err = searchIdentitySession(ctx, c.session, options)
		for _, object := range result.Observation.Objects {
			group, decodeErr := decodeGroup(object)
			result.Groups = append(result.Groups, group)
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

func groupFlags(category GroupCategory, scope GroupScope) (Flags32, error) {
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
	return flags.With(groupSecurityBit, category == GroupSecurity), nil
}

func groupTextFields(sam, description, display, home, managedBy *string) []AttributeChange {
	fields := []struct {
		attribute string
		value     *string
	}{
		{"sAMAccountName", sam}, {"description", description}, {"displayName", display},
		{"wWWHomePage", home}, {"managedBy", managedBy},
	}
	var changes []AttributeChange
	for _, field := range fields {
		if field.value != nil {
			changes = append(changes, AttributeChange{Attribute: field.attribute, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*field.value))}})
		}
	}
	return changes
}

func validateGroupText(changes []AttributeChange) error {
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

func groupMutationResult(mutation ObjectMutationResult, err error) (GroupMutationResult, error) {
	result := GroupMutationResult{Mutation: mutation}
	if mutation.After != nil {
		group, decodeErr := decodeGroup(*mutation.After)
		result.Group = &group
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func (c *Client) CreateGroup(ctx context.Context, request CreateGroupRequest) (GroupMutationResult, error) {
	flags, err := groupFlags(request.Category, request.Scope)
	if err != nil {
		return GroupMutationResult{}, err
	}
	fields := groupTextFields(request.SAMAccountName, request.Description, request.DisplayName, request.HomePage, request.ManagedByDN)
	if err := validateGroupText(fields); err != nil {
		return GroupMutationResult{}, err
	}
	attributes := make(map[string][]RawValue, len(request.Attributes)+len(fields)+1)
	for name, values := range request.Attributes {
		key := strings.ToLower(name)
		if key == "grouptype" {
			return GroupMutationResult{}, ErrInvalidGroup
		}
		if _, exists := attributes[key]; exists {
			return GroupMutationResult{}, ErrInvalidGroup
		}
		attributes[key] = values
	}
	for _, field := range fields {
		key := strings.ToLower(field.Attribute)
		if _, exists := attributes[key]; exists {
			return GroupMutationResult{}, ErrInvalidGroup
		}
		attributes[key] = field.Values
	}
	attributes["groupType"] = []RawValue{NewRawValue([]byte(flags.LDAPString()))}
	request.Options.Properties = groupProperties(request.Options.Properties)
	return groupMutationResult(c.CreateObject(ctx, CreateObjectRequest{Parent: request.Parent, Class: "group", Name: request.Name, Attributes: attributes, Options: request.Options}))
}

func validateGroupMutation(identity Identity, options ObjectMutationOptions) error {
	if err := validateIdentityOperation(identity, groupIdentityOptions(identity, options.Partition, options.Properties)); err != nil {
		return err
	}
	for _, name := range options.Properties {
		if name == "1.1" {
			return ErrInvalidProperty
		}
	}
	return nil
}

// UpdateGroup submits one Modify. Scope/category changes delete the exact old
// groupType value then add its replacement in that same request, retaining
// unrelated bits and rejecting a concurrently changed value. Server scope and
// membership constraints are authoritative; no intermediate conversion occurs.
func (c *Client) UpdateGroup(ctx context.Context, request UpdateGroupRequest) (GroupMutationResult, error) {
	if err := validateGroupMutation(request.Identity, request.Options); err != nil {
		return GroupMutationResult{}, err
	}
	if request.Category != nil && *request.Category != GroupSecurity && *request.Category != GroupDistribution {
		return GroupMutationResult{}, ErrInvalidGroup
	}
	if request.Scope != nil && (*request.Scope < GroupGlobal || *request.Scope > GroupUniversal) {
		return GroupMutationResult{}, ErrInvalidGroup
	}
	fields := groupTextFields(request.SAMAccountName, request.Description, request.DisplayName, request.HomePage, request.ManagedByDN)
	if err := validateGroupText(fields); err != nil {
		return GroupMutationResult{}, err
	}
	for _, change := range request.Changes {
		if strings.EqualFold(change.Attribute, "groupType") {
			return GroupMutationResult{}, ErrInvalidGroup
		}
	}
	changes := append(slices.Clone(request.Changes), fields...)
	var mods []ldapAttributeModification
	if len(changes) != 0 {
		var err error
		mods, err = objectChanges(changes)
		if err != nil {
			return GroupMutationResult{}, err
		}
	} else if request.Category == nil && request.Scope == nil {
		return GroupMutationResult{}, ErrInvalidGroup
	}
	request.Options.Properties = groupProperties(request.Options.Properties)
	mutation, err := c.objectMutationIdentity(ctx, request.Identity, request.Options, groupIdentityOptions(request.Identity, request.Options.Partition, request.Options.Properties), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := groupClass(*observed.Object); err != nil {
			return err
		}
		writes := slices.Clone(mods)
		verification := slices.Clone(mods)
		if request.Category != nil || request.Scope != nil {
			value, err := observed.Object.Values("groupType").Single()
			if err != nil {
				return err
			}
			flags, err := value.Flags32()
			if err != nil {
				return err
			}
			next := flags
			if request.Category != nil {
				next = next.With(groupSecurityBit, *request.Category == GroupSecurity)
			}
			if request.Scope != nil {
				scope, _ := groupFlags(GroupDistribution, *request.Scope)
				next = (next &^ groupScopeBits) | scope
			}
			if next != flags {
				writes = append(writes, ldapAttributeModification{operation: 1, attribute: "groupType", values: [][]byte{value.Bytes()}}, ldapAttributeModification{operation: 0, attribute: "groupType", values: [][]byte{[]byte(next.LDAPString())}})
			}
			verification = append(verification, ldapAttributeModification{operation: 2, attribute: "groupType", values: [][]byte{[]byte(next.LDAPString())}})
		}
		if len(writes) == 0 {
			// No server operation would enforce this precondition.
			if request.Options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			result.After, result.ReadbackComplete = observed.Object, observed.Complete
			return verifyObjectWrite(result, verification, "")
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: writes, controls: controls}, false, result); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(request.Options, writes), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, verification, "")
	})
	return groupMutationResult(mutation, err)
}

func (c *Client) DeleteGroup(ctx context.Context, request DeleteGroupRequest) (GroupMutationResult, error) {
	if err := validateGroupMutation(request.Identity, request.Options); err != nil {
		return GroupMutationResult{}, err
	}
	mutation, err := c.objectMutationIdentity(ctx, request.Identity, request.Options, groupIdentityOptions(request.Identity, request.Options.Partition, nil), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := groupClass(*observed.Object); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}, false, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
	return groupMutationResult(mutation, err)
}
