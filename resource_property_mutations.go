package activedirectory

import (
	"context"
	"errors"
	"strings"
)

// Resource property writes mirror the claim-type machinery: the value type is
// settled from the referenced value-type object rather than accepted directly,
// and suggested values are encoded for that settled type.

// CreateResourcePropertyRequest creates one resource property.
type CreateResourcePropertyRequest struct {
	// DisplayName is required. ID is the directory name; when nil the display
	// name is used, matching the reference's own default.
	DisplayName string
	ID          *string
	Description *string
	// ValueType references an msDS-ValueType object by identity or by its
	// lDAPDisplayName-equivalent name. It settles the property's value type.
	ValueType SchemaReference
	// SharesValuesWith optionally references a claim type whose possible
	// values this property shares.
	SharesValuesWith                *Identity
	AppliesToResourceTypes          []string
	Enabled, IsSecured              *bool
	RestrictValues                  *bool
	SuggestedValues                 []ClaimSuggestedValue
	ProtectedFromAccidentalDeletion *bool
	Attributes                      map[string][]RawValue
	Options                         ObjectMutationOptions
}

// UpdateResourcePropertyRequest changes one resource property.
type UpdateResourcePropertyRequest struct {
	Identity                 Identity
	DisplayName, Description *string
	ClearDescription         bool
	// SharesValuesWith re-points the shared claim type; ClearSharesValuesWith
	// removes the reference. They conflict.
	SharesValuesWith      *Identity
	ClearSharesValuesWith bool
	// AppliesToResourceTypes replaces the stored list when Replace is set,
	// otherwise adds. Clear removes the attribute.
	AppliesToResourceTypes          []string
	ReplaceAppliesToResourceTypes   bool
	ClearAppliesToResourceTypes     bool
	Enabled, IsSecured              *bool
	RestrictValues                  *bool
	SuggestedValues                 []ClaimSuggestedValue
	ClearSuggestedValues            bool
	ProtectedFromAccidentalDeletion *bool
	Changes                         []AttributeChange
	Options                         ObjectMutationOptions
}

// CreateResourcePropertyListRequest creates one property list.
type CreateResourcePropertyListRequest struct {
	Name                            string
	Description                     *string
	ProtectedFromAccidentalDeletion *bool
	Options                         ObjectMutationOptions
}

// UpdateResourcePropertyListRequest changes one property list.
type UpdateResourcePropertyListRequest struct {
	Identity                        Identity
	Description                     *string
	ClearDescription                bool
	ProtectedFromAccidentalDeletion *bool
	Changes                         []AttributeChange
	Options                         ObjectMutationOptions
}

// ResourcePropertyListMembersRequest adds or removes list members. Members are
// resource properties; each is resolved and verified before any write.
type ResourcePropertyListMembersRequest struct {
	Identity   Identity
	Members    []Identity
	References CentralAccessReferenceLimits
	Options    ObjectMutationOptions
}

type ResourcePropertyMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	Property   *ResourceProperty
	// ValueTypeObservation is the value-type object the property was pointed
	// at, retained even when the write was rejected.
	ValueTypeObservation *ResourceValueTypeResult
	GeneratedID          *string
}

type ResourcePropertyListMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	List       *ResourcePropertyList
}

// ResourcePropertyList is one msDS-ResourcePropertyList.
type ResourcePropertyList struct {
	Raw                             Object
	GUID                            *GUID
	ID, DisplayName, Description    *string
	ProtectedFromAccidentalDeletion *bool
}

type ResourcePropertyListResult struct {
	List        *ResourcePropertyList
	Observation IdentityResult
	Members     CentralAccessReferencesResult
	Protection  OUProtectionResult
}

type ResourcePropertyListsResult struct {
	Lists       []ResourcePropertyListResult
	Observation SearchResult
}

type ResourcePropertyListMembersResult struct {
	Mutation ObjectMutationResult
	Before   CentralAccessReferencesResult
	After    CentralAccessReferencesResult
	Inputs   []CentralAccessMemberInput
}

func decodeResourcePropertyList(object Object) (result ResourcePropertyList, err error) {
	result.Raw = object
	d := rootDSEDecoder{attributes: object.Attributes}
	result.ID = d.text("name")
	result.DisplayName = d.text("displayName")
	result.Description = d.text("description")
	guid, guidErr := centralAccessGUID(object)
	if guidErr == nil {
		result.GUID = &guid
	}
	return result, errors.Join(guidErr, errors.Join(d.errors...), centralAccessClassCheck(object, resourcePropertyListClass))
}

// resourceManaged attributes are written only from typed fields.
var resourceManaged = []string{
	"cn", "name", resourceValueTypeReference, resourceSharesValuesWith, resourceAppliesTo,
	resourceIsSecured, resourceListMembers, claimPossible, claimRestricted, claimValueType,
	"nTSecurityDescriptor",
}

func resourceRawChanges(changes []AttributeChange) error {
	for _, change := range changes {
		for _, managed := range resourceManaged {
			if strings.EqualFold(change.Attribute, managed) {
				return ErrResourceProperty
			}
		}
	}
	return nil
}

func resourceRawAttributes(attributes map[string][]RawValue) error {
	for name := range attributes {
		for _, managed := range resourceManaged {
			if strings.EqualFold(name, managed) {
				return ErrResourceProperty
			}
		}
	}
	return nil
}

func resourceProject(result ResourcePropertyMutationResult, err error) (ResourcePropertyMutationResult, error) {
	if result.Mutation.After != nil {
		value, decodeErr := decodeResourceProperty(*result.Mutation.After)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Property = &value
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func resourceListProject(result ResourcePropertyListMutationResult, err error) (ResourcePropertyListMutationResult, error) {
	if result.Mutation.After != nil {
		value, decodeErr := decodeResourcePropertyList(*result.Mutation.After)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.List = &value
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// resolveResourceValueType selects the value-type object a property points at.
// Only an identity or an explicit name is accepted; the SDK never guesses a
// value type from the property's own name.
func (c *Client) resolveResourceValueType(ctx context.Context, root RootDSE, configuration string, reference SchemaReference) (*ResourceValueTypeResult, error) {
	if claimSchemaReferenceEmpty(reference) {
		return nil, errors.Join(ErrResourceProperty, ErrInvalidIdentity)
	}
	if reference.LDAPDisplayName != "" && reference.Identity.Form() != 0 {
		return nil, errors.Join(ErrResourceProperty, ErrInvalidIdentity)
	}
	if reference.Identity.Form() != 0 {
		return c.readResourceValueTypeSession(ctx, root, configuration, reference.Identity.String())
	}
	if !validDirectoryText(reference.LDAPDisplayName) {
		return nil, errors.Join(ErrResourceProperty, ErrInvalidIdentity)
	}
	observed, err := searchIdentitySession(ctx, c.session, SearchOptions{
		Base:        resourceValueTypeParent(configuration),
		Scope:       ScopeOneLevel,
		Filter:      "(&(objectClass=" + resourceValueTypeClass + ")(name=" + ldapLiteral(reference.LDAPDisplayName) + "))",
		Properties:  resourceValueTypeProperties(nil),
		PageSize:    2,
		ResultLimit: 2,
	})
	result := &ResourceValueTypeResult{Observation: IdentityResult{Candidates: observed.Objects, Complete: observed.Complete}}
	switch {
	case err != nil:
		return result, err
	case len(observed.Objects) > 1:
		return result, ErrAmbiguousIdentity
	case !observed.Complete:
		return result, ErrIncompleteResult
	case len(observed.Objects) == 0:
		return result, ErrDirectoryObjectNotFound
	}
	object := observed.Objects[0]
	result.Observation.Object = &object
	value, decodeErr := decodeResourceValueType(object)
	result.ValueType = &value
	return result, decodeErr
}

// CreateResourceProperty creates one resource property. The value type is
// resolved first, so an unusable reference fails before anything is written.
func (c *Client) CreateResourceProperty(ctx context.Context, request CreateResourcePropertyRequest) (ResourcePropertyMutationResult, error) {
	var result ResourcePropertyMutationResult
	if request.DisplayName == "" || !validDirectoryText(request.DisplayName) {
		return result, ErrInvalidObjectMutation
	}
	if request.Description != nil && !validDirectoryText(*request.Description) {
		return result, ErrInvalidObjectMutation
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if err := resourceRawAttributes(request.Attributes); err != nil {
		return result, err
	}
	if err := resourceAppliesToValid(request.AppliesToResourceTypes); err != nil {
		return result, err
	}
	name := request.DisplayName
	if request.ID != nil {
		if *request.ID == "" || !validDirectoryText(*request.ID) {
			return result, ErrInvalidObjectMutation
		}
		name = *request.ID
	} else {
		generated := name
		result.GeneratedID = &generated
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()

	var settled ClaimValueType
	var sharedDN string
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		if e := centralAccessProtectionCapability(c.session, root, request.ProtectedFromAccidentalDeletion); e != nil {
			return e
		}
		observation, e := c.resolveResourceValueType(ctx, root, options.Partition, request.ValueType)
		result.ValueTypeObservation = observation
		if e != nil {
			return e
		}
		if observation.ValueType == nil || observation.ValueType.ValueType == nil {
			return errors.Join(ErrResourceProperty, ErrAttributeUnavailable)
		}
		settled = *observation.ValueType.ValueType
		if request.SharesValuesWith != nil {
			// The shared reference must be a claim type in its own container,
			// so a property can never share values with an arbitrary object.
			shared, e := resolveIdentitySession(ctx, c.session, c.config, root, *request.SharesValuesWith, ResolveIdentityOptions{Partition: options.Partition, Properties: claimProperties(nil)})
			if e != nil {
				return e
			}
			if e := claimLocation(*shared.Object, options.Partition); e != nil {
				return e
			}
			sharedDN = shared.Object.DistinguishedName
		}
		return nil
	})
	if err != nil {
		return result, err
	}

	attributes := map[string][]RawValue{}
	for attribute, values := range request.Attributes {
		attributes[attribute] = values
	}
	attributes["displayName"] = []RawValue{NewRawValue([]byte(request.DisplayName))}
	attributes[resourceValueTypeReference] = []RawValue{NewRawValue([]byte(result.ValueTypeObservation.Observation.Object.DistinguishedName))}
	if request.Description != nil {
		attributes["description"] = []RawValue{NewRawValue([]byte(*request.Description))}
	}
	if sharedDN != "" {
		attributes[resourceSharesValuesWith] = []RawValue{NewRawValue([]byte(sharedDN))}
	}
	for _, flag := range []struct {
		attribute string
		value     *bool
	}{
		{"enabled", request.Enabled},
		{resourceIsSecured, request.IsSecured},
		{claimRestricted, request.RestrictValues},
	} {
		if flag.value != nil {
			attributes[flag.attribute] = []RawValue{claimBoolValue(*flag.value)}
		}
	}
	suggested, err := claimSuggestedValueAttribute(request.SuggestedValues, settled)
	if err != nil {
		return result, err
	}
	if suggested != nil {
		attributes[claimPossible] = suggested
	}
	if len(request.AppliesToResourceTypes) != 0 {
		values := make([]RawValue, 0, len(request.AppliesToResourceTypes))
		for _, kind := range request.AppliesToResourceTypes {
			values = append(values, NewRawValue([]byte(kind)))
		}
		attributes[resourceAppliesTo] = values
	}

	parent, _ := IdentityByDN(resourcePropertyParent(options.Partition))
	options.Properties = resourcePropertyProperties(options.Properties)
	result.Mutation, err = c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: resourcePropertyClass, Name: name, Attributes: attributes, Options: options})
	if err != nil {
		return resourceProject(result, err)
	}
	if request.ProtectedFromAccidentalDeletion != nil {
		protection, protectErr := c.setCentralAccessProtection(ctx, objectGUIDIdentity(*result.Mutation.TargetGUID), *request.ProtectedFromAccidentalDeletion, ObjectMutationOptions{Partition: options.Partition}, false)
		result.Protection = protection
		err = protectErr
	}
	return resourceProject(result, err)
}

func resourcePropertyUpdateChanges(request UpdateResourcePropertyRequest) ([]AttributeChange, error) {
	if request.Description != nil && request.ClearDescription {
		return nil, ErrResourceProperty
	}
	if request.SharesValuesWith != nil && request.ClearSharesValuesWith {
		return nil, ErrResourceProperty
	}
	if len(request.SuggestedValues) != 0 && request.ClearSuggestedValues {
		return nil, ErrResourceProperty
	}
	if len(request.AppliesToResourceTypes) != 0 && request.ClearAppliesToResourceTypes {
		return nil, ErrResourceProperty
	}
	if request.ReplaceAppliesToResourceTypes && request.ClearAppliesToResourceTypes {
		return nil, ErrResourceProperty
	}
	if err := resourceRawChanges(request.Changes); err != nil {
		return nil, err
	}
	if err := resourceAppliesToValid(request.AppliesToResourceTypes); err != nil {
		return nil, err
	}
	var changes []AttributeChange
	if request.DisplayName != nil {
		if *request.DisplayName == "" || !validDirectoryText(*request.DisplayName) {
			return nil, ErrInvalidObjectMutation
		}
		changes = append(changes, AttributeChange{Attribute: "displayName", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*request.DisplayName))}})
	}
	if request.Description != nil {
		if !validDirectoryText(*request.Description) {
			return nil, ErrInvalidObjectMutation
		}
		changes = append(changes, AttributeChange{Attribute: "description", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*request.Description))}})
	}
	if request.ClearDescription {
		changes = append(changes, AttributeChange{Attribute: "description", Kind: AttributeClear})
	}
	for _, flag := range []struct {
		attribute string
		value     *bool
	}{
		{"enabled", request.Enabled},
		{resourceIsSecured, request.IsSecured},
		{claimRestricted, request.RestrictValues},
	} {
		if flag.value != nil {
			changes = append(changes, AttributeChange{Attribute: flag.attribute, Kind: AttributeSet, Values: []RawValue{claimBoolValue(*flag.value)}})
		}
	}
	if request.ClearSharesValuesWith {
		changes = append(changes, AttributeChange{Attribute: resourceSharesValuesWith, Kind: AttributeClear})
	}
	if request.ClearSuggestedValues {
		changes = append(changes, AttributeChange{Attribute: claimPossible, Kind: AttributeClear})
	}
	if request.ClearAppliesToResourceTypes {
		changes = append(changes, AttributeChange{Attribute: resourceAppliesTo, Kind: AttributeClear})
	}
	if len(request.AppliesToResourceTypes) != 0 {
		values := make([]RawValue, 0, len(request.AppliesToResourceTypes))
		for _, kind := range request.AppliesToResourceTypes {
			values = append(values, NewRawValue([]byte(kind)))
		}
		kind := AttributeAddValues
		if request.ReplaceAppliesToResourceTypes {
			kind = AttributeSet
		}
		changes = append(changes, AttributeChange{Attribute: resourceAppliesTo, Kind: kind, Values: values})
	}
	return append(changes, request.Changes...), nil
}

// UpdateResourceProperty changes one resource property in a single modify. The
// value type is never changed: the reference exposes no parameter for it, so a
// property keeps the value type it was created with.
func (c *Client) UpdateResourceProperty(ctx context.Context, request UpdateResourcePropertyRequest) (ResourcePropertyMutationResult, error) {
	var result ResourcePropertyMutationResult
	changes, err := resourcePropertyUpdateChanges(request)
	if err != nil {
		return result, err
	}
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: resourcePropertyProperties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := resourceLocation(*observed.Object, options.Partition, resourcePropertyClass); err != nil {
			return err
		}
		if err := centralAccessProtectionCapability(session, root, request.ProtectedFromAccidentalDeletion); err != nil {
			return err
		}
		applied := changes
		current, decodeErr := decodeResourceProperty(*observed.Object)
		if decodeErr != nil {
			return decodeErr
		}
		if request.SharesValuesWith != nil {
			shared, err := resolveIdentitySession(ctx, session, c.config, root, *request.SharesValuesWith, ResolveIdentityOptions{Partition: options.Partition, Properties: claimProperties(nil)})
			if err != nil {
				return err
			}
			if err := claimLocation(*shared.Object, options.Partition); err != nil {
				return err
			}
			applied = append(applied, AttributeChange{Attribute: resourceSharesValuesWith, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(shared.Object.DistinguishedName))}})
		}
		if len(request.SuggestedValues) != 0 {
			// Suggested values are encoded for the value type the property
			// already stores; it is not re-derived or changed here.
			if current.ValueType == nil {
				return errors.Join(ErrResourceProperty, ErrAttributeUnavailable)
			}
			suggested, err := claimSuggestedValueAttribute(request.SuggestedValues, *current.ValueType)
			if err != nil {
				return err
			}
			applied = append(applied, AttributeChange{Attribute: claimPossible, Kind: AttributeSet, Values: suggested})
		}
		return c.submitResourceWrite(ctx, session, root, options, applied, request.ProtectedFromAccidentalDeletion, mutation, &result.Protection, resourcePropertyProperties)
	})
	return resourceProject(result, err)
}

func (c *Client) submitResourceWrite(ctx context.Context, session ldapWriteSession, root RootDSE, options ObjectMutationOptions, changes []AttributeChange, protect *bool, mutation *ObjectMutationResult, protection *OUProtectionResult, properties func([]string) []string) error {
	mods, err := objectChanges(changes)
	if err != nil {
		return err
	}
	if len(mods) == 0 {
		if options.ExpectedVersion != nil && protect == nil {
			return ErrObjectControlUnsupported
		}
		mutation.After = mutation.Before
		mutation.ReadbackComplete = true
		mutation.Verified = true
	} else {
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); err != nil {
			return err
		}
		readOptions := options
		readOptions.Properties = properties(options.Properties)
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, objectWriteProperties(readOptions, mods), false); err != nil {
			return err
		}
		if err := verifyObjectWrite(mutation, mods, ""); err != nil {
			return err
		}
	}
	if protect != nil {
		protection.Object = *mutation
		return changeOUProtection(ctx, session, root, c.config, mutation, *protect, options, protection)
	}
	return nil
}

// DeleteResourceProperty removes one resource property with a single native
// leaf delete. It never removes the property from the lists that reference it;
// the directory's own referential outcome is surfaced unchanged.
func (c *Client) DeleteResourceProperty(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	return c.deleteResourceObject(ctx, identity, options, resourcePropertyClass, resourcePropertyProperties)
}

// DeleteResourcePropertyList removes one property list. It never deletes the
// properties the list referenced.
func (c *Client) DeleteResourcePropertyList(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	return c.deleteResourceObject(ctx, identity, options, resourcePropertyListClass, resourceListProperties)
}

func (c *Client) deleteResourceObject(ctx context.Context, identity Identity, options ObjectMutationOptions, class string, properties func([]string) []string) (ObjectMutationResult, error) {
	if err := validateObjectOptions(identity, options); err != nil {
		return ObjectMutationResult{}, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, options)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	defer cancel()
	return c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{Properties: properties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := resourceLocation(*observed.Object, options.Partition, class); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}, false, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
}

// CreateResourcePropertyList creates one property list.
func (c *Client) CreateResourcePropertyList(ctx context.Context, request CreateResourcePropertyListRequest) (ResourcePropertyListMutationResult, error) {
	var result ResourcePropertyListMutationResult
	if err := centralAccessCreateInput(request.Name, request.Description, request.Options); err != nil {
		return result, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		return centralAccessProtectionCapability(c.session, root, request.ProtectedFromAccidentalDeletion)
	})
	if err != nil {
		return result, err
	}
	attributes := map[string][]RawValue{}
	if request.Description != nil {
		attributes["description"] = []RawValue{NewRawValue([]byte(*request.Description))}
	}
	parent, _ := IdentityByDN(resourcePropertyListParent(options.Partition))
	options.Properties = resourceListProperties(options.Properties)
	result.Mutation, err = c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: resourcePropertyListClass, Name: request.Name, Attributes: attributes, Options: options})
	if err != nil {
		return resourceListProject(result, err)
	}
	if request.ProtectedFromAccidentalDeletion != nil {
		protection, protectErr := c.setCentralAccessProtection(ctx, objectGUIDIdentity(*result.Mutation.TargetGUID), *request.ProtectedFromAccidentalDeletion, ObjectMutationOptions{Partition: options.Partition}, false)
		result.Protection = protection
		err = protectErr
	}
	return resourceListProject(result, err)
}

// UpdateResourcePropertyList changes one property list. Membership is edited
// with AddResourcePropertyListMembers and RemoveResourcePropertyListMembers,
// not through this call.
func (c *Client) UpdateResourcePropertyList(ctx context.Context, request UpdateResourcePropertyListRequest) (ResourcePropertyListMutationResult, error) {
	var result ResourcePropertyListMutationResult
	if request.Description != nil && request.ClearDescription {
		return result, ErrResourceProperty
	}
	if err := resourceRawChanges(request.Changes); err != nil {
		return result, err
	}
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	var changes []AttributeChange
	if request.Description != nil {
		if !validDirectoryText(*request.Description) {
			return result, ErrInvalidObjectMutation
		}
		changes = append(changes, AttributeChange{Attribute: "description", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*request.Description))}})
	}
	if request.ClearDescription {
		changes = append(changes, AttributeChange{Attribute: "description", Kind: AttributeClear})
	}
	changes = append(changes, request.Changes...)
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: resourceListProperties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := resourceLocation(*observed.Object, options.Partition, resourcePropertyListClass); err != nil {
			return err
		}
		if err := centralAccessProtectionCapability(session, root, request.ProtectedFromAccidentalDeletion); err != nil {
			return err
		}
		return c.submitResourceWrite(ctx, session, root, options, changes, request.ProtectedFromAccidentalDeletion, mutation, &result.Protection, resourceListProperties)
	})
	return resourceListProject(result, err)
}

// AddResourcePropertyListMembers adds resource properties to one list.
func (c *Client) AddResourcePropertyListMembers(ctx context.Context, request ResourcePropertyListMembersRequest) (ResourcePropertyListMembersResult, error) {
	return c.changeResourceListMembers(ctx, request, false)
}

// RemoveResourcePropertyListMembers removes resource properties from one list.
// It never deletes the properties themselves.
func (c *Client) RemoveResourcePropertyListMembers(ctx context.Context, request ResourcePropertyListMembersRequest) (ResourcePropertyListMembersResult, error) {
	return c.changeResourceListMembers(ctx, request, true)
}

func (c *Client) changeResourceListMembers(ctx context.Context, request ResourcePropertyListMembersRequest, remove bool) (ResourcePropertyListMembersResult, error) {
	var result ResourcePropertyListMembersResult
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if len(request.Members) == 0 || len(request.Members) > ResourcePropertyListMemberLimit {
		return result, ErrResourcePropertyMember
	}
	limits, err := normalizeCentralAccessLimits(request.References)
	if err != nil {
		return result, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: resourceListProperties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := resourceLocation(*observed.Object, options.Partition, resourcePropertyListClass); err != nil {
			return err
		}
		before, err := readCentralAccessReferences(ctx, session, *observed.Object, resourceListMembers, limits)
		result.Before = before
		if err != nil {
			return err
		}
		if !remove && len(before.References)+len(request.Members) > ResourcePropertyListMemberLimit {
			return ErrResourcePropertyMember
		}
		values := make([][]byte, 0, len(request.Members))
		seen := map[string]struct{}{}
		for _, identity := range request.Members {
			// Every member must be a resource property in its own container,
			// so a list can never reference an arbitrary object.
			input, err := resolveIdentitySession(ctx, session, c.config, root, identity, ResolveIdentityOptions{Partition: options.Partition, Properties: resourcePropertyProperties(nil)})
			result.Inputs = append(result.Inputs, CentralAccessMemberInput{Identity: identity, Observation: input})
			if err != nil {
				return err
			}
			if err := resourceLocation(*input.Object, options.Partition, resourcePropertyClass); err != nil {
				return err
			}
			parsed, err := parseIdentityDN(input.Object.DistinguishedName)
			if err != nil {
				return err
			}
			key := identityDNKey(parsed)
			if _, duplicate := seen[key]; duplicate {
				return ErrResourcePropertyMember
			}
			seen[key] = struct{}{}
			values = append(values, []byte(input.Object.DistinguishedName))
		}
		operation := uint32(0)
		if remove {
			operation = 1
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: []ldapAttributeModification{{operation: operation, attribute: resourceListMembers, values: values}}, controls: controls}, false, mutation); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, resourceListProperties(options.Properties), false); err != nil {
			return err
		}
		after, err := readCentralAccessReferences(ctx, session, *mutation.After, resourceListMembers, limits)
		result.After = after
		if err != nil {
			return errors.Join(ErrObjectReadback, err)
		}
		return nil
	})
	return result, err
}
