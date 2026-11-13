package activedirectory

import (
	"context"
	"errors"
	"strings"
)

// Claim type creation and update settle the value type from the source rather
// than accepting it directly, matching the reference parameter sets: ValueType
// is stated only for a transform-policy source, and no update can change the
// value type an existing claim already stores.

// CreateClaimTypeRequest creates one claim type under the configuration
// partition's Claim Types container.
type CreateClaimTypeRequest struct {
	// DisplayName is required. ID is the claim's directory name; when nil a
	// conforming ad://ext/ identifier is generated and reported back in the
	// result, including when the write is rejected or uncertain.
	DisplayName string
	ID          *string
	Description *string
	// Source selects exactly one of the attribute, certificate OID or
	// transform-policy forms. It settles the stored value type.
	Source                                  ClaimTypeSource
	AppliesToClasses                        []SchemaReference
	Enabled, IsSingleValued, RestrictValues *bool
	SuggestedValues                         []ClaimSuggestedValue
	ProtectedFromAccidentalDeletion         *bool
	// Attributes carries additional raw attributes. Managed claim attributes
	// are rejected rather than merged.
	Attributes map[string][]RawValue
	Options    ObjectMutationOptions
}

// UpdateClaimTypeRequest changes one claim type. Nil fields are left alone;
// the explicit Clear flags request removal and conflict with a stated value.
type UpdateClaimTypeRequest struct {
	Identity                 Identity
	DisplayName, Description *string
	ClearDescription         bool
	// Source re-points the claim. The new source must settle the same value
	// type the claim already stores; the reference module cannot change it.
	Source *ClaimTypeSource
	// AppliesToClasses replaces the stored class list when ReplaceAppliesToClasses
	// is set. Without it a non-empty list is added and ClearAppliesToClasses
	// removes the attribute.
	AppliesToClasses                        []SchemaReference
	ReplaceAppliesToClasses                 bool
	ClearAppliesToClasses                   bool
	Enabled, IsSingleValued, RestrictValues *bool
	SuggestedValues                         []ClaimSuggestedValue
	ClearSuggestedValues                    bool
	ProtectedFromAccidentalDeletion         *bool
	Changes                                 []AttributeChange
	Options                                 ObjectMutationOptions
}

// DeleteClaimTypeRequest removes one claim type.
type DeleteClaimTypeRequest struct {
	Identity Identity
	// Force deletes a claim type that resource properties still reference.
	// Without it an observed reference is reported as ErrClaimTypeReferenced
	// and no delete is submitted.
	Force      bool
	References CentralAccessReferenceLimits
	Options    ObjectMutationOptions
}

type ClaimTypeMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	Claim      *ClaimType
	// Schema retains every schema object read while settling the source and
	// applies-to classes, including objects that were then rejected.
	Schema []ClaimSchemaObservation
	// GeneratedID is retained even when the create is rejected or uncertain,
	// so a caller can find an object a retry must not duplicate.
	GeneratedID *string
}

// claimManagedAttributes are written only from typed request fields. Raw
// changes naming them are rejected so a caller cannot bypass source and value
// type validation.
var claimManagedAttributes = []string{
	"cn", "name", claimSourceAttribute, claimSourceOID, claimSourceKind,
	claimValueType, claimSingle, claimRestricted, claimPossible, claimApplies,
	claimBacklinks, "nTSecurityDescriptor",
}

func claimRawChanges(changes []AttributeChange) error {
	for _, change := range changes {
		for _, managed := range claimManagedAttributes {
			if strings.EqualFold(change.Attribute, managed) {
				return ErrClaimType
			}
		}
	}
	return nil
}

func claimRawAttributes(attributes map[string][]RawValue) error {
	for name := range attributes {
		for _, managed := range claimManagedAttributes {
			if strings.EqualFold(name, managed) {
				return ErrClaimType
			}
		}
	}
	return nil
}

func claimBoolValue(value bool) RawValue {
	return NewRawValue([]byte(strconvClaimBool(value)))
}

// claimSourceAttributes renders the stored form of a settled source.
func claimSourceAttributes(source ClaimTypeSource, resolution claimSchemaResolution) map[string][]RawValue {
	attributes := map[string][]RawValue{
		claimSourceKind: {NewRawValue([]byte(source.Type))},
		claimValueType:  {NewRawValue([]byte(claimValueTypeText(resolution.ValueType)))},
	}
	switch source.Type {
	case ClaimSourceAttribute:
		attributes[claimSourceAttribute] = []RawValue{NewRawValue([]byte(resolution.SourceAttributeDN))}
	case ClaimSourceCertificate:
		attributes[claimSourceOID] = []RawValue{NewRawValue([]byte(source.OID))}
	}
	return attributes
}

func claimClassValues(dns []string) []RawValue {
	values := make([]RawValue, 0, len(dns))
	for _, dn := range dns {
		values = append(values, NewRawValue([]byte(dn)))
	}
	return values
}

// claimSuggestedValueAttribute encodes suggested values for the settled value
// type. RestrictValues is the directory's own gate and is not inferred here.
func claimSuggestedValueAttribute(values []ClaimSuggestedValue, valueType ClaimValueType) ([]RawValue, error) {
	if len(values) == 0 {
		return nil, nil
	}
	text, err := encodeClaimValues(values, valueType)
	if err != nil {
		return nil, err
	}
	return []RawValue{NewRawValue([]byte(text))}, nil
}

// CreateClaimType creates one claim type. The source is resolved against the
// schema before anything is submitted, so an unusable source fails without a
// partially built object.
func (c *Client) CreateClaimType(ctx context.Context, request CreateClaimTypeRequest) (ClaimTypeMutationResult, error) {
	var result ClaimTypeMutationResult
	if request.DisplayName == "" || !validDirectoryText(request.DisplayName) {
		return result, ErrInvalidObjectMutation
	}
	if request.Description != nil && !validDirectoryText(*request.Description) {
		return result, ErrInvalidObjectMutation
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if err := claimRawAttributes(request.Attributes); err != nil {
		return result, err
	}
	id := ""
	if request.ID != nil {
		if err := validateClaimID(*request.ID); err != nil {
			return result, err
		}
		id = *request.ID
	} else {
		generated, err := generateClaimID(request.DisplayName)
		if err != nil {
			return result, err
		}
		id = generated
		result.GeneratedID = &generated
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()

	var resolution claimSchemaResolution
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		if e := centralAccessProtectionCapability(c.session, root, request.ProtectedFromAccidentalDeletion); e != nil {
			return e
		}
		reader := newClaimSchemaReader(ctx, c.session, c.config, root, &result.Schema)
		resolution, e = validateClaimSchema(reader, request.Source, request.AppliesToClasses, nil)
		return e
	})
	if err != nil {
		return result, err
	}

	attributes := claimSourceAttributes(request.Source, resolution)
	for name, values := range request.Attributes {
		attributes[name] = values
	}
	attributes["displayName"] = []RawValue{NewRawValue([]byte(request.DisplayName))}
	if request.Description != nil {
		attributes["description"] = []RawValue{NewRawValue([]byte(*request.Description))}
	}
	if request.Enabled != nil {
		attributes["enabled"] = []RawValue{claimBoolValue(*request.Enabled)}
	}
	if request.IsSingleValued != nil {
		attributes[claimSingle] = []RawValue{claimBoolValue(*request.IsSingleValued)}
	}
	if request.RestrictValues != nil {
		attributes[claimRestricted] = []RawValue{claimBoolValue(*request.RestrictValues)}
	}
	suggested, err := claimSuggestedValueAttribute(request.SuggestedValues, resolution.ValueType)
	if err != nil {
		return result, err
	}
	if suggested != nil {
		attributes[claimPossible] = suggested
	}
	if len(resolution.AppliesToClassDNs) != 0 {
		attributes[claimApplies] = claimClassValues(resolution.AppliesToClassDNs)
	}

	parent, _ := IdentityByDN(claimParent(options.Partition))
	options.Properties = claimProperties(options.Properties)
	result.Mutation, err = c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: claimClass, Name: id, Attributes: attributes, Options: options})
	if err != nil {
		return claimProject(result, err)
	}
	if request.ProtectedFromAccidentalDeletion != nil {
		protection, e := c.setCentralAccessProtection(ctx, objectGUIDIdentity(*result.Mutation.TargetGUID), *request.ProtectedFromAccidentalDeletion, ObjectMutationOptions{Partition: options.Partition}, false)
		result.Protection = protection
		err = e
	}
	return claimProject(result, err)
}

func claimProject(result ClaimTypeMutationResult, err error) (ClaimTypeMutationResult, error) {
	if result.Mutation.After != nil {
		value, decodeErr := decodeClaimType(*result.Mutation.After)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Claim = &value
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// claimUpdateChanges renders every typed field that does not need the schema.
func claimUpdateChanges(request UpdateClaimTypeRequest) ([]AttributeChange, error) {
	if request.Description != nil && request.ClearDescription {
		return nil, ErrClaimType
	}
	if len(request.SuggestedValues) != 0 && request.ClearSuggestedValues {
		return nil, ErrClaimType
	}
	if len(request.AppliesToClasses) != 0 && request.ClearAppliesToClasses {
		return nil, ErrClaimType
	}
	if request.ReplaceAppliesToClasses && request.ClearAppliesToClasses {
		return nil, ErrClaimType
	}
	if err := claimRawChanges(request.Changes); err != nil {
		return nil, err
	}
	var changes []AttributeChange
	if request.DisplayName != nil {
		if !validDirectoryText(*request.DisplayName) || *request.DisplayName == "" {
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
		{claimSingle, request.IsSingleValued},
		{claimRestricted, request.RestrictValues},
	} {
		if flag.value != nil {
			changes = append(changes, AttributeChange{Attribute: flag.attribute, Kind: AttributeSet, Values: []RawValue{claimBoolValue(*flag.value)}})
		}
	}
	if request.ClearSuggestedValues {
		changes = append(changes, AttributeChange{Attribute: claimPossible, Kind: AttributeClear})
	}
	if request.ClearAppliesToClasses {
		changes = append(changes, AttributeChange{Attribute: claimApplies, Kind: AttributeClear})
	}
	return append(changes, request.Changes...), nil
}

// UpdateClaimType changes one claim type in a single modify. A source change
// is resolved against the schema and must agree with the stored value type.
func (c *Client) UpdateClaimType(ctx context.Context, request UpdateClaimTypeRequest) (ClaimTypeMutationResult, error) {
	var result ClaimTypeMutationResult
	changes, err := claimUpdateChanges(request)
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

	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: claimProperties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := claimLocation(*observed.Object, options.Partition); err != nil {
			return err
		}
		if err := centralAccessProtectionCapability(session, root, request.ProtectedFromAccidentalDeletion); err != nil {
			return err
		}
		current, decodeErr := decodeClaimType(*observed.Object)
		if decodeErr != nil {
			return decodeErr
		}
		applied := changes
		if request.Source != nil || len(request.AppliesToClasses) != 0 || len(request.SuggestedValues) != 0 {
			reader := newClaimSchemaReader(ctx, session, c.config, root, &result.Schema)
			var source ClaimTypeSource
			if request.Source != nil {
				source = *request.Source
			} else {
				// Without a stated source the claim keeps its own, so the
				// applies-to classes and values are still settled against it.
				observedSource, err := claimSourceFromObject(current)
				if err != nil {
					return err
				}
				source = observedSource
			}
			resolution, err := validateClaimSchema(reader, source, request.AppliesToClasses, current.ValueType)
			if err != nil {
				return err
			}
			if request.Source != nil {
				for name, values := range claimSourceAttributes(source, resolution) {
					applied = append(applied, AttributeChange{Attribute: name, Kind: AttributeSet, Values: values})
				}
				// Re-pointing a source retires the attributes the previous
				// form owned, so a stale DN or OID never outlives it.
				for _, stale := range claimStaleSourceAttributes(source.Type) {
					applied = append(applied, AttributeChange{Attribute: stale, Kind: AttributeClear})
				}
			}
			if len(resolution.AppliesToClassDNs) != 0 {
				kind := AttributeAddValues
				if request.ReplaceAppliesToClasses {
					kind = AttributeSet
				}
				applied = append(applied, AttributeChange{Attribute: claimApplies, Kind: kind, Values: claimClassValues(resolution.AppliesToClassDNs)})
			}
			if len(request.SuggestedValues) != 0 {
				suggested, err := claimSuggestedValueAttribute(request.SuggestedValues, resolution.ValueType)
				if err != nil {
					return err
				}
				applied = append(applied, AttributeChange{Attribute: claimPossible, Kind: AttributeSet, Values: suggested})
			}
		}
		return c.submitClaimTypeUpdate(ctx, session, root, options, applied, request.ProtectedFromAccidentalDeletion, mutation, &result)
	})
	return claimProject(result, err)
}

// claimStaleSourceAttributes names the source attributes a different form owns.
func claimStaleSourceAttributes(kind ClaimSourceType) []string {
	switch kind {
	case ClaimSourceAttribute:
		return []string{claimSourceOID}
	case ClaimSourceCertificate:
		return []string{claimSourceAttribute}
	default:
		return []string{claimSourceAttribute, claimSourceOID}
	}
}

func (c *Client) submitClaimTypeUpdate(ctx context.Context, session ldapWriteSession, root RootDSE, options ObjectMutationOptions, changes []AttributeChange, protect *bool, mutation *ObjectMutationResult, result *ClaimTypeMutationResult) error {
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
		readOptions.Properties = claimProperties(options.Properties)
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, objectWriteProperties(readOptions, mods), false); err != nil {
			return err
		}
		if err := verifyObjectWrite(mutation, mods, ""); err != nil {
			return err
		}
	}
	if protect != nil {
		result.Protection.Object = *mutation
		return changeOUProtection(ctx, session, root, c.config, mutation, *protect, options, &result.Protection)
	}
	return nil
}

// DeleteClaimType removes one claim type. It submits a single native leaf
// delete and never unprotects the object or removes references for the caller.
func (c *Client) DeleteClaimType(ctx context.Context, request DeleteClaimTypeRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	limits, err := normalizeCentralAccessLimits(request.References)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	defer cancel()
	return c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: claimProperties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := claimLocation(*observed.Object, options.Partition); err != nil {
			return err
		}
		if !request.Force {
			// An observed reference is reported without deleting. A failed or
			// incomplete reference read is never read as "no references".
			references, err := readCentralAccessReferences(ctx, session, *observed.Object, claimBacklinks, limits)
			if err != nil {
				return err
			}
			if !references.Complete {
				return ErrIncompleteResult
			}
			if len(references.References) != 0 {
				return ErrClaimTypeReferenced
			}
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
