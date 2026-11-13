package activedirectory

import (
	"context"
	"errors"
	"strings"
)

// Resource properties, resource property lists and value types share the
// configuration partition's Claims Configuration container with claim types.
// Value types are read-only: the reference exposes no New/Set/Remove for them,
// so this SDK does not invent one.

var (
	ErrResourceProperty       = errors.New("invalid resource property or property list operation")
	ErrResourcePropertyMember = errors.New("invalid resource property list membership change")
)

const (
	resourcePropertyClass     = "msDS-ResourceProperty"
	resourcePropertyListClass = "msDS-ResourcePropertyList"
	resourceValueTypeClass    = "msDS-ValueType"

	resourceValueTypeReference = "msDS-ValueTypeReference"
	resourceSharesValuesWith   = "msDS-ClaimSharesPossibleValuesWith"
	resourceAppliesTo          = "msDS-AppliesToResourceTypes"
	resourceIsSecured          = "msDS-IsUsedAsResourceSecurityAttribute"
	resourceListMembers        = "msDS-MembersOfResourcePropertyList"
	resourcePossibleValuesFlag = "msDS-IsPossibleValuesPresent"
)

// ResourcePropertyListMemberLimit bounds one membership change. Exceeding it is
// an error rather than a silently truncated write.
const ResourcePropertyListMemberLimit = 10000

func resourcePropertyParent(configuration string) string {
	return "CN=Resource Properties,CN=Claims Configuration,CN=Services," + configuration
}

func resourcePropertyListParent(configuration string) string {
	return "CN=Resource Property Lists,CN=Claims Configuration,CN=Services," + configuration
}

func resourceValueTypeParent(configuration string) string {
	return "CN=Value Types,CN=Claims Configuration,CN=Services," + configuration
}

// resourceContainerFor selects the container that owns a class, so location
// checks and searches cannot drift apart.
func resourceContainerFor(class, configuration string) string {
	switch class {
	case resourcePropertyClass:
		return resourcePropertyParent(configuration)
	case resourcePropertyListClass:
		return resourcePropertyListParent(configuration)
	default:
		return resourceValueTypeParent(configuration)
	}
}

func resourcePropertyProperties(extra []string) []string {
	return append(append([]string(nil), extra...), "objectGUID", "uSNChanged", "objectClass", "name",
		"displayName", "description", "enabled", resourceValueTypeReference, resourceSharesValuesWith,
		resourceAppliesTo, resourceIsSecured, claimPossible, claimRestricted, claimValueType)
}

func resourceListProperties(extra []string) []string {
	return append(append([]string(nil), extra...), "objectGUID", "uSNChanged", "objectClass", "name",
		"displayName", "description", resourceListMembers)
}

func resourceValueTypeProperties(extra []string) []string {
	return append(append([]string(nil), extra...), "objectGUID", "uSNChanged", "objectClass", "name",
		"displayName", "description", claimValueType, claimSingle, claimRestricted, resourcePossibleValuesFlag)
}

// resourceLocation requires the expected class and the direct container parent.
// A matching class elsewhere in the tree is out of scope, not a near match.
func resourceLocation(object Object, configuration, class string) error {
	if err := centralAccessClassCheck(object, class); err != nil {
		return errors.Join(ErrResourceProperty, err)
	}
	parent, err := parentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	if !centralSameDN(parent, resourceContainerFor(class, configuration)) {
		return ErrIdentityScope
	}
	return nil
}

// ResourceProperty is one msDS-ResourceProperty. Suggested values and the
// restricted value space mirror the claim-type representation because the
// directory stores them in the same attributes.
type ResourceProperty struct {
	Raw                             Object
	GUID                            *GUID
	ID, DisplayName, Description    *string
	Enabled, IsSecured              *bool
	RestrictValues                  *bool
	ValueTypeDN                     *string
	ValueType                       *ClaimValueType
	SharesValuesWithDN              *string
	AppliesToResourceTypes          []string
	SuggestedValues                 *ClaimSuggestedValues
	ProtectedFromAccidentalDeletion *bool
}

type ResourcePropertyReadOptions struct {
	ResolveIdentityOptions
	IncludeProtection bool
	// IncludeValueType resolves the referenced value type object so a caller
	// sees the settled claim value type rather than only its DN.
	IncludeValueType bool
	References       CentralAccessReferenceLimits
}

type ResourcePropertyResult struct {
	Property    *ResourceProperty
	Observation IdentityResult
	// ValueTypeObservation is populated only when IncludeValueType is set.
	ValueTypeObservation *ResourceValueTypeResult
	Protection           OUProtectionResult
}

type ResourcePropertiesResult struct {
	Properties  []ResourcePropertyResult
	Observation SearchResult
}

// ResourceValueType is one read-only msDS-ValueType.
type ResourceValueType struct {
	Raw                          Object
	GUID                         *GUID
	ID, DisplayName, Description *string
	ValueType                    *ClaimValueType
	IsSingleValued               *bool
	RestrictValues               *bool
	PossibleValuesPresent        *bool
}

type ResourceValueTypeResult struct {
	ValueType   *ResourceValueType
	Observation IdentityResult
}

type ResourceValueTypesResult struct {
	ValueTypes  []ResourceValueTypeResult
	Observation SearchResult
}

func decodeResourceProperty(object Object) (result ResourceProperty, err error) {
	result.Raw = object
	d := rootDSEDecoder{attributes: object.Attributes}
	result.ID = d.text("name")
	result.DisplayName = d.text("displayName")
	result.Description = d.text("description")
	result.Enabled = decodeScalar(&d, "enabled", parseLDAPBool)
	result.IsSecured = decodeScalar(&d, resourceIsSecured, parseLDAPBool)
	result.RestrictValues = decodeScalar(&d, claimRestricted, parseLDAPBool)
	result.ValueTypeDN = d.text(resourceValueTypeReference)
	result.SharesValuesWithDN = d.text(resourceSharesValuesWith)
	result.AppliesToResourceTypes = d.texts(resourceAppliesTo)
	if value := decodeScalar(&d, claimValueType, parseInt64); value != nil {
		settled := ClaimValueType(*value)
		result.ValueType = &settled
	}
	guid, guidErr := centralAccessGUID(object)
	if guidErr == nil {
		result.GUID = &guid
	}
	err = guidErr
	if raw := d.text(claimPossible); raw != nil {
		values, valuesErr := parseClaimValues(*raw, result.ValueType)
		result.SuggestedValues = &values
		err = errors.Join(err, valuesErr)
	}
	return result, errors.Join(err, errors.Join(d.errors...), centralAccessClassCheck(object, resourcePropertyClass))
}

func decodeResourceValueType(object Object) (result ResourceValueType, err error) {
	result.Raw = object
	d := rootDSEDecoder{attributes: object.Attributes}
	result.ID = d.text("name")
	result.DisplayName = d.text("displayName")
	result.Description = d.text("description")
	result.IsSingleValued = decodeScalar(&d, claimSingle, parseLDAPBool)
	result.RestrictValues = decodeScalar(&d, claimRestricted, parseLDAPBool)
	result.PossibleValuesPresent = decodeScalar(&d, resourcePossibleValuesFlag, parseLDAPBool)
	if value := decodeScalar(&d, claimValueType, parseInt64); value != nil {
		settled := ClaimValueType(*value)
		result.ValueType = &settled
	}
	guid, guidErr := centralAccessGUID(object)
	if guidErr == nil {
		result.GUID = &guid
	}
	return result, errors.Join(guidErr, errors.Join(d.errors...), centralAccessClassCheck(object, resourceValueTypeClass))
}

// resourceRead resolves one object of the requested class inside the Claims
// Configuration container and hands it to the caller's projection.
func (c *Client) resourceRead(ctx context.Context, identity Identity, options ResolveIdentityOptions, class string, properties func([]string) []string, project func(context.Context, RootDSE, string, IdentityResult) error) (IdentityResult, error) {
	var observed IdentityResult
	if err := centralAccessIdentity(identity, options); err != nil {
		return observed, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		configuration, e := centralAccessConfiguration(root, c.config, options.Partition)
		if e != nil {
			return e
		}
		resolve := options
		resolve.Partition = configuration
		resolve.Properties = properties(options.Properties)
		observed, e = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if e != nil {
			return e
		}
		if e := resourceLocation(*observed.Object, configuration, class); e != nil {
			return e
		}
		return project(ctx, root, configuration, observed)
	})
	return observed, err
}

// ResourceProperty reads one resource property by identity.
func (c *Client) ResourceProperty(ctx context.Context, identity Identity, options ResourcePropertyReadOptions) (ResourcePropertyResult, error) {
	var result ResourcePropertyResult
	limits, err := normalizeCentralAccessLimits(options.References)
	if err != nil {
		return result, err
	}
	result.Observation, err = c.resourceRead(ctx, identity, options.ResolveIdentityOptions, resourcePropertyClass, resourcePropertyProperties, func(ctx context.Context, root RootDSE, configuration string, observed IdentityResult) error {
		value, decodeErr := decodeResourceProperty(*observed.Object)
		result.Property = &value
		var err error
		if options.IncludeValueType && value.ValueTypeDN != nil {
			observation, e := c.readResourceValueTypeSession(ctx, root, configuration, *value.ValueTypeDN)
			result.ValueTypeObservation = observation
			err = e
			// The property's own stored value type must agree with the object
			// it references; a disagreement is reported, never reconciled.
			if e == nil && observation != nil && observation.ValueType != nil && value.ValueType != nil &&
				observation.ValueType.ValueType != nil && *observation.ValueType.ValueType != *value.ValueType {
				err = ErrResourceProperty
			}
		}
		if options.IncludeProtection && value.GUID != nil {
			protection, e := readOUProtection(ctx, c.session, root, c.config, OrganizationalUnit{DistinguishedName: observed.Object.DistinguishedName, GUID: value.GUID}, configuration)
			result.Protection = protection
			value.ProtectedFromAccidentalDeletion = protection.ProtectedFromAccidentalDeletion
			result.Property = &value
			err = errors.Join(err, e)
		}
		_ = limits
		return errors.Join(decodeErr, err)
	})
	return result, err
}

func (c *Client) readResourceValueTypeSession(ctx context.Context, root RootDSE, configuration, dn string) (*ResourceValueTypeResult, error) {
	identity, err := IdentityByDN(dn)
	if err != nil {
		return nil, err
	}
	observed, err := resolveIdentitySession(ctx, c.session, c.config, root, identity, ResolveIdentityOptions{Partition: configuration, Properties: resourceValueTypeProperties(nil)})
	result := &ResourceValueTypeResult{Observation: observed}
	if err != nil {
		return result, err
	}
	if err := resourceLocation(*observed.Object, configuration, resourceValueTypeClass); err != nil {
		return result, err
	}
	value, decodeErr := decodeResourceValueType(*observed.Object)
	result.ValueType = &value
	return result, decodeErr
}

// ResourceValueType reads one read-only value type by identity.
func (c *Client) ResourceValueType(ctx context.Context, identity Identity, options ResolveIdentityOptions) (ResourceValueTypeResult, error) {
	var result ResourceValueTypeResult
	var err error
	result.Observation, err = c.resourceRead(ctx, identity, options, resourceValueTypeClass, resourceValueTypeProperties, func(_ context.Context, _ RootDSE, _ string, observed IdentityResult) error {
		value, decodeErr := decodeResourceValueType(*observed.Object)
		result.ValueType = &value
		return decodeErr
	})
	return result, err
}

// resourceSearch restricts a caller's query to one container and class.
func (c *Client) resourceSearch(ctx context.Context, options SearchOptions, class string, properties func([]string) []string, row func(context.Context, RootDSE, string, Object) error) (SearchResult, error) {
	var observation SearchResult
	query, err := options.normalized()
	if err != nil {
		return observation, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		configuration, e := centralAccessConfiguration(root, c.config, "")
		if e != nil {
			return e
		}
		container := resourceContainerFor(class, configuration)
		if query.Base != "" && !centralSameDN(query.Base, container) {
			return ErrIdentityScope
		}
		query.Base = container
		query.Scope = ScopeOneLevel
		query.Filter = "(&(objectClass=" + class + ")" + query.Filter + ")"
		query.Properties = properties(options.Properties)
		observation, e = searchIdentitySession(ctx, c.session, query)
		for _, object := range observation.Objects {
			e = errors.Join(e, row(ctx, root, configuration, object))
		}
		return e
	})
	if err != nil {
		observation.Complete = false
	}
	return observation, err
}

// ResourceProperties lists resource properties in the Claims Configuration
// container. The value type reference is not resolved per row; read one
// property with IncludeValueType for that.
func (c *Client) ResourceProperties(ctx context.Context, options SearchOptions) (ResourcePropertiesResult, error) {
	var result ResourcePropertiesResult
	var err error
	result.Observation, err = c.resourceSearch(ctx, options, resourcePropertyClass, resourcePropertyProperties, func(_ context.Context, _ RootDSE, _ string, object Object) error {
		value, decodeErr := decodeResourceProperty(object)
		result.Properties = append(result.Properties, ResourcePropertyResult{Property: &value, Observation: IdentityResult{Object: &object, Complete: true}})
		return decodeErr
	})
	return result, err
}

// ResourceValueTypes lists the read-only value types.
func (c *Client) ResourceValueTypes(ctx context.Context, options SearchOptions) (ResourceValueTypesResult, error) {
	var result ResourceValueTypesResult
	var err error
	result.Observation, err = c.resourceSearch(ctx, options, resourceValueTypeClass, resourceValueTypeProperties, func(_ context.Context, _ RootDSE, _ string, object Object) error {
		value, decodeErr := decodeResourceValueType(object)
		result.ValueTypes = append(result.ValueTypes, ResourceValueTypeResult{ValueType: &value, Observation: IdentityResult{Object: &object, Complete: true}})
		return decodeErr
	})
	return result, err
}

// resourceAppliesToValid rejects applies-to entries that are empty or carry
// directory-hostile text, before any write is attempted.
func resourceAppliesToValid(types []string) error {
	seen := make(map[string]struct{}, len(types))
	for _, name := range types {
		if name == "" || !validDirectoryText(name) {
			return ErrResourceProperty
		}
		key := strings.ToLower(name)
		if _, duplicate := seen[key]; duplicate {
			return ErrResourceProperty
		}
		seen[key] = struct{}{}
	}
	return nil
}

// ResourcePropertyList reads one property list. Members are retrieved through
// the shared bounded reference reader, so a large list is either complete or
// reported as incomplete rather than silently truncated.
func (c *Client) ResourcePropertyList(ctx context.Context, identity Identity, options ResourcePropertyReadOptions) (ResourcePropertyListResult, error) {
	var result ResourcePropertyListResult
	limits, err := normalizeCentralAccessLimits(options.References)
	if err != nil {
		return result, err
	}
	result.Observation, err = c.resourceRead(ctx, identity, options.ResolveIdentityOptions, resourcePropertyListClass, resourceListProperties, func(ctx context.Context, root RootDSE, configuration string, observed IdentityResult) error {
		value, decodeErr := decodeResourcePropertyList(*observed.Object)
		result.List = &value
		members, membersErr := readCentralAccessReferences(ctx, c.session, *observed.Object, resourceListMembers, limits)
		result.Members = members
		err := errors.Join(decodeErr, membersErr)
		if options.IncludeProtection && value.GUID != nil {
			protection, protectErr := readOUProtection(ctx, c.session, root, c.config, OrganizationalUnit{DistinguishedName: observed.Object.DistinguishedName, GUID: value.GUID}, configuration)
			result.Protection = protection
			value.ProtectedFromAccidentalDeletion = protection.ProtectedFromAccidentalDeletion
			result.List = &value
			err = errors.Join(err, protectErr)
		}
		return err
	})
	return result, err
}

// ResourcePropertyLists lists property lists. Members are not retrieved per
// row; read one list for its membership.
func (c *Client) ResourcePropertyLists(ctx context.Context, options SearchOptions) (ResourcePropertyListsResult, error) {
	var result ResourcePropertyListsResult
	var err error
	result.Observation, err = c.resourceSearch(ctx, options, resourcePropertyListClass, resourceListProperties, func(_ context.Context, _ RootDSE, _ string, object Object) error {
		value, decodeErr := decodeResourcePropertyList(object)
		result.Lists = append(result.Lists, ResourcePropertyListResult{List: &value, Observation: IdentityResult{Object: &object, Complete: true}})
		return decodeErr
	})
	return result, err
}
