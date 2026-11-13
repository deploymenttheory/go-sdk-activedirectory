package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrNotOrganizationalUnit = errors.New("directory object is not an organizational unit")
	ErrOUProtection          = errors.New("organizational unit protection could not be established or verified")
)

// OrganizationalUnit retains raw LDAP values and unknown optional properties.
// Protection is an ACL observation, not a guarantee against every privileged
// operation or recursive deletion of an ancestor.
type OrganizationalUnit struct {
	DistinguishedName                                                                          string
	GUID                                                                                       *GUID
	Name, Description, DisplayName, City, Country, State, StreetAddress, PostalCode, ManagedBy *string
	ProtectedFromAccidentalDeletion                                                            *bool
	Raw                                                                                        Object
}

type OrganizationalUnitResult struct {
	Unit        *OrganizationalUnit
	Observation IdentityResult
	Protection  OUProtectionResult
}

type OrganizationalUnitsResult struct {
	Units       []OrganizationalUnit
	Observation SearchResult
	Protection  []OUProtectionResult
}

func organizationalUnitProperties(extra []string) []string {
	properties := slices.DeleteFunc(slices.Clone(extra), func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") })
	return append(properties, "objectClass", "objectGUID", "name", "description", "displayName", "l", "c", "st", "street", "postalCode", "managedBy")
}

func decodeOrganizationalUnit(object Object) (OrganizationalUnit, error) {
	unit := OrganizationalUnit{DistinguishedName: object.DistinguishedName, Raw: object}
	decoder := rootDSEDecoder{attributes: object.Attributes}
	classes := decoder.texts("objectClass")
	if !slices.ContainsFunc(classes, func(class string) bool { return strings.EqualFold(class, "organizationalUnit") }) {
		return unit, errors.Join(ErrNotOrganizationalUnit, errors.Join(decoder.errors...))
	}
	if values, state := object.Attribute("objectGUID"); state == AttributePresent {
		if len(values) != 1 {
			decoder.errors = append(decoder.errors, ErrInvalidResult)
		} else {
			guid, err := NewRawValue(values[0]).GUID()
			if err != nil {
				decoder.errors = append(decoder.errors, err)
			} else {
				unit.GUID = &guid
			}
		}
	}
	for attribute, destination := range map[string]**string{
		"name": &unit.Name, "description": &unit.Description, "displayName": &unit.DisplayName,
		"l": &unit.City, "c": &unit.Country, "st": &unit.State, "street": &unit.StreetAddress,
		"postalCode": &unit.PostalCode, "managedBy": &unit.ManagedBy,
	} {
		*destination = decoder.text(attribute)
	}
	return unit, errors.Join(decoder.errors...)
}

// OrganizationalUnit resolves an explicit DN/GUID using the common identity
// rules and verifies its class. Missing typed attributes remain nil.
func (c *Client) OrganizationalUnit(ctx context.Context, identity Identity, options ResolveIdentityOptions) (OrganizationalUnitResult, error) {
	if options.Target != IdentityTargetObject {
		return OrganizationalUnitResult{}, ErrUnsupportedIdentity
	}
	wantProtection := slices.ContainsFunc(options.Properties, func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") })
	options.Properties = organizationalUnitProperties(options.Properties)
	var result OrganizationalUnitResult
	if err := validateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		observed, err := resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		result.Observation = observed
		if err != nil {
			return err
		}
		unit, err := decodeOrganizationalUnit(*observed.Object)
		result.Unit = &unit
		if err != nil || !wantProtection {
			return err
		}
		result.Protection, err = readOUProtection(ctx, c.session, root, c.config, unit, observed.Partition)
		result.Unit.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		return err
	})
	return result, err
}

// OrganizationalUnits uses the SDK's existing LDAP SearchOptions, including
// explicit scope, paging and caller limits. An empty Base selects the configured
// partition or the endpoint's default NC. The filter is intersected with the OU
// class filter; no PowerShell-expression parsing or fallback scope is performed.
func (c *Client) OrganizationalUnits(ctx context.Context, options SearchOptions) (OrganizationalUnitsResult, error) {
	var result OrganizationalUnitsResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	wantProtection := slices.ContainsFunc(options.Properties, func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") })
	options.Properties = organizationalUnitProperties(options.Properties)
	if !options.TypedFilter.unset() {
		options.TypedFilter = FilterAnd(FilterEqual("objectClass", FilterText("organizationalUnit")), options.TypedFilter)
	} else if options.Filter == "" {
		options.Filter = "(objectClass=organizationalUnit)"
	} else {
		options.Filter = "(&(objectClass=organizationalUnit)" + options.Filter + ")"
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
		selected, contexts, err := identityPartition(identity, c.config.Partition, root)
		if err != nil {
			return err
		}
		result.Observation, err = searchIdentitySession(ctx, c.session, options)
		searchErr := err
		for _, object := range result.Observation.Objects {
			unit, decodeErr := decodeOrganizationalUnit(object)
			dn, scopeErr := parseIdentityDN(object.DistinguishedName)
			if scopeErr != nil || identityNamingContext(dn, contexts) != selected {
				decodeErr = errors.Join(decodeErr, ErrIdentityScope)
			}
			if wantProtection {
				var protection OUProtectionResult
				if decodeErr == nil && searchErr == nil {
					protection, decodeErr = readOUProtection(ctx, c.session, root, c.config, unit, root.NamingContexts[selected])
					unit.ProtectedFromAccidentalDeletion = protection.ProtectedFromAccidentalDeletion
				}
				result.Protection = append(result.Protection, protection)
			}
			result.Units = append(result.Units, unit)
			err = errors.Join(err, decodeErr)
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}

func readOUProtection(ctx context.Context, directory directorySession, root RootDSE, config Config, unit OrganizationalUnit, partition string) (OUProtectionResult, error) {
	var result OUProtectionResult
	session, ok := directory.(ouProtectionSession)
	if !ok {
		return result, ErrUnsupported
	}
	if unit.GUID == nil {
		return result, ErrInvalidResult
	}
	if !slices.Contains(root.SupportedControls, ouSDFlagsControl) {
		return result, ErrObjectControlUnsupported
	}
	object := ObjectMutationResult{TargetGUID: unit.GUID, TargetDN: unit.DistinguishedName, Partition: partition}
	snapshot, err := prepareOUProtection(ctx, session, root, config, &object, &result)
	if err != nil {
		return result, err
	}
	left, right := ouACLProtection(snapshot.acl, ouObjectProtectionMask), snapshot.parentProtection()
	if left != nil && right != nil {
		value := *left && *right
		result.ProtectedFromAccidentalDeletion = &value
	}
	return result, nil
}
