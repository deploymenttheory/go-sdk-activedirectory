package model

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrNotOrganizationalUnit = errors.New("directory object is not an organizational unit")
	ErrOUProtection          = errors.New(
		"organizational unit protection could not be established or verified",
	)
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

func InternalOrganizationalUnitProperties(extra []string) []string {
	properties := slices.DeleteFunc(
		slices.Clone(extra),
		func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") },
	)
	return append(
		properties,
		"objectClass",
		"objectGUID",
		"name",
		"description",
		"displayName",
		"l",
		"c",
		"st",
		"street",
		"postalCode",
		"managedBy",
	)
}

func InternalDecodeOrganizationalUnit(object Object) (OrganizationalUnit, error) {
	unit := OrganizationalUnit{DistinguishedName: object.DistinguishedName, Raw: object}
	decoder := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	classes := decoder.InternalTexts("objectClass")
	if !slices.ContainsFunc(
		classes,
		func(class string) bool { return strings.EqualFold(class, "organizationalUnit") },
	) {
		return unit, errors.Join(ErrNotOrganizationalUnit, errors.Join(decoder.InternalErrors...))
	}
	if values, state := object.Attribute("objectGUID"); state == AttributePresent {
		if len(values) != 1 {
			decoder.InternalErrors = append(decoder.InternalErrors, ErrInvalidResult)
		} else {
			guid, err := NewRawValue(values[0]).GUID()
			if err != nil {
				decoder.InternalErrors = append(decoder.InternalErrors, err)
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
		*destination = decoder.InternalText(attribute)
	}
	return unit, errors.Join(decoder.InternalErrors...)
}

func InternalReadOUProtection(
	ctx context.Context,
	directory InternalDirectorySession,
	root RootDSE,
	config Config,
	unit OrganizationalUnit,
	partition string,
) (OUProtectionResult, error) {
	var result OUProtectionResult
	session, ok := directory.(InternalOuProtectionSession)
	if !ok {
		return result, ErrUnsupported
	}
	if unit.GUID == nil {
		return result, ErrInvalidResult
	}
	if !slices.Contains(root.SupportedControls, InternalOuSDFlagsControl) {
		return result, ErrObjectControlUnsupported
	}
	object := ObjectMutationResult{
		TargetGUID: unit.GUID,
		TargetDN:   unit.DistinguishedName,
		Partition:  partition,
	}
	snapshot, err := InternalPrepareOUProtection(ctx, session, root, config, &object, &result)
	if err != nil {
		return result, err
	}
	left, right := InternalOuACLProtection(
		snapshot.InternalAcl,
		InternalOuObjectProtectionMask,
	), snapshot.InternalParentProtection()
	if left != nil && right != nil {
		value := *left && *right
		result.ProtectedFromAccidentalDeletion = &value
	}
	return result, nil
}
