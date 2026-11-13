package activedirectory

import (
	"context"
	"errors"
	"strings"
)

// OUProperties uses nil to omit a property; a pointer to an empty string is an
// explicit empty value. Use the common AttributeChange Clear operation to clear
// one. ManagedBy is an explicit DN, not an inferred account name.
type OUProperties struct {
	Description, DisplayName, City, Country, State, StreetAddress, PostalCode, ManagedBy *string
}

type CreateOrganizationalUnitRequest struct {
	Parent                          Identity // zero selects Config.Partition or the endpoint's default NC
	Name                            string
	Properties                      OUProperties
	Attributes                      map[string][]RawValue
	ProtectedFromAccidentalDeletion *bool // nil defaults to true
	Options                         ObjectMutationOptions
}

type UpdateOrganizationalUnitRequest struct {
	Identity                        Identity
	Properties                      OUProperties
	Changes                         []AttributeChange
	ProtectedFromAccidentalDeletion *bool // nil leaves protection unchanged
	Options                         ObjectMutationOptions
}

type DeleteOrganizationalUnitRequest struct {
	Identity  Identity
	Recursive bool
	Options   ObjectMutationOptions
}

type OrganizationalUnitMutationResult struct {
	Object     ObjectMutationResult
	Unit       *OrganizationalUnit
	Protection OUProtectionResult
}

func ouPropertyChanges(properties OUProperties) ([]AttributeChange, error) {
	var changes []AttributeChange
	for _, property := range []struct {
		name  string
		value *string
	}{
		{"description", properties.Description}, {"displayName", properties.DisplayName}, {"l", properties.City}, {"c", properties.Country}, {"st", properties.State}, {"street", properties.StreetAddress}, {"postalCode", properties.PostalCode}, {"managedBy", properties.ManagedBy},
	} {
		if property.value == nil {
			continue
		}
		if !validDirectoryText(*property.value) {
			return nil, ErrInvalidObjectMutation
		}
		if property.name == "managedBy" {
			if _, err := IdentityByDN(*property.value); err != nil {
				return nil, err
			}
		}
		changes = append(changes, AttributeChange{Attribute: property.name, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*property.value))}})
	}
	return changes, nil
}

// CreateOrganizationalUnit uses generic schema-class creation, then protection.
// The add and subsequent parent/OU ACL writes are not a transaction. A returned
// error can therefore accompany an accepted Add or parent ACL update.
func (c *Client) CreateOrganizationalUnit(ctx context.Context, request CreateOrganizationalUnitRequest) (OrganizationalUnitMutationResult, error) {
	var result OrganizationalUnitMutationResult
	changes, err := ouPropertyChanges(request.Properties)
	if err != nil {
		return result, err
	}
	attributes := make(map[string][]RawValue, len(request.Attributes)+len(changes))
	for name, values := range request.Attributes {
		attributes[name] = values
	}
	for _, change := range changes {
		for name := range attributes {
			if strings.EqualFold(name, change.Attribute) {
				return result, ErrInvalidObjectMutation
			}
		}
		attributes[change.Attribute] = change.Values
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	parent := request.Parent
	if parent.Form() == 0 {
		if c == nil {
			return result, ErrClosed
		}
		root, readErr := c.RootDSE(ctx, RootDSEOptions{})
		if readErr != nil {
			return result, readErr
		}
		path := request.Options.Partition
		if path == "" {
			path = c.config.Partition
		}
		if path == "" && root.DefaultNamingContext != nil {
			path = *root.DefaultNamingContext
		}
		if path == "" {
			return result, ErrNoDefaultPartition
		}
		parent, err = IdentityByDN(path)
		if err != nil {
			return result, err
		}
	}
	options := request.Options
	options.Properties = organizationalUnitProperties(options.Properties)
	result.Object, err = c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: "organizationalUnit", Name: request.Name, Attributes: attributes, Options: options})
	if result.Object.After != nil {
		unit, decodeErr := decodeOrganizationalUnit(*result.Object.After)
		result.Unit = &unit
		err = errors.Join(err, decodeErr)
	}
	if err != nil {
		return result, err
	}
	protect := request.ProtectedFromAccidentalDeletion == nil || *request.ProtectedFromAccidentalDeletion
	result.Protection, err = c.SetOrganizationalUnitProtection(ctx, objectGUIDIdentity(*result.Object.TargetGUID), protect, ObjectMutationOptions{Partition: result.Object.Partition})
	if result.Unit != nil {
		result.Unit.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
	}
	return result, err
}

// UpdateOrganizationalUnit submits attribute changes in one strict Modify. An
// optional protection change follows; per-step outcomes survive later errors.
func (c *Client) UpdateOrganizationalUnit(ctx context.Context, request UpdateOrganizationalUnitRequest) (OrganizationalUnitMutationResult, error) {
	var result OrganizationalUnitMutationResult
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	changes, err := ouPropertyChanges(request.Properties)
	if err != nil {
		return result, err
	}
	changes = append(changes, request.Changes...)
	if len(changes) == 0 && request.ProtectedFromAccidentalDeletion == nil {
		return result, ErrInvalidObjectMutation
	}
	var mods []ldapAttributeModification
	if len(changes) > 0 {
		mods, err = objectChanges(changes)
		if err != nil {
			return result, err
		}
	}
	if request.ProtectedFromAccidentalDeletion != nil && request.Options.ExpectedVersion != nil && len(mods) > 0 {
		return result, ErrObjectControlUnsupported
	}
	result.Object, err = c.objectMutation(ctx, request.Identity, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, resolved IdentityResult, object *ObjectMutationResult) error {
		if _, err := decodeOrganizationalUnit(*resolved.Object); err != nil {
			return err
		}
		if len(mods) > 0 {
			controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *object.TargetGUID, false)
			if err != nil {
				return err
			}
			write := ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*object.TargetGUID), modifications: mods, controls: controls}
			if err := submitObjectWrite(ctx, session, write, false, object); err != nil {
				return err
			}
			options := request.Options
			options.Properties = organizationalUnitProperties(options.Properties)
			if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*object.TargetGUID), object, objectWriteProperties(options, mods), false); err != nil {
				return err
			}
			if err := verifyObjectWrite(object, mods, ""); err != nil {
				return err
			}
		}
		if request.ProtectedFromAccidentalDeletion != nil {
			return changeOUProtection(ctx, session, root, c.config, object, *request.ProtectedFromAccidentalDeletion, request.Options, &result.Protection)
		}
		return nil
	})
	if result.Object.After != nil {
		unit, decodeErr := decodeOrganizationalUnit(*result.Object.After)
		unit.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Unit = &unit
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// DeleteOrganizationalUnit never disables protection. Recursive intent can
// remove protected descendants of an unprotected target, as in the reference.
func (c *Client) DeleteOrganizationalUnit(ctx context.Context, request DeleteOrganizationalUnitRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	return c.objectMutation(ctx, request.Identity, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, resolved IdentityResult, result *ObjectMutationResult) error {
		if _, err := decodeOrganizationalUnit(*resolved.Object); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, request.Recursive)
		if err != nil {
			return err
		}
		write := ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}
		if err := submitObjectWrite(ctx, session, write, request.Recursive, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
}
