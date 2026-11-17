package model

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

func InternalOuPropertyChanges(properties OUProperties) ([]AttributeChange, error) {
	var changes []AttributeChange
	for _, property := range []struct {
		InternalName  string
		InternalValue *string
	}{
		{"description", properties.Description},
		{"displayName", properties.DisplayName},
		{"l", properties.City},
		{"c", properties.Country},
		{"st", properties.State},
		{"street", properties.StreetAddress},
		{"postalCode", properties.PostalCode},
		{"managedBy", properties.ManagedBy},
	} {
		if property.InternalValue == nil {
			continue
		}
		if !InternalValidDirectoryText(*property.InternalValue) {
			return nil, ErrInvalidObjectMutation
		}
		if property.InternalName == "managedBy" {
			if _, err := IdentityByDN(*property.InternalValue); err != nil {
				return nil, err
			}
		}
		changes = append(
			changes,
			AttributeChange{
				Attribute: property.InternalName,
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue([]byte(*property.InternalValue))},
			},
		)
	}
	return changes, nil
}
