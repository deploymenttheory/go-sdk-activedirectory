package model

import (
	"errors"
	"slices"
	"strings"
)

type InternalUserTextField struct {
	InternalAttribute string
	InternalValue     **string
}

func InternalUserTextFields(p *UserProperties) []InternalUserTextField {
	return []InternalUserTextField{
		{"sAMAccountName", &p.SAMAccountName},
		{"userPrincipalName", &p.UserPrincipalName},
		{"givenName", &p.GivenName},
		{"sn", &p.Surname},
		{"displayName", &p.DisplayName},
		{"description", &p.Description},
		{"mail", &p.EmailAddress},
		{"telephoneNumber", &p.OfficePhone},
		{"mobile", &p.MobilePhone},
		{"department", &p.Department},
		{"company", &p.Company},
		{"title", &p.Title},
		{"physicalDeliveryOfficeName", &p.Office},
		{"l", &p.City},
		{"st", &p.State},
		{"streetAddress", &p.StreetAddress},
		{"postalCode", &p.PostalCode},
		{"homeDirectory", &p.HomeDirectory},
		{"homeDrive", &p.HomeDrive},
		{"profilePath", &p.ProfilePath},
		{"scriptPath", &p.ScriptPath},
		{"manager", &p.ManagerDN},
	}
}

func InternalValidateUserMutation(identity Identity, options ObjectMutationOptions) error {
	if err := InternalValidateIdentityOperation(
		identity,
		InternalUserIdentityOptions(identity, options.Partition, options.Properties),
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

func InternalUserManagedAttribute(name string) bool {
	switch strings.ToLower(name) {
	case "useraccountcontrol",
		"msds-useraccountdisabled",
		"ms-ds-userpasswordnotrequired",
		"msds-userdontexpirepassword",
		"unicodepwd",
		"userpassword":
		return true
	}
	return false
}

func InternalUserAttributeChanges(
	properties UserProperties,
	raw []AttributeChange,
) ([]AttributeChange, error) {
	changes := slices.Clone(raw)
	for _, change := range changes {
		if InternalUserManagedAttribute(change.Attribute) {
			return nil, ErrInvalidUser
		}
	}
	for _, field := range InternalUserTextFields(&properties) {
		if *field.InternalValue == nil {
			continue
		}
		text := **field.InternalValue
		if !InternalValidDirectoryText(text) {
			return nil, ErrInvalidUser
		}
		if field.InternalAttribute == "manager" {
			if _, err := IdentityByDN(text); err != nil {
				return nil, errors.Join(ErrInvalidUser, err)
			}
		}
		changes = append(
			changes,
			AttributeChange{
				Attribute: field.InternalAttribute,
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue([]byte(text))},
			},
		)
	}
	if properties.AccountExpires != nil {
		changes = append(
			changes,
			AttributeChange{
				Attribute: "accountExpires",
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue([]byte(properties.AccountExpires.LDAPString()))},
			},
		)
	}
	return changes, nil
}

func InternalUserHasFlags(p UserProperties) bool {
	return p.Enabled != nil || p.PasswordNotRequired != nil || p.PasswordNeverExpires != nil ||
		p.SmartcardLogonRequired != nil
}

func InternalUserAccountControlPatch(p UserProperties) AccountControlPatch {
	return AccountControlPatch{
		Enabled:                p.Enabled,
		PasswordNotRequired:    p.PasswordNotRequired,
		PasswordNeverExpires:   p.PasswordNeverExpires,
		SmartcardLogonRequired: p.SmartcardLogonRequired,
	}
}

type InternalUserLDSFlag struct {
	InternalAttribute string
	InternalValue     *bool
	InternalInvert    bool
}

func InternalUserLDSFlags(p UserProperties) []InternalUserLDSFlag {
	return []InternalUserLDSFlag{
		{"msDS-UserAccountDisabled", p.Enabled, true},
		{"ms-DS-UserPasswordNotRequired", p.PasswordNotRequired, false},
		{"msDS-UserDontExpirePassword", p.PasswordNeverExpires, false},
	}
}

func InternalUserBooleanText(value bool) []byte {
	if value {
		return []byte("TRUE")
	}
	return []byte("FALSE")
}

func InternalUserFlagChanges(
	object Object,
	kind DirectoryType,
	properties UserProperties,
) (writes, verification []InternalLdapAttributeModification, err error) {
	if !InternalUserHasFlags(properties) {
		return nil, nil, nil
	}
	return InternalAccountControlChanges(object, kind, InternalUserAccountControlPatch(properties))
}

func InternalUserCreationAttributes(
	request CreateUserRequest,
	kind DirectoryType,
) (map[string][]RawValue, error) {
	attributes := make(map[string][]RawValue, len(request.Attributes)+28)
	for name, values := range request.Attributes {
		key := strings.ToLower(name)
		if InternalUserManagedAttribute(key) {
			return nil, ErrInvalidUser
		}
		if _, exists := attributes[key]; exists {
			return nil, ErrInvalidUser
		}
		attributes[key] = values
	}
	changes, err := InternalUserAttributeChanges(request.Properties, nil)
	if err != nil {
		return nil, err
	}
	for _, change := range changes {
		key := strings.ToLower(change.Attribute)
		if _, exists := attributes[key]; exists {
			return nil, ErrInvalidUser
		}
		attributes[key] = change.Values
	}
	disabled := false
	initial := request.Properties
	initial.Enabled = &disabled
	switch kind {
	case DirectoryADDS:
		// Set NORMAL_ACCOUNT and ACCOUNTDISABLE explicitly; do not inherit
		// the server's default PASSWD_NOTREQD behavior for a new account.
		flags := InternalAccountControlValues(512|2, InternalUserAccountControlPatch(initial))
		attributes["useraccountcontrol"] = []RawValue{NewRawValue([]byte(flags.LDAPString()))}
	case DirectoryADLDS:
		if initial.SmartcardLogonRequired != nil {
			return nil, errors.Join(ErrUserCapability, (DirectoryCapabilities{Type: kind}).RequireADDS("SmartcardLogonRequired"))
		}
		// Explicit false prevents the default password exemption from being
		// mistaken for the caller's authorization to enable without a password.
		if initial.PasswordNotRequired == nil {
			notRequired := false
			initial.PasswordNotRequired = &notRequired
		}
		for _, flag := range InternalUserLDSFlags(initial) {
			if flag.InternalValue == nil {
				continue
			}
			value := *flag.InternalValue
			if flag.InternalInvert {
				value = !value
			}
			attributes[strings.ToLower(flag.InternalAttribute)] = []RawValue{
				NewRawValue(InternalUserBooleanText(value)),
			}
		}
	default:
		return nil, errors.Join(ErrUserCapability, (DirectoryCapabilities{Type: kind}).RequireAD("CreateUser"))
	}
	if _, err := InternalCreateObjectAttributes(attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}
