package activedirectory

import (
	"errors"
	"slices"
	"strings"
)

type userTextField struct {
	attribute string
	value     **string
}

func userTextFields(p *UserProperties) []userTextField {
	return []userTextField{{"sAMAccountName", &p.SAMAccountName}, {"userPrincipalName", &p.UserPrincipalName}, {"givenName", &p.GivenName}, {"sn", &p.Surname}, {"displayName", &p.DisplayName}, {"description", &p.Description}, {"mail", &p.EmailAddress}, {"telephoneNumber", &p.OfficePhone}, {"mobile", &p.MobilePhone}, {"department", &p.Department}, {"company", &p.Company}, {"title", &p.Title}, {"physicalDeliveryOfficeName", &p.Office}, {"l", &p.City}, {"st", &p.State}, {"streetAddress", &p.StreetAddress}, {"postalCode", &p.PostalCode}, {"homeDirectory", &p.HomeDirectory}, {"homeDrive", &p.HomeDrive}, {"profilePath", &p.ProfilePath}, {"scriptPath", &p.ScriptPath}, {"manager", &p.ManagerDN}}
}

func validateUserMutation(identity Identity, options ObjectMutationOptions) error {
	if err := validateIdentityOperation(identity, userIdentityOptions(identity, options.Partition, options.Properties)); err != nil {
		return err
	}
	for _, name := range options.Properties {
		if name == "1.1" {
			return ErrInvalidProperty
		}
	}
	return nil
}

func userManagedAttribute(name string) bool {
	switch strings.ToLower(name) {
	case "useraccountcontrol", "msds-useraccountdisabled", "ms-ds-userpasswordnotrequired", "msds-userdontexpirepassword", "unicodepwd", "userpassword":
		return true
	}
	return false
}

func userAttributeChanges(properties UserProperties, raw []AttributeChange) ([]AttributeChange, error) {
	changes := slices.Clone(raw)
	for _, change := range changes {
		if userManagedAttribute(change.Attribute) {
			return nil, ErrInvalidUser
		}
	}
	for _, field := range userTextFields(&properties) {
		if *field.value == nil {
			continue
		}
		text := **field.value
		if !validDirectoryText(text) {
			return nil, ErrInvalidUser
		}
		if field.attribute == "manager" {
			if _, err := IdentityByDN(text); err != nil {
				return nil, errors.Join(ErrInvalidUser, err)
			}
		}
		changes = append(changes, AttributeChange{Attribute: field.attribute, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(text))}})
	}
	if properties.AccountExpires != nil {
		changes = append(changes, AttributeChange{Attribute: "accountExpires", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(properties.AccountExpires.LDAPString()))}})
	}
	return changes, nil
}

func userHasFlags(p UserProperties) bool {
	return p.Enabled != nil || p.PasswordNotRequired != nil || p.PasswordNeverExpires != nil || p.SmartcardLogonRequired != nil
}
func userAccountControlPatch(p UserProperties) AccountControlPatch {
	return AccountControlPatch{Enabled: p.Enabled, PasswordNotRequired: p.PasswordNotRequired, PasswordNeverExpires: p.PasswordNeverExpires, SmartcardLogonRequired: p.SmartcardLogonRequired}
}

type userLDSFlag struct {
	attribute string
	value     *bool
	invert    bool
}

func userLDSFlags(p UserProperties) []userLDSFlag {
	return []userLDSFlag{{"msDS-UserAccountDisabled", p.Enabled, true}, {"ms-DS-UserPasswordNotRequired", p.PasswordNotRequired, false}, {"msDS-UserDontExpirePassword", p.PasswordNeverExpires, false}}
}
func userBooleanText(value bool) []byte {
	if value {
		return []byte("TRUE")
	}
	return []byte("FALSE")
}

func userFlagChanges(object Object, kind DirectoryType, properties UserProperties) (writes, verification []ldapAttributeModification, err error) {
	if !userHasFlags(properties) {
		return nil, nil, nil
	}
	return accountControlChanges(object, kind, userAccountControlPatch(properties))
}

func userCreationAttributes(request CreateUserRequest, kind DirectoryType) (map[string][]RawValue, error) {
	attributes := make(map[string][]RawValue, len(request.Attributes)+28)
	for name, values := range request.Attributes {
		key := strings.ToLower(name)
		if userManagedAttribute(key) {
			return nil, ErrInvalidUser
		}
		if _, exists := attributes[key]; exists {
			return nil, ErrInvalidUser
		}
		attributes[key] = values
	}
	changes, err := userAttributeChanges(request.Properties, nil)
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
	if kind == DirectoryADDS {
		// Set NORMAL_ACCOUNT and ACCOUNTDISABLE explicitly; do not inherit
		// the server's default PASSWD_NOTREQD behavior for a new account.
		flags := accountControlValues(512|2, userAccountControlPatch(initial))
		attributes["useraccountcontrol"] = []RawValue{NewRawValue([]byte(flags.LDAPString()))}
	} else if kind == DirectoryADLDS {
		if initial.SmartcardLogonRequired != nil {
			return nil, ErrUserCapability
		}
		// Explicit false prevents the default password exemption from being
		// mistaken for the caller's authorization to enable without a password.
		if initial.PasswordNotRequired == nil {
			notRequired := false
			initial.PasswordNotRequired = &notRequired
		}
		for _, flag := range userLDSFlags(initial) {
			if flag.value == nil {
				continue
			}
			value := *flag.value
			if flag.invert {
				value = !value
			}
			attributes[strings.ToLower(flag.attribute)] = []RawValue{NewRawValue(userBooleanText(value))}
		}
	} else {
		return nil, ErrUserCapability
	}
	if _, err := createObjectAttributes(attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}
