package model

import (
	"errors"
	"slices"
	"strings"
)

const InternalComputerEncryptionMask Flags32 = 0x1f

type InternalComputerTextField struct {
	InternalAttribute string
	InternalValue     **string
}

func InternalComputerTextFields(p *ComputerProperties) []InternalComputerTextField {
	return []InternalComputerTextField{
		{"sAMAccountName", &p.SAMAccountName},
		{"dNSHostName", &p.DNSHostName},
		{"userPrincipalName", &p.UserPrincipalName},
		{"displayName", &p.DisplayName},
		{"description", &p.Description},
		{"location", &p.Location},
		{"managedBy", &p.ManagedByDN},
		{"wWWHomePage", &p.HomePage},
		{"operatingSystem", &p.OperatingSystem},
		{"operatingSystemVersion", &p.OperatingSystemVersion},
		{"operatingSystemServicePack", &p.OperatingSystemServicePack},
		{"operatingSystemHotfix", &p.OperatingSystemHotfix},
	}
}

func InternalComputerSAM(value string) (string, error) {
	if value == "" || !InternalValidDirectoryText(value) || value == "$" ||
		strings.HasSuffix(value, "$$") {
		return "", ErrInvalidComputer
	}
	if !strings.HasSuffix(value, "$") {
		value += "$"
	}
	return value, nil
}

func InternalComputerManagedAttribute(name string) bool {
	if InternalUserManagedAttribute(name) {
		return true
	}
	switch strings.ToLower(name) {
	case "samaccountname", "msds-supportedencryptiontypes", "pwdlastset":
		return true
	}
	return false
}

func InternalComputerAttributeChanges(
	properties ComputerProperties,
	raw []AttributeChange,
) ([]AttributeChange, error) {
	changes := slices.Clone(raw)
	for _, change := range changes {
		if InternalComputerManagedAttribute(change.Attribute) {
			return nil, ErrInvalidComputer
		}
	}
	for _, field := range InternalComputerTextFields(&properties) {
		if *field.InternalValue == nil {
			continue
		}
		value := **field.InternalValue
		if !InternalValidDirectoryText(value) {
			return nil, ErrInvalidComputer
		}
		if field.InternalAttribute == "managedBy" {
			if _, err := IdentityByDN(value); err != nil {
				return nil, errors.Join(ErrInvalidComputer, err)
			}
		}
		if field.InternalAttribute == "sAMAccountName" {
			var err error
			value, err = InternalComputerSAM(value)
			if err != nil {
				return nil, err
			}
		}
		changes = append(
			changes,
			AttributeChange{
				Attribute: field.InternalAttribute,
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue([]byte(value))},
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
	if properties.KerberosEncryptionTypes != nil &&
		*properties.KerberosEncryptionTypes & ^InternalComputerEncryptionMask != 0 {
		return nil, ErrInvalidComputer
	}
	return changes, nil
}

func InternalComputerHasEncryption(p ComputerProperties) bool {
	return p.KerberosEncryptionTypes != nil || p.CompoundIdentitySupported != nil
}

func InternalComputerEncryptionValues(old Flags32, p ComputerProperties) Flags32 {
	if p.KerberosEncryptionTypes != nil {
		old = (old & ^InternalComputerEncryptionMask) | *p.KerberosEncryptionTypes
	}
	if p.CompoundIdentitySupported != nil {
		old = old.With(0x40, *p.CompoundIdentitySupported)
	}
	return old
}

func InternalComputerEncryptionChanges(
	object Object,
	p ComputerProperties,
) (writes, verification []InternalLdapAttributeModification, err error) {
	if !InternalComputerHasEncryption(p) {
		return nil, nil, nil
	}
	// Missing/hidden is not a known zero mask. Fail instead of overwriting
	// flags that the caller could not observe.
	value, err := object.Values("msDS-SupportedEncryptionTypes").Single()
	if err != nil {
		return nil, nil, err
	}
	old, err := value.Flags32()
	if err != nil {
		return nil, nil, err
	}
	next := InternalComputerEncryptionValues(old, p)
	if next != old {
		writes = InternalAccountConditionalValue(
			"msDS-SupportedEncryptionTypes",
			value.Bytes(),
			[]byte(next.LDAPString()),
		)
	}
	verification = []InternalLdapAttributeModification{
		InternalAccountValueVerification(
			"msDS-SupportedEncryptionTypes",
			[]byte(next.LDAPString()),
		),
	}
	return writes, verification, nil
}

func InternalComputerCreationAttributes(
	request CreateComputerRequest,
) (map[string][]RawValue, error) {
	if request.Control.ChangePasswordAtLogon != nil {
		return nil, ErrAccountControlUnsupported
	}
	if err := InternalValidateAccountControlPatch(request.Control); err != nil {
		return nil, err
	}
	if request.Properties.SAMAccountName == nil {
		request.Properties.SAMAccountName = &request.Name
	}
	changes, err := InternalComputerAttributeChanges(request.Properties, nil)
	if err != nil {
		return nil, err
	}
	attributes := make(map[string][]RawValue, len(request.Attributes)+len(changes)+2)
	for name, values := range request.Attributes {
		key := strings.ToLower(name)
		if InternalComputerManagedAttribute(key) {
			return nil, ErrInvalidComputer
		}
		if _, exists := attributes[key]; exists {
			return nil, ErrInvalidComputer
		}
		attributes[key] = values
	}
	for _, change := range changes {
		key := strings.ToLower(change.Attribute)
		if _, exists := attributes[key]; exists {
			return nil, ErrInvalidComputer
		}
		attributes[key] = change.Values
	}
	disabled := false
	initial := request.Control
	initial.Enabled = &disabled
	flags := InternalAccountControlValues(0x1000|2, initial)
	attributes["useraccountcontrol"] = []RawValue{NewRawValue([]byte(flags.LDAPString()))}
	if InternalComputerHasEncryption(request.Properties) {
		flags := InternalComputerEncryptionValues(0, request.Properties)
		attributes["msds-supportedencryptiontypes"] = []RawValue{
			NewRawValue([]byte(flags.LDAPString())),
		}
	}
	if _, err := InternalCreateObjectAttributes(attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}
