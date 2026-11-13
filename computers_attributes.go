package activedirectory

import (
	"errors"
	"slices"
	"strings"
)

const computerEncryptionMask Flags32 = 0x1f

type computerTextField struct {
	attribute string
	value     **string
}

func computerTextFields(p *ComputerProperties) []computerTextField {
	return []computerTextField{{"sAMAccountName", &p.SAMAccountName}, {"dNSHostName", &p.DNSHostName}, {"userPrincipalName", &p.UserPrincipalName}, {"displayName", &p.DisplayName}, {"description", &p.Description}, {"location", &p.Location}, {"managedBy", &p.ManagedByDN}, {"wWWHomePage", &p.HomePage}, {"operatingSystem", &p.OperatingSystem}, {"operatingSystemVersion", &p.OperatingSystemVersion}, {"operatingSystemServicePack", &p.OperatingSystemServicePack}, {"operatingSystemHotfix", &p.OperatingSystemHotfix}}
}

func computerSAM(value string) (string, error) {
	if value == "" || !validDirectoryText(value) || value == "$" || strings.HasSuffix(value, "$$") {
		return "", ErrInvalidComputer
	}
	if !strings.HasSuffix(value, "$") {
		value += "$"
	}
	return value, nil
}

func computerManagedAttribute(name string) bool {
	if userManagedAttribute(name) {
		return true
	}
	switch strings.ToLower(name) {
	case "samaccountname", "msds-supportedencryptiontypes", "pwdlastset":
		return true
	}
	return false
}
func computerAttributeChanges(properties ComputerProperties, raw []AttributeChange) ([]AttributeChange, error) {
	changes := slices.Clone(raw)
	for _, change := range changes {
		if computerManagedAttribute(change.Attribute) {
			return nil, ErrInvalidComputer
		}
	}
	for _, field := range computerTextFields(&properties) {
		if *field.value == nil {
			continue
		}
		value := **field.value
		if !validDirectoryText(value) {
			return nil, ErrInvalidComputer
		}
		if field.attribute == "managedBy" {
			if _, err := IdentityByDN(value); err != nil {
				return nil, errors.Join(ErrInvalidComputer, err)
			}
		}
		if field.attribute == "sAMAccountName" {
			var err error
			value, err = computerSAM(value)
			if err != nil {
				return nil, err
			}
		}
		changes = append(changes, AttributeChange{Attribute: field.attribute, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(value))}})
	}
	if properties.AccountExpires != nil {
		changes = append(changes, AttributeChange{Attribute: "accountExpires", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(properties.AccountExpires.LDAPString()))}})
	}
	if properties.KerberosEncryptionTypes != nil && *properties.KerberosEncryptionTypes & ^computerEncryptionMask != 0 {
		return nil, ErrInvalidComputer
	}
	return changes, nil
}
func computerHasEncryption(p ComputerProperties) bool {
	return p.KerberosEncryptionTypes != nil || p.CompoundIdentitySupported != nil
}
func computerEncryptionValues(old Flags32, p ComputerProperties) Flags32 {
	if p.KerberosEncryptionTypes != nil {
		old = (old & ^computerEncryptionMask) | *p.KerberosEncryptionTypes
	}
	if p.CompoundIdentitySupported != nil {
		old = old.With(0x40, *p.CompoundIdentitySupported)
	}
	return old
}
func computerEncryptionChanges(object Object, p ComputerProperties) (writes, verification []ldapAttributeModification, err error) {
	if !computerHasEncryption(p) {
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
	next := computerEncryptionValues(old, p)
	if next != old {
		writes = accountConditionalValue("msDS-SupportedEncryptionTypes", value.Bytes(), []byte(next.LDAPString()))
	}
	verification = []ldapAttributeModification{accountValueVerification("msDS-SupportedEncryptionTypes", []byte(next.LDAPString()))}
	return writes, verification, nil
}

func computerCreationAttributes(request CreateComputerRequest) (map[string][]RawValue, error) {
	if request.Control.ChangePasswordAtLogon != nil {
		return nil, ErrAccountControlUnsupported
	}
	if err := validateAccountControlPatch(request.Control); err != nil {
		return nil, err
	}
	if request.Properties.SAMAccountName == nil {
		request.Properties.SAMAccountName = &request.Name
	}
	changes, err := computerAttributeChanges(request.Properties, nil)
	if err != nil {
		return nil, err
	}
	attributes := make(map[string][]RawValue, len(request.Attributes)+len(changes)+2)
	for name, values := range request.Attributes {
		key := strings.ToLower(name)
		if computerManagedAttribute(key) {
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
	flags := accountControlValues(0x1000|2, initial)
	attributes["useraccountcontrol"] = []RawValue{NewRawValue([]byte(flags.LDAPString()))}
	if computerHasEncryption(request.Properties) {
		flags := computerEncryptionValues(0, request.Properties)
		attributes["msds-supportedencryptiontypes"] = []RawValue{NewRawValue([]byte(flags.LDAPString()))}
	}
	if _, err := createObjectAttributes(attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}
