package activedirectory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

// AuthenticationPolicyProperties is an explicit patch: nil omits a property,
// false/zero are values, and AttributeClear clears one. Lifetimes are positive
// 100ns counts, with zero meaning no policy override, not an infinite duration.
// Descriptor strings are SDDL; conditions.Compile builds them headlessly.
type AuthenticationPolicyProperties struct {
	Description                                                                   *string
	Enforced                                                                      *bool
	UserTGTLifetime, ComputerTGTLifetime, ServiceTGTLifetime                      *Interval100ns
	UserAllowedToAuthenticateFrom, UserAllowedToAuthenticateTo                    *string
	ComputerAllowedToAuthenticateTo                                               *string
	ServiceAllowedToAuthenticateFrom, ServiceAllowedToAuthenticateTo              *string
	UserAllowedNTLMNetworkAuthentication, ServiceAllowedNTLMNetworkAuthentication *bool
	RollingNTLMSecret                                                             *StrongNTLMPolicy
}

func authenticationPolicyChanges(properties AuthenticationPolicyProperties, raw []AttributeChange) ([]ldapAttributeModification, error) {
	changes := append([]AttributeChange(nil), raw...)
	// Descriptor writes use typed SDDL so Windows validates conditional syntax.
	// Raw reads remain exact; raw Clear is supported for every policy property.
	for _, change := range raw {
		name := strings.ToLower(change.Attribute)
		if authenticationDescriptorAttribute(name) && change.Kind != AttributeClear {
			return nil, fmt.Errorf("%w: use the typed SDDL property", ErrAuthenticationPolicyDescriptor)
		}
		switch name {
		case "ntsecuritydescriptor", "msds-assignedauthnpolicy", "msds-assignedauthnpolicysilo":
			return nil, ErrInvalidAuthenticationPolicy
		}
	}
	if properties.Description != nil {
		if !validDirectoryText(*properties.Description) {
			return nil, ErrInvalidAuthenticationPolicy
		}
		changes = append(changes, authenticationSetting("description", *properties.Description))
	}
	for _, property := range []struct {
		name  string
		value *bool
	}{
		{"msDS-AuthNPolicyEnforced", properties.Enforced},
		{"msDS-UserAllowedNTLMNetworkAuthentication", properties.UserAllowedNTLMNetworkAuthentication},
		{"msDS-ServiceAllowedNTLMNetworkAuthentication", properties.ServiceAllowedNTLMNetworkAuthentication},
	} {
		if property.value != nil {
			value := "FALSE"
			if *property.value {
				value = "TRUE"
			}
			changes = append(changes, authenticationSetting(property.name, value))
		}
	}
	for _, property := range []struct {
		name  string
		value *Interval100ns
	}{
		{"msDS-UserTGTLifetime", properties.UserTGTLifetime}, {"msDS-ComputerTGTLifetime", properties.ComputerTGTLifetime}, {"msDS-ServiceTGTLifetime", properties.ServiceTGTLifetime},
	} {
		if property.value != nil {
			if *property.value < 0 {
				return nil, ErrInvalidAuthenticationPolicy
			}
			changes = append(changes, authenticationSetting(property.name, property.value.LDAPString()))
		}
	}
	if value := properties.RollingNTLMSecret; value != nil {
		if *value < StrongNTLMDisabled || *value > StrongNTLMRequired {
			return nil, ErrInvalidAuthenticationPolicy
		}
		changes = append(changes, authenticationSetting("msDS-StrongNTLMPolicy", strconv.FormatInt(int64(*value), 10)))
	}
	for _, property := range []struct {
		name  string
		value *string
	}{
		{"msDS-UserAllowedToAuthenticateFrom", properties.UserAllowedToAuthenticateFrom}, {"msDS-UserAllowedToAuthenticateTo", properties.UserAllowedToAuthenticateTo}, {"msDS-ComputerAllowedToAuthenticateTo", properties.ComputerAllowedToAuthenticateTo}, {"msDS-ServiceAllowedToAuthenticateFrom", properties.ServiceAllowedToAuthenticateFrom}, {"msDS-ServiceAllowedToAuthenticateTo", properties.ServiceAllowedToAuthenticateTo},
	} {
		if property.value == nil {
			continue
		}
		descriptor, err := conditions.DescriptorBytes(*property.value)
		if err != nil {
			return nil, errors.Join(ErrAuthenticationPolicyDescriptor, err)
		}
		if err := validateAuthenticationDescriptor(descriptor); err != nil {
			return nil, err
		}
		changes = append(changes, AttributeChange{Attribute: property.name, Kind: AttributeSet, Values: []RawValue{NewRawValue(descriptor)}})
	}
	if len(changes) == 0 {
		return nil, nil
	}
	mods, err := objectChanges(changes)
	if err != nil {
		return nil, err
	}
	for _, mod := range mods {
		if err := validateAuthenticationModification(mod); err != nil {
			return nil, err
		}
	}
	return mods, nil
}

func authenticationSetting(name, value string) AttributeChange {
	return AttributeChange{Attribute: name, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(value))}}
}

func authenticationDescriptorAttribute(name string) bool {
	switch strings.ToLower(name) {
	case "msds-userallowedtoauthenticatefrom", "msds-userallowedtoauthenticateto", "msds-computerallowedtoauthenticateto", "msds-serviceallowedtoauthenticatefrom", "msds-serviceallowedtoauthenticateto":
		return true
	}
	return false
}

func validateAuthenticationModification(mod ldapAttributeModification) error {
	name := strings.ToLower(mod.attribute)
	if mod.operation == 1 && len(mod.values) == 0 {
		return nil
	}
	switch name {
	case "msds-authnpolicyenforced", "msds-userallowedntlmnetworkauthentication", "msds-serviceallowedntlmnetworkauthentication":
		if len(mod.values) != 1 {
			return ErrInvalidAuthenticationPolicy
		}
		if _, err := parseLDAPBool(string(mod.values[0])); err != nil {
			return ErrInvalidAuthenticationPolicy
		}
	case "msds-usertgtlifetime", "msds-computertgtlifetime", "msds-servicetgtlifetime", "msds-strongntlmpolicy":
		if len(mod.values) != 1 {
			return ErrInvalidAuthenticationPolicy
		}
		value, err := strconv.ParseInt(string(mod.values[0]), 10, 64)
		if err != nil || value < 0 || (name == "msds-strongntlmpolicy" && value > 2) {
			return ErrInvalidAuthenticationPolicy
		}
	}
	return nil
}

func validateAuthenticationDescriptor(raw []byte) error {
	if len(raw) > 132096 {
		return ErrAuthenticationPolicyDescriptor
	}
	acl, err := decodeDirectoryDACL(raw)
	if err != nil {
		return errors.Join(ErrAuthenticationPolicyDescriptor, err)
	}
	// NULL/absent DACLs are rejected by the shared decoder. An explicit empty
	// DACL is a valid deny-all policy. Preserve ACE order, all masks and bytes.
	hasControlAccess := len(acl.aces) == 0
	for _, ace := range acl.aces {
		switch ace[0] {
		case 0, 1, 5, 6, 9, 10, 11, 12:
		default:
			return ErrAuthenticationPolicyDescriptor
		}
		mask := binary.LittleEndian.Uint32(ace[4:8])
		if ace[1]&8 == 0 && mask&(0x100|0x10000000) != 0 {
			hasControlAccess = true
		}
	}
	if !hasControlAccess {
		return ErrAuthenticationPolicyDescriptor
	}
	return nil
}
