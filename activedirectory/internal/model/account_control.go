package model

import (
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalidAccountControl     = errors.New("invalid or conflicting account-control options")
	ErrAccountControlTarget      = errors.New("directory object is not a supported account")
	ErrAccountControlUnsupported = errors.New(
		"account-control option is not supported by this directory",
	)
)

// AccountControlPatch changes only non-nil fields. It never exposes a raw mask
// that could overwrite account-type, computed or unknown flags. Password change
// permission is an ACL property, not a stored UAC flag.
type AccountControlPatch struct {
	Enabled                           *bool
	AccountNotDelegated               *bool
	AllowReversiblePasswordEncryption *bool
	DoesNotRequirePreAuth             *bool
	HomeDirectoryRequired             *bool
	MNSLogonAccount                   *bool
	PasswordNeverExpires              *bool
	PasswordNotRequired               *bool
	SmartcardLogonRequired            *bool
	TrustedForDelegation              *bool
	TrustedToAuthForDelegation        *bool
	UseDESKeyOnly                     *bool
	// True writes pwdLastSet=0. False writes -1, asking the server to set its
	// current time. Neither value is written into userAccountControl.
	ChangePasswordAtLogon *bool
}

// AccountControlState retains stored and computed values separately. Nil means
// the attribute was not returned, not false. LockoutTime alone is not a current
// lockout verdict: the server's computed flags account for lockout duration.
type AccountControlState struct {
	DistinguishedName                                                 string
	Directory                                                         DirectoryType
	StoredFlags, ComputedFlags                                        *Flags32
	Enabled, AccountNotDelegated, AllowReversiblePasswordEncryption   *bool
	DoesNotRequirePreAuth, HomeDirectoryRequired, MNSLogonAccount     *bool
	PasswordNeverExpires, PasswordNotRequired, SmartcardLogonRequired *bool
	TrustedForDelegation, TrustedToAuthForDelegation, UseDESKeyOnly   *bool
	LockedOut, PasswordExpired                                        *bool
	PasswordLastSet, LockoutTime                                      *FileTime
	Raw                                                               Object
}

type AccountControlResult struct {
	Account     *AccountControlState
	Observation IdentityResult
}

type AccountControlRequest struct {
	Identity Identity
	Patch    AccountControlPatch
	Options  ObjectMutationOptions
}

type AccountControlMutationResult struct {
	Account  *AccountControlState
	Mutation ObjectMutationResult
}

type InternalAccountFlagField struct {
	InternalValue        *bool
	InternalMask         Flags32
	InternalInverse      bool
	InternalLdsAttribute string
}

func InternalAccountFlagFields(p AccountControlPatch) []InternalAccountFlagField {
	return []InternalAccountFlagField{
		{p.Enabled, 0x2, true, "msDS-UserAccountDisabled"},
		{p.HomeDirectoryRequired, 0x8, false, ""},
		{p.PasswordNotRequired, 0x20, false, "ms-DS-UserPasswordNotRequired"},
		{
			p.AllowReversiblePasswordEncryption,
			0x80,
			false,
			"ms-DS-UserEncryptedTextPasswordAllowed",
		},
		{p.PasswordNeverExpires, 0x10000, false, "msDS-UserDontExpirePassword"},
		{p.MNSLogonAccount, 0x20000, false, ""},
		{p.SmartcardLogonRequired, 0x40000, false, ""},
		{p.TrustedForDelegation, 0x80000, false, ""},
		{p.AccountNotDelegated, 0x100000, false, ""},
		{p.UseDESKeyOnly, 0x200000, false, ""},
		{p.DoesNotRequirePreAuth, 0x400000, false, ""},
		{p.TrustedToAuthForDelegation, 0x1000000, false, ""},
	}
}

func InternalAccountControlValues(flags Flags32, patch AccountControlPatch) Flags32 {
	for _, field := range InternalAccountFlagFields(patch) {
		if field.InternalValue != nil {
			flags = flags.With(field.InternalMask, *field.InternalValue != field.InternalInverse)
		}
	}
	return flags
}

func InternalAccountControlProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"distinguishedName",
		"objectClass",
		"objectGUID",
		"userAccountControl",
		"msDS-User-Account-Control-Computed",
		"pwdLastSet",
		"lockoutTime",
		"msDS-UserAccountDisabled",
		"ms-DS-UserPasswordNotRequired",
		"ms-DS-UserEncryptedTextPasswordAllowed",
		"msDS-UserDontExpirePassword",
	)
}

func InternalAccountControlIdentity(
	identity Identity,
	partition string,
	properties []string,
) ResolveIdentityOptions {
	target := IdentityTargetObject
	if identity.Form() == IdentityFormSID || identity.Form() == IdentityFormAccountName {
		target = IdentityTargetAccount
	}
	return ResolveIdentityOptions{
		Target:     target,
		Partition:  partition,
		Properties: InternalAccountControlProperties(properties),
	}
}

func InternalAccountControlClass(object Object, kind DirectoryType) error {
	if kind != DirectoryADDS && kind != DirectoryADLDS {
		return ErrUnsupportedDirectory
	}
	classes, state := object.Attribute("objectClass")
	if state != AttributePresent {
		return errors.Join(ErrAccountControlTarget, ErrAttributeUnavailable)
	}
	for _, class := range classes {
		if strings.EqualFold(string(class), "user") ||
			strings.EqualFold(string(class), "inetOrgPerson") ||
			(kind == DirectoryADLDS && strings.EqualFold(string(class), "msDS-BindableObject")) {
			return nil
		}
	}
	return ErrAccountControlTarget
}

func InternalDecodeAccountControl(object Object, kind DirectoryType) (AccountControlState, error) {
	state := AccountControlState{
		DistinguishedName: InternalObservedDistinguishedName(&object),
		Directory:         kind,
		Raw:               object,
	}
	if err := InternalAccountControlClass(object, kind); err != nil {
		return state, err
	}
	decoder := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	for attribute, destination := range map[string]**Flags32{"userAccountControl": &state.StoredFlags, "msDS-User-Account-Control-Computed": &state.ComputedFlags} {
		value := InternalDecodeScalar(&decoder, attribute, InternalParseDirectoryMask)
		if value != nil {
			flags := Flags32(*value)
			*destination = &flags
		}
	}
	for attribute, destination := range map[string]**FileTime{"pwdLastSet": &state.PasswordLastSet, "lockoutTime": &state.LockoutTime} {
		*destination = InternalDecodeScalar(&decoder, attribute, ParseFileTime)
	}
	fields := []struct {
		InternalMask        Flags32
		InternalInverse     bool
		InternalLds         string
		InternalDestination **bool
	}{
		{0x2, true, "msDS-UserAccountDisabled", &state.Enabled},
		{0x8, false, "", &state.HomeDirectoryRequired},
		{0x20, false, "ms-DS-UserPasswordNotRequired", &state.PasswordNotRequired},
		{
			0x80,
			false,
			"ms-DS-UserEncryptedTextPasswordAllowed",
			&state.AllowReversiblePasswordEncryption,
		},
		{0x10000, false, "msDS-UserDontExpirePassword", &state.PasswordNeverExpires},
		{0x20000, false, "", &state.MNSLogonAccount},
		{0x40000, false, "", &state.SmartcardLogonRequired},
		{0x80000, false, "", &state.TrustedForDelegation},
		{0x100000, false, "", &state.AccountNotDelegated},
		{0x200000, false, "", &state.UseDESKeyOnly},
		{0x400000, false, "", &state.DoesNotRequirePreAuth},
		{0x1000000, false, "", &state.TrustedToAuthForDelegation},
	}
	for _, field := range fields {
		if kind == DirectoryADDS && state.StoredFlags != nil {
			value := state.StoredFlags.Has(field.InternalMask) != field.InternalInverse
			*field.InternalDestination = &value
		} else if kind == DirectoryADLDS && field.InternalLds != "" {
			value := InternalDecodeScalar(&decoder, field.InternalLds, InternalParseLDAPBool)
			if value != nil {
				observed := *value != field.InternalInverse
				*field.InternalDestination = &observed
			}
		}
	}
	if state.ComputedFlags != nil {
		locked, expired := state.ComputedFlags.Has(0x10), state.ComputedFlags.Has(0x800000)
		state.LockedOut, state.PasswordExpired = &locked, &expired
	}
	return state, errors.Join(decoder.InternalErrors...)
}

func InternalValidateAccountControlPatch(patch AccountControlPatch) error {
	if patch.ChangePasswordAtLogon != nil && *patch.ChangePasswordAtLogon &&
		patch.PasswordNeverExpires != nil &&
		*patch.PasswordNeverExpires {
		return ErrInvalidAccountControl
	}
	return nil
}

func InternalAccountControlPatchEmpty(patch AccountControlPatch) bool {
	if patch.ChangePasswordAtLogon != nil {
		return false
	}
	for _, field := range InternalAccountFlagFields(patch) {
		if field.InternalValue != nil {
			return false
		}
	}
	return true
}

// accountControlChanges is shared with typed user/computer workflows. It only
// prepares one atomic Modify; the caller owns class checks, execution and
// readback. Missing required old values fail rather than being assumed false.
func InternalAccountControlChanges(
	object Object,
	kind DirectoryType,
	patch AccountControlPatch,
) (writes, verification []InternalLdapAttributeModification, err error) {
	if err := InternalValidateAccountControlPatch(patch); err != nil {
		return nil, nil, err
	}
	if kind != DirectoryADDS && kind != DirectoryADLDS {
		return nil, nil, ErrUnsupportedDirectory
	}
	flagChanges := false
	for _, field := range InternalAccountFlagFields(patch) {
		if field.InternalValue != nil {
			flagChanges = true
			if kind == DirectoryADLDS && field.InternalLdsAttribute == "" {
				return nil, nil, ErrAccountControlUnsupported
			}
		}
	}
	if patch.PasswordNeverExpires != nil && *patch.PasswordNeverExpires &&
		patch.ChangePasswordAtLogon == nil {
		// The reverse interaction also depends on existing state: enabling
		// never-expire must not silently override a required password change.
		// Only an explicit false ChangePasswordAtLogon supplies the -1 write
		// that clears that requirement. Omission or an invalid timestamp is
		// not evidence that no change is required.
		value, readErr := object.Values("pwdLastSet").Single()
		if readErr != nil {
			return nil, nil, readErr
		}
		ticks, readErr := value.Int64()
		if readErr != nil || ticks < 0 {
			return nil, nil, errors.Join(ErrInvalidValue, readErr)
		}
		if ticks == 0 {
			return nil, nil, ErrInvalidAccountControl
		}
	}
	var neverExpires bool
	if kind == DirectoryADDS &&
		(flagChanges || (patch.ChangePasswordAtLogon != nil && *patch.ChangePasswordAtLogon)) {
		old, readErr := object.Values("userAccountControl").Single()
		if readErr != nil {
			return nil, nil, readErr
		}
		flags, readErr := old.Flags32()
		if readErr != nil {
			return nil, nil, readErr
		}
		next := InternalAccountControlValues(flags, patch)
		neverExpires = next.Has(0x10000)
		if next != flags {
			writes = append(
				writes,
				InternalAccountConditionalValue(
					"userAccountControl",
					old.Bytes(),
					[]byte(next.LDAPString()),
				)...)
		}
		if flagChanges {
			verification = append(
				verification,
				InternalAccountValueVerification("userAccountControl", []byte(next.LDAPString())),
			)
		}
	}
	if kind == DirectoryADLDS {
		writes, verification, neverExpires, err = InternalAccountLDSChanges(object, patch)
		if err != nil {
			return nil, nil, err
		}
	}
	if patch.ChangePasswordAtLogon != nil {
		if *patch.ChangePasswordAtLogon && neverExpires {
			return nil, nil, ErrInvalidAccountControl
		}
		value := []byte("-1")
		if *patch.ChangePasswordAtLogon {
			value = []byte("0")
		}
		writes = append(writes, InternalAccountValueVerification("pwdLastSet", value))
		if *patch.ChangePasswordAtLogon {
			verification = append(
				verification,
				InternalAccountValueVerification("pwdLastSet", value),
			)
		}
	}
	return writes, verification, nil
}

func InternalAccountConditionalValue(
	attribute string,
	old, next []byte,
) []InternalLdapAttributeModification {
	return []InternalLdapAttributeModification{
		{InternalOperation: 1, InternalAttribute: attribute, InternalValues: [][]byte{old}},
		{InternalOperation: 0, InternalAttribute: attribute, InternalValues: [][]byte{next}},
	}
}

func InternalAccountValueVerification(
	attribute string,
	value []byte,
) InternalLdapAttributeModification {
	return InternalLdapAttributeModification{
		InternalOperation: 2,
		InternalAttribute: attribute,
		InternalValues:    [][]byte{value},
	}
}
