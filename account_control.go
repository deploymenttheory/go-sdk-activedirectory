package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalidAccountControl     = errors.New("invalid or conflicting account-control options")
	ErrAccountControlTarget      = errors.New("directory object is not a supported account")
	ErrAccountControlUnsupported = errors.New("account-control option is not supported by this directory")
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

type accountFlagField struct {
	value        *bool
	mask         Flags32
	inverse      bool
	ldsAttribute string
}

func accountFlagFields(p AccountControlPatch) []accountFlagField {
	return []accountFlagField{
		{p.Enabled, 0x2, true, "msDS-UserAccountDisabled"},
		{p.HomeDirectoryRequired, 0x8, false, ""},
		{p.PasswordNotRequired, 0x20, false, "ms-DS-UserPasswordNotRequired"},
		{p.AllowReversiblePasswordEncryption, 0x80, false, "ms-DS-UserEncryptedTextPasswordAllowed"},
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

func accountControlValues(flags Flags32, patch AccountControlPatch) Flags32 {
	for _, field := range accountFlagFields(patch) {
		if field.value != nil {
			flags = flags.With(field.mask, *field.value != field.inverse)
		}
	}
	return flags
}

func accountControlProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectClass", "objectGUID", "userAccountControl", "msDS-User-Account-Control-Computed", "pwdLastSet", "lockoutTime", "msDS-UserAccountDisabled", "ms-DS-UserPasswordNotRequired", "ms-DS-UserEncryptedTextPasswordAllowed", "msDS-UserDontExpirePassword")
}

func accountControlIdentity(identity Identity, partition string, properties []string) ResolveIdentityOptions {
	target := IdentityTargetObject
	if identity.Form() == IdentityFormSID || identity.Form() == IdentityFormAccountName {
		target = IdentityTargetAccount
	}
	return ResolveIdentityOptions{Target: target, Partition: partition, Properties: accountControlProperties(properties)}
}

func accountControlClass(object Object, kind DirectoryType) error {
	if kind != DirectoryADDS && kind != DirectoryADLDS {
		return ErrUnsupportedDirectory
	}
	classes, state := object.Attribute("objectClass")
	if state != AttributePresent {
		return errors.Join(ErrAccountControlTarget, ErrAttributeUnavailable)
	}
	for _, class := range classes {
		if strings.EqualFold(string(class), "user") || strings.EqualFold(string(class), "inetOrgPerson") || (kind == DirectoryADLDS && strings.EqualFold(string(class), "msDS-BindableObject")) {
			return nil
		}
	}
	return ErrAccountControlTarget
}

func decodeAccountControl(object Object, kind DirectoryType) (AccountControlState, error) {
	state := AccountControlState{DistinguishedName: object.DistinguishedName, Directory: kind, Raw: object}
	if err := accountControlClass(object, kind); err != nil {
		return state, err
	}
	decoder := rootDSEDecoder{attributes: object.Attributes}
	for attribute, destination := range map[string]**Flags32{"userAccountControl": &state.StoredFlags, "msDS-User-Account-Control-Computed": &state.ComputedFlags} {
		value := decodeScalar(&decoder, attribute, parseDirectoryMask)
		if value != nil {
			flags := Flags32(*value)
			*destination = &flags
		}
	}
	for attribute, destination := range map[string]**FileTime{"pwdLastSet": &state.PasswordLastSet, "lockoutTime": &state.LockoutTime} {
		*destination = decodeScalar(&decoder, attribute, ParseFileTime)
	}
	fields := []struct {
		mask        Flags32
		inverse     bool
		lds         string
		destination **bool
	}{
		{0x2, true, "msDS-UserAccountDisabled", &state.Enabled},
		{0x8, false, "", &state.HomeDirectoryRequired},
		{0x20, false, "ms-DS-UserPasswordNotRequired", &state.PasswordNotRequired},
		{0x80, false, "ms-DS-UserEncryptedTextPasswordAllowed", &state.AllowReversiblePasswordEncryption},
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
			value := state.StoredFlags.Has(field.mask) != field.inverse
			*field.destination = &value
		} else if kind == DirectoryADLDS && field.lds != "" {
			value := decodeScalar(&decoder, field.lds, parseLDAPBool)
			if value != nil {
				observed := *value != field.inverse
				*field.destination = &observed
			}
		}
	}
	if state.ComputedFlags != nil {
		locked, expired := state.ComputedFlags.Has(0x10), state.ComputedFlags.Has(0x800000)
		state.LockedOut, state.PasswordExpired = &locked, &expired
	}
	return state, errors.Join(decoder.errors...)
}

// AccountControl reads persisted options and the selected server's computed
// state under one client timeout. It does not infer lockout from old timestamps.
func (c *Client) AccountControl(ctx context.Context, identity Identity, options ResolveIdentityOptions) (AccountControlResult, error) {
	var result AccountControlResult
	if options.Target > IdentityTargetAccount {
		return result, ErrInvalidIdentity
	}
	options = accountControlIdentity(identity, options.Partition, options.Properties)
	if err := validateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if result.Observation.Object != nil {
			account, decodeErr := decodeAccountControl(*result.Observation.Object, root.Capabilities().Type)
			result.Account = &account
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

func validateAccountControlPatch(patch AccountControlPatch) error {
	if patch.ChangePasswordAtLogon != nil && *patch.ChangePasswordAtLogon && patch.PasswordNeverExpires != nil && *patch.PasswordNeverExpires {
		return ErrInvalidAccountControl
	}
	return nil
}

func accountControlPatchEmpty(patch AccountControlPatch) bool {
	if patch.ChangePasswordAtLogon != nil {
		return false
	}
	for _, field := range accountFlagFields(patch) {
		if field.value != nil {
			return false
		}
	}
	return true
}

// accountControlChanges is shared with typed user/computer workflows. It only
// prepares one atomic Modify; the caller owns class checks, execution and
// readback. Missing required old values fail rather than being assumed false.
func accountControlChanges(object Object, kind DirectoryType, patch AccountControlPatch) (writes, verification []ldapAttributeModification, err error) {
	if err := validateAccountControlPatch(patch); err != nil {
		return nil, nil, err
	}
	if kind != DirectoryADDS && kind != DirectoryADLDS {
		return nil, nil, ErrUnsupportedDirectory
	}
	flagChanges := false
	for _, field := range accountFlagFields(patch) {
		if field.value != nil {
			flagChanges = true
			if kind == DirectoryADLDS && field.ldsAttribute == "" {
				return nil, nil, ErrAccountControlUnsupported
			}
		}
	}
	var neverExpires bool
	if kind == DirectoryADDS && (flagChanges || (patch.ChangePasswordAtLogon != nil && *patch.ChangePasswordAtLogon)) {
		old, readErr := object.Values("userAccountControl").Single()
		if readErr != nil {
			return nil, nil, readErr
		}
		flags, readErr := old.Flags32()
		if readErr != nil {
			return nil, nil, readErr
		}
		next := accountControlValues(flags, patch)
		neverExpires = next.Has(0x10000)
		if next != flags {
			writes = append(writes, accountConditionalValue("userAccountControl", old.Bytes(), []byte(next.LDAPString()))...)
		}
		if flagChanges {
			verification = append(verification, accountValueVerification("userAccountControl", []byte(next.LDAPString())))
		}
	}
	if kind == DirectoryADLDS {
		for _, field := range accountFlagFields(patch) {
			if field.value == nil {
				continue
			}
			next := *field.value != field.inverse
			text := []byte("FALSE")
			if next {
				text = []byte("TRUE")
			}
			// Each LDS option owns a separate boolean attribute, so assignment
			// cannot overwrite unrelated flag bits. Omission may be unset or
			// hidden: write the requested value without inventing an old false.
			unchanged := false
			oldValues := object.Values(field.ldsAttribute)
			if oldValues.State == AttributePresent {
				old, readErr := oldValues.Single()
				if readErr != nil {
					return nil, nil, readErr
				}
				value, readErr := old.Bool()
				if readErr != nil {
					return nil, nil, readErr
				}
				unchanged = value == next
			}
			if !unchanged {
				writes = append(writes, accountValueVerification(field.ldsAttribute, text))
			}
			verification = append(verification, accountValueVerification(field.ldsAttribute, text))
		}
		if patch.ChangePasswordAtLogon != nil && *patch.ChangePasswordAtLogon {
			if patch.PasswordNeverExpires != nil {
				neverExpires = *patch.PasswordNeverExpires
			} else {
				value, readErr := object.Values("msDS-UserDontExpirePassword").Single()
				if readErr != nil {
					return nil, nil, readErr
				}
				neverExpires, readErr = value.Bool()
				if readErr != nil {
					return nil, nil, readErr
				}
			}
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
		writes = append(writes, accountValueVerification("pwdLastSet", value))
		if *patch.ChangePasswordAtLogon {
			verification = append(verification, accountValueVerification("pwdLastSet", value))
		}
	}
	return writes, verification, nil
}

func accountConditionalValue(attribute string, old, next []byte) []ldapAttributeModification {
	return []ldapAttributeModification{{operation: 1, attribute: attribute, values: [][]byte{old}}, {operation: 0, attribute: attribute, values: [][]byte{next}}}
}
func accountValueVerification(attribute string, value []byte) ldapAttributeModification {
	return ldapAttributeModification{operation: 2, attribute: attribute, values: [][]byte{value}}
}

// UpdateAccountControl applies one atomic Modify using exact-old value removal
// for stored flags. It does not write computed lockout/password-expiry bits.
func (c *Client) UpdateAccountControl(ctx context.Context, request AccountControlRequest) (AccountControlMutationResult, error) {
	if accountControlPatchEmpty(request.Patch) {
		return AccountControlMutationResult{}, ErrInvalidAccountControl
	}
	if err := validateAccountControlPatch(request.Patch); err != nil {
		return AccountControlMutationResult{}, err
	}
	return c.mutateAccountControl(ctx, request.Identity, request.Options, request.Patch, false)
}

func (c *Client) EnableAccount(ctx context.Context, identity Identity, options ObjectMutationOptions) (AccountControlMutationResult, error) {
	enabled := true
	return c.UpdateAccountControl(ctx, AccountControlRequest{Identity: identity, Options: options, Patch: AccountControlPatch{Enabled: &enabled}})
}
func (c *Client) DisableAccount(ctx context.Context, identity Identity, options ObjectMutationOptions) (AccountControlMutationResult, error) {
	enabled := false
	return c.UpdateAccountControl(ctx, AccountControlRequest{Identity: identity, Options: options, Patch: AccountControlPatch{Enabled: &enabled}})
}

// UnlockAccount writes lockoutTime=0 on the selected server. It does not alter
// disabled status, manufacture a computed flag, or prove forest-wide convergence.
func (c *Client) UnlockAccount(ctx context.Context, identity Identity, options ObjectMutationOptions) (AccountControlMutationResult, error) {
	return c.mutateAccountControl(ctx, identity, options, AccountControlPatch{}, true)
}

func (c *Client) mutateAccountControl(ctx context.Context, identity Identity, options ObjectMutationOptions, patch AccountControlPatch, unlock bool) (AccountControlMutationResult, error) {
	resolve := accountControlIdentity(identity, options.Partition, options.Properties)
	if err := validateIdentityOperation(identity, resolve); err != nil {
		return AccountControlMutationResult{}, err
	}
	for _, property := range options.Properties {
		if property == "1.1" {
			return AccountControlMutationResult{}, ErrInvalidProperty
		}
	}
	options.Properties = accountControlProperties(options.Properties)
	var kind DirectoryType
	mutation, err := c.objectMutationIdentity(ctx, identity, options, resolve, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		kind = root.Capabilities().Type
		if err := accountControlClass(*observed.Object, kind); err != nil {
			return err
		}
		writes, verification, err := accountControlChanges(*observed.Object, kind, patch)
		if err != nil {
			return err
		}
		if unlock {
			writes = []ldapAttributeModification{accountValueVerification("lockoutTime", []byte("0"))}
			verification = slices.Clone(writes)
		}
		if len(writes) == 0 {
			if options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			result.After, result.ReadbackComplete = observed.Object, observed.Complete
			return verifyObjectWrite(result, verification, "")
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: writes, controls: controls}, false, result); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(options, writes), false); err != nil {
			return err
		}
		if patch.ChangePasswordAtLogon != nil && !*patch.ChangePasswordAtLogon {
			// -1 is a write instruction, never the readback value. A positive
			// server timestamp confirms the requested state, not exact timing.
			value, err := result.After.Values("pwdLastSet").Single()
			if err != nil {
				return errors.Join(ErrObjectVerification, err)
			}
			ticks, err := value.Int64()
			if err != nil || ticks <= 0 {
				return errors.Join(ErrObjectVerification, err)
			}
		}
		return verifyObjectWrite(result, verification, "")
	})
	result := AccountControlMutationResult{Mutation: mutation}
	if mutation.After != nil {
		state, decodeErr := decodeAccountControl(*mutation.After, kind)
		result.Account = &state
		err = errors.Join(err, decodeErr)
	}
	return result, err
}
