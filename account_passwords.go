package activedirectory

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	ErrInvalidPasswordRequest = errors.New("password request requires explicit valid UTF-8 password bytes without NUL")
	ErrPasswordProtection     = errors.New("password operation requires verified encryption of at least 128 bits")
	ErrPasswordTarget         = errors.New("password operation requires a user or inetOrgPerson account on a writable LDAP endpoint")
	ErrPasswordAccess         = errors.New("password operation access denied")
	ErrPasswordCredential     = errors.New("password operation credential rejected")
	ErrPasswordConstraint     = errors.New("password operation rejected by directory constraints or password policy")
	ErrPasswordUncertain      = errors.New("password operation outcome is unknown; reconcile before another write")
)

// PasswordChangeRequest requests one delete-old/add-new unicodePwd Modify.
// Passwords are caller-owned UTF-8, must not be mutated during the call, and
// are never retained in Client or Result. Nil means omitted and is rejected;
// an explicit empty slice requests an empty password, subject to server policy.
// The caller clears its own buffers. Go/Windows copies cannot be guaranteed wiped.
type PasswordChangeRequest struct {
	Identity    Identity
	Partition   string
	OldPassword []byte `json:"-"`
	NewPassword []byte `json:"-"`
}

// PasswordResetRequest requests an administrative unicodePwd replacement,
// without an old password. The server enforces force-change-password rights.
type PasswordResetRequest struct {
	Identity    Identity
	Partition   string
	NewPassword []byte `json:"-"`
}

func (PasswordChangeRequest) String() string               { return "PasswordChangeRequest{redacted}" }
func (PasswordChangeRequest) GoString() string             { return "PasswordChangeRequest{redacted}" }
func (PasswordChangeRequest) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (PasswordChangeRequest) MarshalText() ([]byte, error) {
	return []byte("PasswordChangeRequest{redacted}"), nil
}
func (PasswordResetRequest) String() string               { return "PasswordResetRequest{redacted}" }
func (PasswordResetRequest) GoString() string             { return "PasswordResetRequest{redacted}" }
func (PasswordResetRequest) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (PasswordResetRequest) MarshalText() ([]byte, error) {
	return []byte("PasswordResetRequest{redacted}"), nil
}

// PasswordProtection describes measured protection, not a port-based inference.
// TransportLDAP means SASL confidentiality with an effective key >=128 bits.
type PasswordProtection struct {
	Transport  Transport
	CipherBits uint32
}

// PasswordResult reports one native write attempt. Accepted means the server
// acknowledged the password operation; no secret readback or test login is
// attempted, and acceptance does not prove replication or future login success.
type PasswordResult struct {
	Source     Endpoint
	Partition  string
	TargetDN   string
	TargetGUID *GUID
	Protection PasswordProtection
	State      ObjectWriteState
}

type passwordSession interface {
	ldapWriteSession
	passwordProtection(context.Context, Transport) (PasswordProtection, error)
}

// ChangeAccountPassword changes a known old password to a new one in one
// protected Modify. It never falls back to an administrator reset or retries.
func (c *Client) ChangeAccountPassword(ctx context.Context, request PasswordChangeRequest) (PasswordResult, error) {
	if err := validatePasswordBytes(request.OldPassword); err != nil {
		return PasswordResult{}, err
	}
	if err := validatePasswordBytes(request.NewPassword); err != nil {
		return PasswordResult{}, err
	}
	return c.accountPassword(ctx, request.Identity, request.Partition, request.OldPassword, request.NewPassword, true)
}

// ResetAccountPassword resets a password without knowing the old password.
// It submits no additional account-flag or pwdLastSet modifications. The
// server's password processing controls timestamps and other derived state.
func (c *Client) ResetAccountPassword(ctx context.Context, request PasswordResetRequest) (PasswordResult, error) {
	if err := validatePasswordBytes(request.NewPassword); err != nil {
		return PasswordResult{}, err
	}
	return c.accountPassword(ctx, request.Identity, request.Partition, nil, request.NewPassword, false)
}

func validatePasswordBytes(value []byte) error {
	if value == nil || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 || utf16Units(value) > (math.MaxUint32-4)/2 {
		return ErrInvalidPasswordRequest
	}
	return nil
}

func (c *Client) accountPassword(ctx context.Context, account Identity, partition string, oldPassword, newPassword []byte, change bool) (PasswordResult, error) {
	var result PasswordResult
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	options := ResolveIdentityOptions{Partition: partition, Properties: []string{"objectGUID", "objectClass"}}
	// SID/account-name resolution is supported only for AD DS; DN/GUID also
	// address applicable AD LDS user classes without assuming objectSid exists.
	if account.Form() == IdentityFormSID || account.Form() == IdentityFormAccountName {
		options.Target = IdentityTargetAccount
	}
	if err := validateIdentityOperation(account, options); err != nil {
		return result, err
	}
	result.Source = c.config.Endpoint
	err := c.read(ctx, func(ctx context.Context) error {
		session, ok := c.session.(passwordSession)
		if !ok {
			return errors.Join(ErrPasswordProtection, ErrUnsupported)
		}
		protection, err := session.passwordProtection(ctx, c.config.Transport)
		if err != nil {
			return errors.Join(ErrPasswordProtection, err)
		}
		result.Protection = protection
		if protection.Transport != c.config.Transport || protection.CipherBits < 128 {
			return ErrPasswordProtection
		}
		root, err := readIdentityRoot(ctx, session)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == DirectoryADDS && (c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269) {
			return ErrPasswordTarget
		}
		if root.Capabilities().Type == DirectoryADDS {
			if root.DSServiceName == nil {
				return errors.Join(ErrPasswordTarget, ErrIncompleteResult)
			}
			if _, err := parseIdentityDN(*root.DSServiceName); err != nil {
				return errors.Join(ErrPasswordTarget, ErrInvalidResult)
			}
			attributes, err := session.baseObject(ctx, *root.DSServiceName, []string{"msDS-isRODC"})
			if err != nil {
				return err
			}
			decoder := rootDSEDecoder{attributes: attributes}
			readOnly := decodeScalar(&decoder, "msDS-isRODC", parseLDAPBool)
			if len(decoder.errors) != 0 {
				return errors.Join(decoder.errors...)
			}
			if readOnly == nil {
				return errors.Join(ErrPasswordTarget, ErrIncompleteResult)
			}
			if *readOnly {
				return ErrPasswordTarget
			}
		}
		resolved, err := resolveIdentitySession(ctx, session, c.config, root, account, options)
		result.Partition = resolved.Partition
		if err != nil {
			return err
		}
		result.TargetDN = resolved.Object.DistinguishedName
		classes, state := resolved.Object.Attribute("objectClass")
		if state != AttributePresent {
			return errors.Join(ErrPasswordTarget, ErrIncompleteResult)
		}
		eligible := false
		for _, class := range classes {
			if strings.EqualFold(string(class), "user") || strings.EqualFold(string(class), "inetOrgPerson") {
				eligible = true
			}
		}
		if !eligible {
			return ErrPasswordTarget
		}
		value, err := resolved.Object.Values("objectGUID").Single()
		if err != nil {
			return errors.Join(ErrInvalidResult, err)
		}
		guid, err := value.GUID()
		if err != nil {
			return errors.Join(ErrInvalidResult, err)
		}
		result.TargetGUID = &guid
		// Check protection immediately before exposing encoded passwords to
		// native request construction; never infer it from the chosen port.
		protection, err = session.passwordProtection(ctx, c.config.Transport)
		if err != nil {
			return errors.Join(ErrPasswordProtection, err)
		}
		result.Protection = protection
		if protection.Transport != c.config.Transport || protection.CipherBits < 128 {
			return ErrPasswordProtection
		}
		if err := context.Cause(ctx); err != nil {
			return err
		}
		newValue := quotedPasswordUTF16(newPassword)
		defer erasePasswordBuffer(newValue)
		mods := []ldapAttributeModification{{operation: 2, attribute: "unicodePwd", values: [][]byte{newValue}}}
		if change {
			oldValue := quotedPasswordUTF16(oldPassword)
			defer erasePasswordBuffer(oldValue)
			mods = []ldapAttributeModification{{operation: 1, attribute: "unicodePwd", values: [][]byte{oldValue}}, {operation: 0, attribute: "unicodePwd", values: [][]byte{newValue}}}
		}
		attempt := session.ldapWrite(ctx, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(guid), modifications: mods})
		switch attempt.State {
		case ldapWriteAccepted:
			result.State = ObjectWriteAccepted
		case ldapWriteRejected:
			result.State = ObjectWriteRejected
		case ldapWriteUncertain:
			result.State = ObjectWriteUncertain
		}
		if result.State == ObjectWriteUncertain {
			return errors.Join(ErrPasswordUncertain, attempt.Err)
		}
		if attempt.Err != nil {
			return attempt.Err
		}
		if result.State != ObjectWriteAccepted {
			return ErrInvalidResult
		}
		return nil
	})
	return result, classifyPasswordError(err)
}

// WinLDAP supplies the BER OCTET STRING wrapper. These are only the quoted
// UTF-16LE value octets: adding another BER wrapper would encode the wrong pwd.
func quotedPasswordUTF16(value []byte) []byte {
	encoded := make([]byte, 0, int(utf16Units(value))*2+4)
	encoded = binary.LittleEndian.AppendUint16(encoded, '"')
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r <= 0xffff {
			encoded = binary.LittleEndian.AppendUint16(encoded, uint16(r))
		} else {
			high, low := utf16.EncodeRune(r)
			encoded = binary.LittleEndian.AppendUint16(encoded, uint16(high))
			encoded = binary.LittleEndian.AppendUint16(encoded, uint16(low))
		}
		value = value[size:]
	}
	return binary.LittleEndian.AppendUint16(encoded, '"')
}

func erasePasswordBuffer(value []byte) { clear(value); runtime.KeepAlive(value) }

func classifyPasswordError(err error) error {
	if errors.Is(err, errLDAPWriteUncertain) {
		err = errors.Join(ErrPasswordUncertain, err)
	}
	var native *LDAPError
	if errors.As(err, &native) {
		switch native.Code {
		case 49:
			return errors.Join(ErrPasswordCredential, err)
		case 50:
			return errors.Join(ErrPasswordAccess, err)
		case 19:
			return errors.Join(ErrPasswordConstraint, err)
		case 8, 13:
			return errors.Join(ErrPasswordProtection, err)
		}
	}
	return err
}

// Keep error messages independent of all password contents and do not parse
// localized server diagnostic prose into speculative policy/credential causes.
var _ fmt.Stringer = PasswordChangeRequest{}
