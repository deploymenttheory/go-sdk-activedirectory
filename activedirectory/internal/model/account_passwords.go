package model

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	ErrInvalidPasswordRequest = errors.New(
		"password request requires explicit valid UTF-8 password bytes without NUL",
	)
	ErrPasswordProtection = errors.New(
		"password operation requires verified encryption of at least 128 bits",
	)
	ErrPasswordTarget = errors.New(
		"password operation requires a user or inetOrgPerson account on a writable LDAP endpoint",
	)
	ErrPasswordAccess     = errors.New("password operation access denied")
	ErrPasswordCredential = errors.New("password operation credential rejected")
	ErrPasswordConstraint = errors.New(
		"password operation rejected by directory constraints or password policy",
	)
	ErrPasswordUncertain = errors.New(
		"password operation outcome is unknown; reconcile before another write",
	)
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

func (PasswordChangeRequest) String() string { return "PasswordChangeRequest{redacted}" }

func (PasswordChangeRequest) GoString() string { return "PasswordChangeRequest{redacted}" }

func (PasswordChangeRequest) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (PasswordChangeRequest) MarshalText() ([]byte, error) {
	return []byte("PasswordChangeRequest{redacted}"), nil
}

func (PasswordResetRequest) String() string { return "PasswordResetRequest{redacted}" }

func (PasswordResetRequest) GoString() string { return "PasswordResetRequest{redacted}" }

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

type InternalPasswordSession interface {
	InternalLdapWriteSession
	InternalPasswordProtection(context.Context, Transport) (PasswordProtection, error)
}

func InternalValidatePasswordBytes(value []byte) error {
	if value == nil || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 ||
		InternalUtf16Units(value) > (math.MaxUint32-4)/2 {
		return ErrInvalidPasswordRequest
	}
	return nil
}

// WinLDAP supplies the BER OCTET STRING wrapper. These are only the quoted
// UTF-16LE value octets: adding another BER wrapper would encode the wrong pwd.
func InternalQuotedPasswordUTF16(value []byte) []byte {
	encoded := make([]byte, 0, int(InternalUtf16Units(value))*2+4)
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

func InternalErasePasswordBuffer(value []byte) { clear(value); runtime.KeepAlive(value) }

func InternalClassifyPasswordError(err error) error {
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
