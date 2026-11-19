package crypto

import (
	"context"
	"errors"
	"fmt"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto/etype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/etypeID"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

var (
	ErrUnsupportedProfile = errors.New("unsupported RPC Kerberos record profile")
	ErrInvalidKey         = errors.New("invalid RPC Kerberos record key")
	ErrInvalidToken       = errors.New("invalid RPC Kerberos record")
	ErrRetiredContext     = errors.New("retired RPC Kerberos record context")
	ErrMessageTooLarge    = errors.New("RPC Kerberos record exceeds limit")
)

type Cipher interface {
	Destroy()
	Wrap(context.Context, uint64, []byte, bool) ([]byte, error)
	WrapEx(context.Context, uint64, [][]byte, [][]byte) ([]byte, error)
	UnwrapEx(context.Context, uint64, [][]byte, [][]byte, []byte) (bool, error)
	Unwrap(context.Context, uint64, []byte, []byte) ([]byte, bool, error)
	ParseSignature(context.Context, []byte) ([]byte, []byte, error)
	MakeSignature(context.Context, uint64, [][]byte) ([]byte, error)
	Size(context.Context, bool) int
}

type CipherSetting struct {
	// Key is an encryption key for the cipher.
	Key types.EncryptionKey
	// Type is an encryption type for the cipher.
	Type etype.EType
	// IsSubKey is true if the key is a subkey.
	IsSubKey bool
	// IsLocal is true if cipher is an initiator's cipher.
	IsLocal bool
	// DCEStyle is true if the cipher is DCE style.
	DCEStyle bool
}

func NewCipher(ctx context.Context, setting CipherSetting) (Cipher, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("create Kerberos record cipher: %w", err)
	}
	if setting.Type == nil {
		return nil, ErrUnsupportedProfile
	}
	switch setting.Type.GetETypeID() {
	case etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96:
		return NewAESCipher(ctx, setting)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedProfile, setting.Type.GetETypeID())
	}
}
