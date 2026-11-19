package crypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"

	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto/common"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto/etype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
)

const (
	CFXFlagSendByAcceptor = uint8(0x01)
	CFXFlagSealed         = uint8(0x02)
	CFXFlagAcceptorSubKey = uint8(0x04)
)

// AESCTSHMACSHA1 represents the integrity/confidentiality routines
// for the aes128-cts-hmac-sha1 and aes256-cts-hmac-sha1.
type AESCTSHMACSHA1 struct {
	mu      sync.Mutex
	setting CipherSetting
	retired bool
}

func NewAESCipher(ctx context.Context, setting CipherSetting) (Cipher, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("create AES record cipher: %w", err)
	}
	if setting.Type == nil || (setting.Type.GetETypeID() != 17 && setting.Type.GetETypeID() != 18) {
		return nil, ErrUnsupportedProfile
	}
	canonical, err := krbcrypto.GetEtype(setting.Type.GetETypeID())
	if err != nil {
		return nil, ErrUnsupportedProfile
	}
	setting.Type = canonical
	if setting.Key.KeyType != setting.Type.GetETypeID() || len(setting.Key.KeyValue) != setting.Type.GetKeyByteSize() {
		return nil, ErrInvalidKey
	}
	setting.Key.KeyValue = bytes.Clone(setting.Key.KeyValue)
	return &AESCTSHMACSHA1{setting: setting}, nil
}

// Destroy retires the copied record key after any in-flight operation finishes.
func (c *AESCTSHMACSHA1) Destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.setting.Key.KeyValue)
	c.setting.Key.KeyValue = nil
	c.retired = true
}

func (c *AESCTSHMACSHA1) ready(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return fmt.Errorf("check AES record state: %w", err)
	}
	if c.retired {
		return ErrRetiredContext
	}
	return nil
}

func (c *AESCTSHMACSHA1) checksumHash() (hash.Hash, error) {
	ckU := keyusage.GSSAPI_INITIATOR_SIGN
	if !c.setting.IsLocal {
		ckU = keyusage.GSSAPI_ACCEPTOR_SIGN
	}
	return c.newHash(common.GetUsageKc(uint32(ckU)))
}

func (c *AESCTSHMACSHA1) integrityHash() (hash.Hash, error) {
	ecU := keyusage.GSSAPI_INITIATOR_SEAL
	if !c.setting.IsLocal {
		ecU = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	return c.newHash(common.GetUsageKi(uint32(ecU)))
}

func (c *AESCTSHMACSHA1) newHash(usage []byte) (hash.Hash, error) {
	k, err := c.setting.Type.DeriveKey(c.setting.Key.KeyValue, usage)
	if err != nil {
		return nil, fmt.Errorf("unable to derive key for checksum: %w", err)
	}
	defer clear(k)
	return &SizedHash{Hash: hmac.New(c.setting.Type.GetHashFunc(), k), etype: c.setting.Type}, nil
}

func (c *AESCTSHMACSHA1) flags() uint8 {
	flags := uint8(0)
	if !c.setting.IsLocal {
		flags |= CFXFlagSendByAcceptor
	}
	if c.setting.IsSubKey {
		flags |= CFXFlagAcceptorSubKey
	}
	return flags
}

const (
	EC  = 16
	RRC = 28
)

func (c *AESCTSHMACSHA1) deriveEncryptionKey() ([]byte, error) {
	ecU := keyusage.GSSAPI_INITIATOR_SEAL
	if !c.setting.IsLocal {
		ecU = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	return c.setting.Type.DeriveKey(c.setting.Key.KeyValue, common.GetUsageKe(uint32(ecU)))
}

func (c *AESCTSHMACSHA1) Wrap(ctx context.Context, seqNum uint64, payload []byte, conf bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return nil, fmt.Errorf("finish AES record: %w", err)
	}
	if !conf {
		return nil, ErrUnsupportedProfile
	}
	if err := validateRecordBuffers([][]byte{payload}, [][]byte{payload}); err != nil {
		return nil, err
	}
	var forSeal [][]byte
	if conf {
		forSeal = [][]byte{payload}
	}

	b, err := c.wrap(ctx, seqNum, [][]byte{payload}, forSeal, false)
	if err != nil {
		return nil, fmt.Errorf("aes-cts-hmac-sha1: wrap: %w", err)
	}
	return b, nil
}

func (c *AESCTSHMACSHA1) WrapEx(ctx context.Context, seqNum uint64, forSign, forSeal [][]byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return nil, err
	}
	if err := validateRecordBuffers(forSign, forSeal); err != nil {
		return nil, err
	}
	b, err := c.wrap(ctx, seqNum, forSign, forSeal, true)
	if err != nil {
		return nil, fmt.Errorf("aes-cts-hmac-sha1: wrap_ex: %w", err)
	}
	return b, nil
}

func (c *AESCTSHMACSHA1) wrap(ctx context.Context, seqNum uint64, forSign, forSeal [][]byte, isEx bool) ([]byte, error) {
	eB, hdr := bytes.NewBuffer(nil), c.WrapHeader(ctx, seqNum)

	// gen confounder.
	confounder := make([]byte, c.setting.Type.GetConfounderByteSize())
	if _, err := rand.Read(confounder); err != nil {
		return nil, fmt.Errorf("read confounder: %w", err)
	}

	ec := EC

	if !isEx /* it's a Wrap call, compute EC according to RFC 4121, section 4.3.2. */ {
		sz, block := 0, c.setting.Type.GetMessageBlockByteSize()
		for _, b := range forSeal {
			sz += len(b)
		}
		if ec = (block - (sz % block)) % block; sz == 0 {
			ec = 16 // if the payload is empty, EC is 16 (the block size).
		}
	}

	// gen ec.
	ecB := bytes.Repeat([]byte{0xFF}, ec)
	// set ec value.
	binary.BigEndian.PutUint16(hdr[4:6], uint16(ec))

	iH, err := c.integrityHash()
	if err != nil {
		return nil, fmt.Errorf("make integrity hash: %w", err)
	}

	if err := writeHash(iH, confounder, forSign, ecB, hdr); err != nil {
		return nil, fmt.Errorf("write hash: %w", err)
	}

	key, err := c.deriveEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	defer clear(key)
	defer clear(confounder)
	defer func() { clear(eB.Bytes()) }()

	if err := writeHash(eB, confounder, forSeal, ecB, hdr); err != nil {
		return nil, fmt.Errorf("write encryption buffers: %w", err)
	}

	_, b, err := c.setting.Type.EncryptData(key, eB.Bytes())
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	b = Rotate(iH.Sum(b), ec+RRC)

	sgn := make([]byte, ec+RRC+len(confounder))
	b = b[copy(sgn, b):]
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("finish AES record: %w", err)
	}

	for i := range forSeal {
		b = b[copy(forSeal[i], b):]
	}

	// set rrc value.
	binary.BigEndian.PutUint16(hdr[6:8], RRC)

	return append(hdr, sgn...), nil
}

func (c *AESCTSHMACSHA1) Unwrap(ctx context.Context, seqNum uint64, payload []byte, sgn []byte) ([]byte, bool, error) {
	var err error

	if len(sgn) == 0 {
		if sgn, payload, err = c.ParseSignature(ctx, payload); err != nil {
			return nil, false, fmt.Errorf("aes-cts-hmac-sha1: unwrap: parse token: %w", err)
		}
	}

	ok, err := c.UnwrapEx(ctx, seqNum, [][]byte{payload}, [][]byte{payload}, sgn)
	if err != nil {
		return nil, false, fmt.Errorf("aes-cts-hmac-sha1: unwrap: %w", err)
	}
	return sgn, ok, nil
}

func (c *AESCTSHMACSHA1) UnwrapEx(ctx context.Context, seqNum uint64, forSign, forSeal [][]byte, sgn []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return false, err
	}
	if err := validateRecordBuffers(forSign, forSeal); err != nil {
		return false, err
	}
	ok, err := c.unwrapEx(ctx, seqNum, forSign, forSeal, sgn)
	if err != nil {
		return ok, fmt.Errorf("aes-cts-hmac-sha1: unwrap_ex: %w", err)
	}
	return ok, nil
}

// ParseSignature parses the header of the signature and returns the header and the remaining of the signature.
func (c *AESCTSHMACSHA1) ParseSignature(ctx context.Context, payload []byte) ([]byte, []byte, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, nil, fmt.Errorf("parse AES record signature: %w", err)
	}

	if len(payload) < 16 {
		return nil, nil, fmt.Errorf("%w: payload size %d < 16", ErrInvalidToken, len(payload))
	}

	rrc, ec := int(binary.BigEndian.Uint16(payload[6:])), int(binary.BigEndian.Uint16(payload[4:]))

	sgn := ec + rrc + 16 /* hdr */ + c.setting.Type.GetConfounderByteSize()
	if len(payload) < sgn {
		return nil, nil, fmt.Errorf("%w: payload size %d < %d", ErrInvalidToken, len(payload), sgn)
	}

	return payload[:sgn], payload[sgn:], nil
}

func (c *AESCTSHMACSHA1) unwrapEx(ctx context.Context, seqNum uint64, forSign, forSeal [][]byte, sgn []byte) (bool, error) {
	if len(sgn) < 16 {
		return false, ErrInvalidToken
	}
	hdr := bytes.Clone(sgn[:16])
	if hdr[0] != 5 || hdr[1] != 4 || hdr[2] != c.flags()|CFXFlagSealed || hdr[3] != 0xff || binary.BigEndian.Uint64(hdr[8:]) != seqNum {
		return false, ErrInvalidToken
	}
	rrc, ec := int(binary.BigEndian.Uint16(hdr[6:])), int(binary.BigEndian.Uint16(hdr[4:]))
	if rrc != RRC || ec == 0 || len(sgn) != ec+rrc+32 {
		return false, ErrInvalidToken
	}
	// Never modify the supplied authentication token, even when validation fails.
	binary.BigEndian.PutUint16(hdr[6:8], 0)
	eB := bytes.NewBuffer(nil)
	if err := writeHash(eB, sgn[16:], forSeal); err != nil {
		return false, fmt.Errorf("finish AES verification: %w", err)
	}
	rotated := Rotate(eB.Bytes(), -(rrc + ec))
	defer clear(rotated)
	if len(rotated) < 12+16+ec+16 {
		return false, ErrInvalidToken
	}
	ciphertext, checksum := rotated[:len(rotated)-12], rotated[len(rotated)-12:]
	key, err := c.deriveEncryptionKey()
	if err != nil {
		return false, fmt.Errorf("derive key: %w", err)
	}
	defer clear(key)
	plain, err := c.setting.Type.DecryptData(key, ciphertext)
	if err != nil {
		return false, fmt.Errorf("%w: decrypt: %w", ErrInvalidToken, err)
	}
	defer clear(plain)
	if len(plain) != len(ciphertext) || !bytes.Equal(plain[len(plain)-16:], hdr) {
		return false, ErrInvalidToken
	}
	// The MAC is over decrypted buffers in their original signing order, with
	// signed-only headers left in place. Publish no plaintext until it verifies.
	decrypted := make([][]byte, len(forSeal))
	offset := 16
	for i, sealed := range forSeal {
		decrypted[i] = plain[offset : offset+len(sealed)]
		offset += len(sealed)
	}
	iH, err := c.integrityHash()
	if err != nil {
		return false, fmt.Errorf("make integrity hash: %w", err)
	}
	if err := writeHash(iH, plain[:16]); err != nil {
		return false, err
	}
	for _, signed := range forSign {
		part := signed
		for i, sealed := range forSeal {
			if sameBuffer(signed, sealed) {
				part = decrypted[i]
				break
			}
		}
		if err := writeHash(iH, part); err != nil {
			return false, err
		}
	}
	if err := writeHash(iH, plain[offset:]); err != nil {
		return false, err
	}
	if !hmac.Equal(iH.Sum(nil), checksum) {
		return false, ErrInvalidToken
	}
	if err := context.Cause(ctx); err != nil {
		return false, fmt.Errorf("finish AES verification: %w", err)
	}
	for i := range forSeal {
		copy(forSeal[i], decrypted[i])
	}
	return true, nil
}

func (c *AESCTSHMACSHA1) MakeSignature(ctx context.Context, seqNum uint64, forSgn [][]byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ready(ctx); err != nil {
		return nil, err
	}
	if err := validateRecordBuffers(forSgn, nil); err != nil {
		return nil, err
	}
	b, err := c.makeSignature(ctx, seqNum, forSgn)
	if err != nil {
		return nil, fmt.Errorf("aes-cts-hmac-sha1: make signature: %w", err)
	}
	return b, nil
}

func (c *AESCTSHMACSHA1) makeSignature(ctx context.Context, seqNum uint64, forSgn [][]byte) ([]byte, error) {
	hdr := c.MICHeader(ctx, seqNum)

	// checksum hash.
	ckH, err := c.checksumHash()
	if err != nil {
		return nil, err
	}

	if err := writeHash(ckH, forSgn, hdr); err != nil {
		return nil, fmt.Errorf("write hash: %w", err)
	}

	return append(hdr, ckH.Sum(nil)...), nil
}

func (c *AESCTSHMACSHA1) Size(ctx context.Context, conf bool) int {
	sz := (16 /* hdr */ + 12 /* cksum */)
	if conf {
		sz += (16 /* confounder */ + 16 /* E"header" */ + 16 /* ec */)
	}
	return sz
}

func (c *AESCTSHMACSHA1) WrapHeader(ctx context.Context, seqNum uint64) []byte {
	hdr := make([]byte, 16)
	// token_type 0x05 0x04
	hdr[0] = 0x05
	hdr[1] = 0x04
	// flags
	hdr[2] = c.flags() | CFXFlagSealed
	// filler.
	hdr[3] = 0xff
	// sequence_number.
	binary.BigEndian.PutUint64(hdr[8:], uint64(seqNum))
	return hdr
}

func (c *AESCTSHMACSHA1) MICHeader(ctx context.Context, seqNum uint64) []byte {
	hdr := make([]byte, 16)
	// token_type 0x04 0x04
	hdr[0] = 0x04
	hdr[1] = 0x04
	// flags
	hdr[2] = c.flags()
	// filler.
	hdr[3] = 0xff
	hdr[4] = 0xff
	hdr[5] = 0xff
	hdr[6] = 0xff
	hdr[7] = 0xff
	// sequence_number.
	binary.BigEndian.PutUint64(hdr[8:], uint64(seqNum))
	return hdr
}

type SizedHash struct {
	hash.Hash
	etype etype.EType
}

func (h *SizedHash) Sum(b []byte) []byte {
	return h.Hash.Sum(b)[:len(b)+h.etype.GetHMACBitLength()/8]
}

// Rotate function rotates the buffer over rotation point `rc`, ie
// out = in[rc:] + in[:rc].
func Rotate(b []byte, rc int) []byte {
	if len(b) == 0 {
		return nil
	}
	out, left := make([]byte, len(b)), (len(b)-rc%len(b))%len(b)
	copy(out[copy(out, b[left:]):], b[:left])
	return out
}
