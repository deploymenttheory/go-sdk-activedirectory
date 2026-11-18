// Package rfc3961 provides encryption and checksum methods as specified in RFC 3961
package rfc3961

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto/common"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto/etype"
)

// DES3EncryptData encrypts the data provided using DES3 and methods specific to the etype provided.
func DES3EncryptData(key, data []byte, e etype.EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, nil, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}
	var padErr error
	data, padErr = common.ZeroPad(data, e.GetMessageBlockByteSize())
	if padErr != nil {
		return nil, nil, padErr
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating cipher: %w", err)
	}

	// RFC 3961: initial cipher state      All bits zero
	ivz := make([]byte, des.BlockSize)

	ct := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, ivz)
	mode.CryptBlocks(ct, data)
	return ct[len(ct)-e.GetMessageBlockByteSize():], ct, nil
}

// DES3EncryptMessage encrypts the message provided using DES3 and methods specific to the etype provided.
// The encrypted data is concatenated with its integrity hash to create an encrypted message.
func DES3EncryptMessage(key, message []byte, usage uint32, e etype.EType) ([]byte, []byte, error) {
	// confounder
	c := make([]byte, e.GetConfounderByteSize())
	_, err := rand.Read(c)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("could not generate random confounder: %w", err)
	}
	plainBytes := append([]byte(nil), c...)
	plainBytes = append(plainBytes, message...)
	plainBytes, _ = common.ZeroPad(plainBytes, e.GetMessageBlockByteSize())

	// Derive key for encryption from usage
	k := key
	if usage != 0 {
		k, err = e.DeriveKey(key, common.GetUsageKe(usage))
		if err != nil {
			return []byte{}, []byte{}, fmt.Errorf("error deriving key for encryption: %w", err)
		}
	}

	iv, b, err := e.EncryptData(k, plainBytes)
	if err != nil {
		return iv, b, fmt.Errorf("error encrypting data: %w", err)
	}

	// Generate and append integrity hash
	ih, err := common.GetIntegrityHash(plainBytes, key, usage, e)
	if err != nil {
		return iv, b, fmt.Errorf("error encrypting data: %w", err)
	}
	b = append(b, ih...)
	return iv, b, nil
}

// DES3DecryptData decrypts the data provided using DES3 and methods specific to the etype provided.
func DES3DecryptData(key, data []byte, e etype.EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	if len(data) < des.BlockSize || len(data)%des.BlockSize != 0 {
		return []byte{}, errors.New("ciphertext is not a multiple of the block size")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return []byte{}, fmt.Errorf("error creating cipher: %w", err)
	}
	pt := make([]byte, len(data))
	ivz := make([]byte, des.BlockSize)
	mode := cipher.NewCBCDecrypter(block, ivz)
	mode.CryptBlocks(pt, data)
	return pt, nil
}

// DES3DecryptMessage decrypts the message provided using DES3 and methods specific to the etype provided.
// The integrity of the message is also verified.
func DES3DecryptMessage(key, ciphertext []byte, usage uint32, e etype.EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() || len(ciphertext) < e.GetConfounderByteSize()+e.GetHMACBitLength()/8 {
		return nil, errors.New("invalid key or truncated ciphertext")
	}
	// Derive the key
	k, err := e.DeriveKey(key, common.GetUsageKe(usage))
	if err != nil {
		return nil, fmt.Errorf("error deriving key: %w", err)
	}
	// Strip off the checksum from the end
	b, err := e.DecryptData(k, ciphertext[:len(ciphertext)-e.GetHMACBitLength()/8])
	if err != nil {
		return nil, fmt.Errorf("error decrypting: %w", err)
	}
	// Verify checksum
	if !e.VerifyIntegrity(key, ciphertext, b, usage) {
		return nil, errors.New("error decrypting: integrity verification failed")
	}
	// Remove the confounder bytes
	if len(b) < e.GetConfounderByteSize() {
		return nil, errors.New("truncated confounder")
	}
	return b[e.GetConfounderByteSize():], nil
}

// VerifyIntegrity verifies the integrity of cipertext bytes ct.
func VerifyIntegrity(key, ct, pt []byte, usage uint32, etype etype.EType) bool {
	if len(key) != etype.GetKeyByteSize() || len(ct) < etype.GetConfounderByteSize()+etype.GetHMACBitLength()/8 {
		return false
	}
	h := make([]byte, etype.GetHMACBitLength()/8)
	copy(h, ct[len(ct)-etype.GetHMACBitLength()/8:])
	expectedMAC, err := common.GetIntegrityHash(pt, key, usage, etype)
	return err == nil && hmac.Equal(h, expectedMAC)
}
