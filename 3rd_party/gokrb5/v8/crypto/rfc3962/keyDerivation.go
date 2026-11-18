package rfc3962

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/jcmturner/gofork/x/crypto/pbkdf2"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto/etype"
)

const (
	// RFC3962 allows a bound of at least 50,000 to limit hostile KDC work.
	maxS2KIterations = 1_048_576
	s2kParamsZero    = 4294967296
)

// StringToKey returns a key derived from the string provided according to the definition in RFC 3961.
func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := S2KparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}
	return StringToKeyIter(secret, salt, i, e)
}

// StringToPBKDF2 generates an encryption key from a pass phrase and salt string using the PBKDF2 function from PKCS #5 v2.0
func StringToPBKDF2(secret, salt string, iterations int64, e etype.EType) []byte {
	return pbkdf2.Key64([]byte(secret), []byte(salt), iterations, int64(e.GetKeyByteSize()), e.GetHashFunc())
}

// StringToKeyIter returns a key derived from the string provided according to the definition in RFC 3961.
func StringToKeyIter(secret, salt string, iterations int64, e etype.EType) ([]byte, error) {
	if iterations <= 0 || iterations > maxS2KIterations {
		return nil, errors.New("string-to-key iteration count exceeds supported range")
	}
	tkey := e.RandomToKey(StringToPBKDF2(secret, salt, iterations, e))
	return e.DeriveKey(tkey, []byte("kerberos"))
}

// S2KparamsToItertions converts the string representation of iterations to an integer
func S2KparamsToItertions(s2kparams string) (int64, error) {
	// The s2kparams string should be hex string representing 4 bytes
	// The 4 bytes represent a number in big endian order
	// The zero encoding means 2^32 and is rejected by this implementation
	// along with other counts above the documented work bound; it is never reduced.
	var i uint32
	if len(s2kparams) != 8 {
		return int64(s2kParamsZero), errors.New("invalid s2kparams length")
	}
	b, err := hex.DecodeString(s2kparams)
	if err != nil {
		return int64(s2kParamsZero), errors.New("invalid s2kparams, cannot decode string to bytes")
	}
	i = binary.BigEndian.Uint32(b)
	if i == 0 || i > maxS2KIterations {
		return 0, errors.New("string-to-key iteration count exceeds supported range")
	}
	return int64(i), nil
}
