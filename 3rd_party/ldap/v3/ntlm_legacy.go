package ldap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"unicode/utf16"

	// #nosec G506 -- Retained upstream NTLM hash codec, unavailable through SDK portable authentication.
	"golang.org/x/crypto/md4" //nolint:staticcheck // NTLM compatibility requires this deprecated primitive.
)

func ntHash(pass string) string {
	runes := utf16.Encode([]rune(pass))
	b := bytes.Buffer{}
	_ = binary.Write(&b, binary.LittleEndian, &runes)
	hash := md4.New() // #nosec G406 -- MS-NLMP NT hash compatibility requires MD4.
	_, _ = hash.Write(b.Bytes())
	return hex.EncodeToString(hash.Sum(nil))
}
