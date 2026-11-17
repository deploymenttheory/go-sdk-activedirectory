package model

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidDirectoryQuery   = errors.New("invalid directory query")
	ErrDirectoryObjectNotFound = errors.New("directory query returned no matching object")
)

// DirectoryObservation records the raw inputs to a projection. Complete means
// all planned reads and conversions finished, not that every attribute exists
// or was visible to this identity. Sequential reads are not an atomic snapshot.
// Absent, unloaded and ranged values remain distinguishable through Object.Attribute.
type DirectoryObservation struct {
	Source   Endpoint
	RootDSE  RootDSE
	Objects  []Object
	Complete bool
}

// DirectoryReadError preserves partial, native, capability, and context errors.
type DirectoryReadError struct {
	Operation string
	Cause     error
}

func (e *DirectoryReadError) Error() string {
	return fmt.Sprintf("%s incomplete: %v", e.Operation, e.Cause)
}
func (e *DirectoryReadError) Unwrap() []error { return []error{ErrIncompleteResult, e.Cause} }

// AD Integer attributes can render a bitmask as signed decimal. Preserve all
// 32 bits while still rejecting values outside either supported representation.
func InternalParseDirectoryMask(value string) (uint32, error) {
	if result, err := InternalParseUint32(value); err == nil {
		return result, nil
	}
	result, err := strconv.ParseInt(value, 10, 32)
	return uint32(result), err
}

func InternalValidDirectoryText(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

// Only fixed schema attributes and literal values are composed here. General
// PowerShell expressions and identity resolution belong to their shared layers.
func InternalLdapLiteral(value string) string {
	var b strings.Builder
	for _, v := range []byte(value) {
		switch v {
		case 0, '(', ')', '*', '\\':
			fmt.Fprintf(&b, "\\%02x", v)
		default:
			b.WriteByte(v)
		}
	}
	return b.String()
}

// Parent traversal only splits server-returned DNs; it does not normalize or
// resolve user identities. Preserve escaped commas and quoted legacy RDNs.
func InternalParentDirectoryDN(dn string) (string, error) {
	quoted := false
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++
		case '"':
			quoted = !quoted
		case ',':
			if !quoted && i > 0 && i+1 < len(dn) {
				return dn[i+1:], nil
			}
		}
	}
	return "", fmt.Errorf("%w: linked DN has no parent", ErrInvalidResult)
}

func InternalCopiedBinary(d *InternalRootDSEDecoder, name string, length int) []byte {
	values, ok := d.InternalAttributes[strings.ToLower(name)]
	if !ok {
		return nil
	}
	if len(values) != 1 || len(values[0]) == 0 || (length > 0 && len(values[0]) != length) {
		d.InternalInvalid(name)
		return nil
	}
	return slices.Clone(values[0])
}

const (
	InternalWellKnownSystem         = "AB1D30F3768811D1ADED00C04FD8D5CD"
	InternalWellKnownInfrastructure = "2FBAC1870ADE11D297C400C04FD8D5CD"
)

// Keys use the AD well-known GUID hexadecimal representation, not objectGUID
// byte order. Values are maintained by the server across container redirection.
func InternalWellKnownContainers(d *InternalRootDSEDecoder) map[string]string {
	values := d.InternalTexts("wellKnownObjects")
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for _, value := range values {
		parts := strings.SplitN(value, ":", 4)
		if len(parts) != 4 || parts[0] != "B" || parts[1] != "32" || len(parts[2]) != 32 ||
			parts[3] == "" {
			d.InternalInvalid("wellKnownObjects")
			continue
		}
		if _, err := hex.DecodeString(parts[2]); err != nil {
			d.InternalInvalid("wellKnownObjects")
			continue
		}
		key := strings.ToUpper(parts[2])
		if _, exists := result[key]; exists {
			d.InternalInvalid("wellKnownObjects")
			continue
		}
		result[key] = parts[3]
	}
	return result
}
