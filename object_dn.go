package activedirectory

import (
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type identityAVA struct {
	attribute, value string
	binary           bool
}
type identityDN [][]identityAVA

// Parse RFC4514 structure for scope checks; this is not a schema matching-rule
// engine. Keep the original wire DN. Legacy quoted/provider/extended DN forms
// are deliberately not accepted by the explicit identity constructor.
func parseIdentityDN(value string) (identityDN, error) {
	if value == "" || !validDirectoryText(value) {
		return nil, ErrInvalidIdentity
	}
	rdns, err := splitIdentityDN(value, ',')
	if err != nil {
		return nil, err
	}
	result := make(identityDN, 0, len(rdns))
	for _, rdn := range rdns {
		avas, err := splitIdentityDN(rdn, '+')
		if err != nil {
			return nil, err
		}
		components := make([]identityAVA, 0, len(avas))
		for _, ava := range avas {
			attribute, text, found := strings.Cut(ava, "=")
			if !found || !attributeDescription.MatchString(attribute) || strings.Contains(attribute, ";") {
				return nil, ErrInvalidIdentity
			}
			decoded, binary, err := decodeIdentityDNValue(text)
			if err != nil {
				return nil, err
			}
			components = append(components, identityAVA{attribute: strings.ToLower(attribute), value: decoded, binary: binary})
		}
		result = append(result, components)
	}
	return result, nil
}

func splitIdentityDN(value string, separator byte) ([]string, error) {
	var result []string
	start := 0
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			if i == len(value) {
				return nil, ErrInvalidIdentity
			}
		} else if value[i] == separator {
			if i == start {
				return nil, ErrInvalidIdentity
			}
			result = append(result, value[start:i])
			start = i + 1
		}
	}
	if start == len(value) {
		return nil, ErrInvalidIdentity
	}
	return append(result, value[start:]), nil
}

func decodeIdentityDNValue(value string) (string, bool, error) {
	if strings.HasPrefix(value, "#") {
		decoded, err := hex.DecodeString(value[1:])
		if err != nil || len(decoded) == 0 {
			return "", false, ErrInvalidIdentity
		}
		return string(decoded), true, nil
	}
	if strings.HasPrefix(value, " ") {
		return "", false, ErrInvalidIdentity
	}
	var decoded strings.Builder
	lastEscaped := false
	for i := 0; i < len(value); i++ {
		lastEscaped = value[i] == '\\'
		if !lastEscaped {
			if strings.ContainsRune(`",+;<>`, rune(value[i])) {
				return "", false, ErrInvalidIdentity
			}
			decoded.WriteByte(value[i])
			continue
		}
		i++
		if i == len(value) {
			return "", false, ErrInvalidIdentity
		}
		if i+1 < len(value) {
			if octet, err := hex.DecodeString(value[i : i+2]); err == nil {
				decoded.WriteByte(octet[0])
				i++
				continue
			}
		}
		if !strings.ContainsRune(` \",+;<>#=`, rune(value[i])) {
			return "", false, ErrInvalidIdentity
		}
		decoded.WriteByte(value[i])
	}
	if (strings.HasSuffix(value, " ") && !lastEscaped) || !utf8.ValidString(decoded.String()) {
		return "", false, ErrInvalidIdentity
	}
	return decoded.String(), false, nil
}

func sameIdentityRDN(a, b []identityAVA) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, left := range a {
		found := false
		for i, right := range b {
			equal := left.value == right.value
			if !left.binary && !right.binary {
				equal = strings.EqualFold(left.value, right.value)
			}
			if !used[i] && left.attribute == right.attribute && left.binary == right.binary && equal {
				used[i], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func identityWithin(dn, base identityDN) bool {
	if len(dn) < len(base) {
		return false
	}
	for i := range base {
		if !sameIdentityRDN(dn[len(dn)-len(base)+i], base[i]) {
			return false
		}
	}
	return true
}

func sameIdentityDN(a, b identityDN) bool { return len(a) == len(b) && identityWithin(a, b) }

// identityDNKey indexes the same structural equivalence as sameIdentityDN:
// decoded escapes, unordered AVAs (including multiplicity), Unicode simple
// case folding for text, and exact bytes for binary values. It is not a schema
// matching-rule canonicalization and must never replace the original wire DN.
func identityDNKey(dn identityDN) string {
	var key strings.Builder
	field := func(value string) {
		key.WriteString(strconv.Itoa(len(value)))
		key.WriteByte(':')
		key.WriteString(value)
	}
	for _, rdn := range dn {
		avas := make([]string, 0, len(rdn))
		for _, ava := range rdn {
			value, kind := ava.value, "b"
			if !ava.binary {
				kind = "t"
				value = strings.Map(func(r rune) rune {
					minimum := r
					for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
						if next < minimum {
							minimum = next
						}
					}
					return minimum
				}, value)
			}
			avas = append(avas, strconv.Itoa(len(ava.attribute))+":"+ava.attribute+kind+value)
		}
		slices.Sort(avas)
		key.WriteString(strconv.Itoa(len(avas)))
		key.WriteByte('+')
		for _, ava := range avas {
			field(ava)
		}
		key.WriteByte(',')
	}
	return key.String()
}

// Select the longest advertised naming-context suffix. In particular, Schema
// is a separate NC from Configuration even though its textual DN is beneath it.
func identityNamingContext(dn identityDN, contexts []identityDN) int {
	selected := -1
	for i, candidate := range contexts {
		if identityWithin(dn, candidate) && (selected == -1 || len(candidate) > len(contexts[selected])) {
			selected = i
		}
	}
	return selected
}
