package conditions

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// SDDLOptions supplies explicit identity context for domain-relative SDDL SID
// aliases. Empty context is permitted only when the input needs no such alias.
// Parsing never consults the current machine, token, environment, or directory.
type SDDLOptions struct {
	DomainSID  string
	MachineSID string
}

var wellKnownSIDTokens = map[string]string{
	"WD": "S-1-1-0", "CO": "S-1-3-0", "CG": "S-1-3-1", "OW": "S-1-3-4",
	"NU": "S-1-5-2", "IU": "S-1-5-4", "SU": "S-1-5-6", "AN": "S-1-5-7", "ED": "S-1-5-9",
	"PS": "S-1-5-10", "AU": "S-1-5-11", "RC": "S-1-5-12", "SY": "S-1-5-18",
	"LS": "S-1-5-19", "NS": "S-1-5-20", "WR": "S-1-5-33", "UD": "S-1-5-84-0-0-0-0-0",
	"AC": "S-1-15-2-1", "LW": "S-1-16-4096", "ME": "S-1-16-8192", "MP": "S-1-16-8448",
	"HI": "S-1-16-12288", "SI": "S-1-16-16384",
	"BA": "S-1-5-32-544", "BU": "S-1-5-32-545", "BG": "S-1-5-32-546", "PU": "S-1-5-32-547",
	"AO": "S-1-5-32-548", "SO": "S-1-5-32-549", "PO": "S-1-5-32-550", "BO": "S-1-5-32-551",
	"RE": "S-1-5-32-552", "RU": "S-1-5-32-554", "RD": "S-1-5-32-555", "NO": "S-1-5-32-556",
	"MU": "S-1-5-32-558", "LU": "S-1-5-32-559", "IS": "S-1-5-32-568", "CY": "S-1-5-32-569",
	"ER": "S-1-5-32-573", "CD": "S-1-5-32-574", "RA": "S-1-5-32-575", "ES": "S-1-5-32-576",
	"MS": "S-1-5-32-577", "HA": "S-1-5-32-578", "AA": "S-1-5-32-579", "RM": "S-1-5-32-580",
}

var domainSIDTokens = map[string]string{
	"DA": "512", "DG": "514", "DU": "513", "DD": "516", "DC": "515", "SA": "518",
	"CA": "517", "RS": "553", "EA": "519", "PA": "520", "RO": "498", "CN": "522",
}

func parseSDDLSID(text string, options SDDLOptions) ([]byte, error) {
	if known, ok := wellKnownSIDTokens[text]; ok {
		text = known
	} else if rid, relative := domainSIDTokens[text]; relative {
		if !validAccountDomain(options.DomainSID) {
			return nil, fmt.Errorf("%w: explicit domain SID required for %s", ErrInvalidExpression, text)
		}
		text = options.DomainSID + "-" + rid
	} else if text == "LA" || text == "LG" {
		if !validAccountDomain(options.MachineSID) {
			return nil, fmt.Errorf("%w: explicit machine SID required for %s", ErrInvalidExpression, text)
		}
		rid := "500"
		if text == "LG" {
			rid = "501"
		}
		text = options.MachineSID + "-" + rid
	}
	return parseNumericSID(text)
}

func validAccountDomain(text string) bool {
	parts := strings.Split(text, "-")
	_, err := parseNumericSID(text)
	return err == nil && len(parts) == 7 && strings.HasPrefix(text, "S-1-5-21-")
}

func parseNumericSID(text string) ([]byte, error) {
	parts := strings.Split(text, "-")
	if len(parts) < 4 || len(parts) > 18 || parts[0] != "S" || parts[1] != "1" {
		return nil, fmt.Errorf("%w: SID syntax", ErrInvalidExpression)
	}
	base := 10
	authorityText := parts[2]
	if strings.HasPrefix(authorityText, "0x") {
		base, authorityText = 16, authorityText[2:]
	}
	authority, err := strconv.ParseUint(authorityText, base, 48)
	if err != nil {
		return nil, fmt.Errorf("%w: SID authority: %w", ErrInvalidExpression, err)
	}
	result := make([]byte, 8+4*(len(parts)-3))
	count := len(parts) - 3
	if count < 0 || count > 15 {
		return nil, fmt.Errorf("%w: SID count", ErrInvalidExpression)
	}
	result[0], result[1] = 1, byte(count)
	for at := 7; at >= 2; at-- {
		result[at] = byte(authority & 0xff)
		authority >>= 8
	}
	for i, text := range parts[3:] {
		value, parseErr := strconv.ParseUint(text, 10, 32)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: SID subauthority: %w", ErrInvalidExpression, parseErr)
		}
		binary.LittleEndian.PutUint32(result[8+4*i:12+4*i], uint32(value))
	}
	return result, nil
}

func formatSID(raw []byte, aliases bool) string {
	var authority uint64
	for _, part := range raw[2:8] {
		authority = authority<<8 | uint64(part)
	}
	text := "S-1-" + strconv.FormatUint(authority, 10)
	if authority >= 1<<32 {
		text = fmt.Sprintf("S-1-0x%012x", authority)
	}
	for i := range int(raw[1]) {
		text += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[8+4*i:12+4*i])), 10)
	}
	if aliases {
		for token, value := range wellKnownSIDTokens {
			if value == text {
				return token
			}
		}
	}
	return text
}
