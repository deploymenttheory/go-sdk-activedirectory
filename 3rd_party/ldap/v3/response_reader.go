package ldap

import (
	"io"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	maxLDAPResponseBytes    = 16 * 1024 * 1024
	maxLDAPResponseElements = 262144
	maxLDAPResponseDepth    = 32
)

// readLDAPResponse bounds the complete BER frame before a recursive decoder can
// allocate from a peer's advertised length. LDAP requires definite BER lengths.
func readLDAPResponse(reader io.Reader) (*ber.Packet, error) {
	var header [6]byte
	if _, err := io.ReadFull(reader, header[:2]); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, malformedf("invalid or oversized LDAP BER frame")
	}
	length := uint32(header[1])
	headerSize := 2
	if header[1]&0x80 != 0 {
		count := int(header[1] & 0x7f)
		if count == 0 || count > 4 {
			return nil, malformedf("invalid or oversized LDAP BER frame")
		}
		if _, err := io.ReadFull(reader, header[2:2+count]); err != nil {
			return nil, err
		}
		length = 0
		for _, octet := range header[2 : 2+count] {
			length = length<<8 | uint32(octet)
		}
		headerSize += count
	}
	if length > maxLDAPResponseBytes-uint32(headerSize) {
		return nil, malformedf("invalid or oversized LDAP BER frame")
	}
	wire := make([]byte, headerSize+int(length))
	copy(wire, header[:headerSize])
	if _, err := io.ReadFull(reader, wire[headerSize:]); err != nil {
		return nil, err
	}
	return decodeLDAPBER(wire)
}

// validateBERBudget performs a non-recursive structural pass before ASN.1 BER
// decoding, including for encoded values inside recognized response controls.
func validateBERBudget(wire []byte) error {
	if len(wire) == 0 || len(wire) > maxLDAPResponseBytes {
		return malformedf("invalid or oversized LDAP BER frame")
	}
	stack := [][]byte{wire}
	elements := 0
	rootElements := 0
	for len(stack) > 0 {
		last := len(stack) - 1
		data := stack[last]
		if len(data) == 0 {
			stack = stack[:last]
			continue
		}
		if len(stack) == 1 {
			rootElements++
			if rootElements > 1 {
				return malformedf("invalid or oversized LDAP BER frame")
			}
		}
		if len(data) < 2 {
			return malformedf("invalid or oversized LDAP BER frame")
		}
		constructed := data[0]&0x20 != 0
		offset := 1
		if data[0]&0x1f == 0x1f {
			for digits := 0; ; digits++ {
				if digits >= 4 || offset >= len(data) {
					return malformedf("invalid or oversized LDAP BER frame")
				}
				next := data[offset]
				offset++
				if next&0x80 == 0 {
					break
				}
			}
		}
		if offset >= len(data) {
			return malformedf("invalid or oversized LDAP BER frame")
		}
		first := data[offset]
		offset++
		length := uint32(first)
		if first&0x80 != 0 {
			count := int(first & 0x7f)
			if count == 0 || count > 4 || offset+count > len(data) {
				return malformedf("invalid or oversized LDAP BER frame")
			}
			length = 0
			for _, octet := range data[offset : offset+count] {
				length = length<<8 | uint32(octet)
			}
			offset += count
		}
		remaining := len(data) - offset
		if remaining < 0 || uint64(length) > uint64(remaining) {
			return malformedf("invalid or oversized LDAP BER frame")
		}
		end := offset + int(length)
		// asn1-ber ignores ParseInt64 errors for these primitive tags. Validate
		// the actual encoding before zero can masquerade as a successful result,
		// a message identifier or a false control flag.
		if data[0] == 2 || data[0] == 10 {
			if length == 0 || length > 8 {
				return malformedf("invalid LDAP BER integer length")
			}
		}
		if data[0] == 1 && length != 1 {
			return malformedf("invalid LDAP BER boolean length")
		}
		stack[last] = data[end:]
		elements++
		if elements > maxLDAPResponseElements {
			return malformedf("response exceeds the BER element limit")
		}
		if constructed && length > 0 {
			if len(stack) >= maxLDAPResponseDepth {
				return malformedf("response exceeds the BER nesting limit")
			}
			stack = append(stack, data[offset:end])
		}
	}
	return nil
}

func decodeLDAPBER(wire []byte) (*ber.Packet, error) {
	if err := validateBERBudget(wire); err != nil {
		return nil, err
	}
	packet, err := ber.DecodePacketErr(wire)
	if err != nil {
		return nil, malformedf("invalid BER content: %v", err)
	}
	return packet, nil
}
