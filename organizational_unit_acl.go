package activedirectory

import (
	"bytes"
	"encoding/binary"
	"slices"
)

const ouObjectProtectionMask uint32 = 0x10040
const ouParentProtectionMask uint32 = 2
const ouSDFlagsControl = "1.2.840.113556.1.4.801"

var ouDACLControlValue = []byte{0x30, 3, 2, 1, 4}

type ouDACL struct {
	control  uint16
	revision byte
	aces     [][]byte
}

// Bounds-check the self-relative protocol representation before any native API
// receives its pointer. Retain opaque ACE bytes rather than normalizing a DACL.
func decodeOUDACL(raw []byte) (ouDACL, error) {
	var result ouDACL
	if len(raw) < 20 || raw[0] != 1 {
		return result, ErrInvalidResult
	}
	result.control = binary.LittleEndian.Uint16(raw[2:4])
	if result.control&0x8000 == 0 || result.control&4 == 0 {
		return result, ErrOUProtection
	}
	for _, at := range []int{4, 8} {
		offset := uint64(binary.LittleEndian.Uint32(raw[at : at+4]))
		if offset == 0 {
			continue
		}
		if offset < 20 || offset%4 != 0 || offset+8 > uint64(len(raw)) {
			return result, ErrInvalidResult
		}
		if raw[offset] != 1 || raw[offset+1] > 15 || offset+8+4*uint64(raw[offset+1]) > uint64(len(raw)) {
			return result, ErrInvalidResult
		}
	}
	for _, at := range []int{12, 16} {
		offset := uint64(binary.LittleEndian.Uint32(raw[at : at+4]))
		if offset == 0 {
			if at == 16 {
				return result, ErrOUProtection
			} // never turn NULL (allow-all) into deny-all
			continue
		}
		if offset < 20 || offset%4 != 0 || offset+8 > uint64(len(raw)) {
			return result, ErrInvalidResult
		}
		length := uint64(binary.LittleEndian.Uint16(raw[offset+2 : offset+4]))
		if length < 8 || offset+length > uint64(len(raw)) || (raw[offset] != 2 && raw[offset] != 4) {
			return result, ErrInvalidResult
		}
		count := int(binary.LittleEndian.Uint16(raw[offset+4 : offset+6]))
		position := offset + 8
		for i := 0; i < count; i++ {
			if position+4 > offset+length {
				return result, ErrInvalidResult
			}
			size := uint64(binary.LittleEndian.Uint16(raw[position+2 : position+4]))
			if size < 4 || size%4 != 0 || position+size > offset+length {
				return result, ErrInvalidResult
			}
			if !boundedDirectoryACE(raw[position : position+size]) {
				return result, ErrInvalidResult
			}
			if at == 16 {
				result.aces = append(result.aces, slices.Clone(raw[position:position+size]))
			}
			position += size
		}
		if at == 16 {
			result.revision = raw[offset]
		}
	}
	return result, nil
}

// Known Windows ACE forms carry a SID at a documented offset. Validate that
// SID within its ACE before calling a native API without a buffer-length input.
// Unknown forms remain opaque; no invented SID layout is assigned to them.
func boundedDirectoryACE(ace []byte) bool {
	offset := 8
	switch ace[0] {
	case 0, 1, 2, 3, 9, 10, 13, 14, 17, 18, 19, 20, 21:
	case 4:
		offset = 12
	case 5, 6, 7, 8, 11, 12, 15, 16:
		if len(ace) < 12 {
			return false
		}
		offset = 12
		flags := binary.LittleEndian.Uint32(ace[8:12])
		if flags&1 != 0 {
			offset += 16
		}
		if flags&2 != 0 {
			offset += 16
		}
	default:
		return true
	}
	return offset+8 <= len(ace) && ace[offset] == 1 && ace[offset+1] <= 15 && offset+8+4*int(ace[offset+1]) <= len(ace)
}

func ouWorldACE(ace []byte) bool {
	return len(ace) == 20 && bytes.Equal(ace[8:], []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
}

// Match the reference's ordered ordinary ACE pattern. Unknown/object/callback
// rules before a decisive ordinary rule remain unknown, rather than being
// interpreted as effective access. Inherited rights are never edited.
func ouACLProtection(acl ouDACL, mask uint32) *bool {
	for _, ace := range acl.aces {
		if ace[0] != 0 && ace[0] != 1 {
			return nil
		}
		if len(ace) < 8 {
			return nil
		}
		rights := binary.LittleEndian.Uint32(ace[4:8])
		if ace[0] == 0 && rights&mask != 0 {
			value := false
			return &value
		}
		if ace[0] == 1 && ace[1]&0x0f == 0 && ouWorldACE(ace) && rights&mask == mask {
			value := true
			return &value
		}
	}
	value := false
	return &value
}

func changeOUACEs(acl ouDACL, mask uint32, protect bool) ([][]byte, bool) {
	if protect {
		if state := ouACLProtection(acl, mask); state != nil && *state {
			return acl.aces, false
		}
		ace := []byte{1, 0, 20, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(ace[4:8], mask)
		return append([][]byte{ace}, acl.aces...), true
	}
	changed := false
	aces := make([][]byte, 0, len(acl.aces))
	for _, ace := range acl.aces {
		if ace[0] != 1 || ace[1] != 0 || !ouWorldACE(ace) {
			aces = append(aces, ace)
			continue
		}
		rights := binary.LittleEndian.Uint32(ace[4:8])
		if rights&mask == 0 {
			aces = append(aces, ace)
			continue
		}
		changed = true
		if remaining := rights &^ mask; remaining != 0 {
			copy := slices.Clone(ace)
			binary.LittleEndian.PutUint32(copy[4:8], remaining)
			aces = append(aces, copy)
		}
	}
	return aces, changed
}
