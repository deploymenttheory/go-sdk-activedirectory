package conditions

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// ErrInvalidDescriptor identifies a malformed or excessively large self-relative descriptor.
var ErrInvalidDescriptor = errors.New("invalid security descriptor")

const (
	descriptorHeaderSize = 20
	maxDescriptorBytes   = 16 << 20
	controlDACLPresent   = 0x0004
	controlSACLPresent   = 0x0010
	controlSelfRelative  = 0x8000
)

// Descriptor is an owned self-relative Windows security descriptor. Parsing and
// binary marshaling preserve its original layout, opaque ACEs, and unused bytes.
// No method evaluates access rights or resolves trustees against a directory.
type Descriptor struct {
	raw []byte
}

// ACL is an owned snapshot of one ACL. Present=false means absent; Present=true
// and Null=true means a NULL ACL, which differs from an empty ACE list.
type ACL struct {
	Present  bool
	Null     bool
	Revision byte
	ACEs     [][]byte
}

// ParseDescriptor bounds-checks a self-relative descriptor and copies its bytes.
// Unknown ACE types remain opaque. Individual known ACEs have their SID bounds
// checked, without interpreting callback data or conditional expressions.
func ParseDescriptor(raw []byte) (*Descriptor, error) {
	if len(raw) < descriptorHeaderSize || len(raw) > maxDescriptorBytes || raw[0] != 1 {
		return nil, fmt.Errorf("%w: header size or revision", ErrInvalidDescriptor)
	}
	control := binary.LittleEndian.Uint16(raw[2:4])
	if control&controlSelfRelative == 0 {
		return nil, fmt.Errorf("%w: absolute representation", ErrInvalidDescriptor)
	}
	for _, at := range []int{4, 8} {
		offset := uint64(binary.LittleEndian.Uint32(raw[at : at+4]))
		if offset != 0 && (offset < descriptorHeaderSize || offset > uint64(len(raw)) || !boundedSID(raw[offset:])) {
			return nil, fmt.Errorf("%w: trustee offset or SID", ErrInvalidDescriptor)
		}
	}
	for _, item := range []struct {
		at   int
		flag uint16
	}{{12, controlSACLPresent}, {16, controlDACLPresent}} {
		offset := uint64(binary.LittleEndian.Uint32(raw[item.at : item.at+4]))
		if offset == 0 {
			continue
		}
		if control&item.flag == 0 || offset < descriptorHeaderSize || offset > uint64(len(raw)) || !boundedACL(raw[offset:]) {
			return nil, fmt.Errorf("%w: ACL offset or contents", ErrInvalidDescriptor)
		}
	}
	return &Descriptor{raw: slices.Clone(raw)}, nil
}

// MarshalBinary returns a fresh copy of the complete original representation.
func (descriptor *Descriptor) MarshalBinary() ([]byte, error) {
	if descriptor == nil || len(descriptor.raw) < descriptorHeaderSize {
		return nil, fmt.Errorf("%w: uninitialized descriptor", ErrInvalidDescriptor)
	}
	return slices.Clone(descriptor.raw), nil
}

// DACL returns a snapshot of the discretionary ACL, preserving ACE order.
func (descriptor *Descriptor) DACL() ACL { return descriptor.acl(16, controlDACLPresent) }

// SACL returns a snapshot of the system ACL, including non-audit ACE classes.
func (descriptor *Descriptor) SACL() ACL { return descriptor.acl(12, controlSACLPresent) }

func (descriptor *Descriptor) acl(at int, flag uint16) ACL {
	var result ACL
	if descriptor == nil || len(descriptor.raw) < descriptorHeaderSize {
		return result
	}
	result.Present = binary.LittleEndian.Uint16(descriptor.raw[2:4])&flag != 0
	if !result.Present {
		return result
	}
	offset := int(binary.LittleEndian.Uint32(descriptor.raw[at : at+4]))
	if offset == 0 {
		result.Null = true
		return result
	}
	acl := descriptor.raw[offset:]
	result.Revision = acl[0]
	count := int(binary.LittleEndian.Uint16(acl[4:6]))
	result.ACEs = make([][]byte, 0, count)
	position := 8
	for range count {
		length := int(binary.LittleEndian.Uint16(acl[position+2 : position+4]))
		result.ACEs = append(result.ACEs, slices.Clone(acl[position:position+length]))
		position += length
	}
	return result
}

func boundedSID(raw []byte) bool {
	return len(raw) >= 8 && raw[0] == 1 && raw[1] <= 15 && 8+4*int(raw[1]) <= len(raw)
}

func boundedACL(raw []byte) bool {
	// Reserved bytes and unused ACL capacity are retained, not interpreted.
	// Existing native descriptors can contain nonzero values in these fields.
	if len(raw) < 8 || (raw[0] != 2 && raw[0] != 4) {
		return false
	}
	length := int(binary.LittleEndian.Uint16(raw[2:4]))
	if length < 8 || length > len(raw) {
		return false
	}
	count := int(binary.LittleEndian.Uint16(raw[4:6]))
	position := 8
	for range count {
		if length-position < 4 {
			return false
		}
		size := int(binary.LittleEndian.Uint16(raw[position+2 : position+4]))
		if size < 4 || size%4 != 0 || size > length-position || !boundedACE(raw[position:position+size]) {
			return false
		}
		position += size
	}
	return true
}

func boundedACE(raw []byte) bool {
	offset := 8
	switch raw[0] {
	case 0, 1, 2, 3, 9, 10, 13, 14, 17, 18, 19, 20, 21:
	case 4:
		offset = 12
	case 5, 6, 7, 8, 11, 12, 15, 16:
		if len(raw) < 12 {
			return false
		}
		offset = 12
		flags := binary.LittleEndian.Uint32(raw[8:12])
		if flags&1 != 0 {
			offset += 16
		}
		if flags&2 != 0 {
			offset += 16
		}
	default:
		return true
	}
	return offset <= len(raw) && boundedSID(raw[offset:])
}
