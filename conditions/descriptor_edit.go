package conditions

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
)

// WithDACL returns an edited copy. It retains the original owner, group, SACL,
// control bits, opaque ACE data, and original storage bytes. ACL order is never
// canonicalized. Callers must explicitly select absent, NULL, or non-NULL state.
func (descriptor *Descriptor) WithDACL(acl ACL) (*Descriptor, error) {
	return descriptor.withACL(16, controlDACLPresent, acl)
}

// WithSACL returns an edited copy with the same preservation rules as WithDACL.
func (descriptor *Descriptor) WithSACL(acl ACL) (*Descriptor, error) {
	return descriptor.withACL(12, controlSACLPresent, acl)
}

// WithOwnerSID returns a copy with an explicitly supplied binary owner SID. Nil
// removes that component. Aliased group/SACL/DACL bytes remain unchanged.
func (descriptor *Descriptor) WithOwnerSID(sid []byte) (*Descriptor, error) {
	return descriptor.withSID(4, sid)
}

// WithGroupSID returns a copy with an explicitly supplied binary primary-group
// SID. Nil removes that component without changing the owner or either ACL.
func (descriptor *Descriptor) WithGroupSID(sid []byte) (*Descriptor, error) {
	return descriptor.withSID(8, sid)
}

func (descriptor *Descriptor) withSID(at int, sid []byte) (*Descriptor, error) {
	if descriptor == nil || len(descriptor.raw) < descriptorHeaderSize {
		return nil, fmt.Errorf("%w: uninitialized descriptor", ErrInvalidDescriptor)
	}
	if len(sid) != 0 && (!boundedSID(sid) || len(sid) != 8+4*int(sid[1])) {
		return nil, fmt.Errorf("%w: edited trustee SID", ErrInvalidDescriptor)
	}
	if bytes.Equal(descriptor.sid(at), sid) {
		return &Descriptor{raw: slices.Clone(descriptor.raw)}, nil
	}
	return descriptor.withComponent(at, 0, false, sid)
}

func (descriptor *Descriptor) withACL(at int, flag uint16, acl ACL) (*Descriptor, error) {
	if descriptor == nil || len(descriptor.raw) < descriptorHeaderSize {
		return nil, fmt.Errorf("%w: uninitialized descriptor", ErrInvalidDescriptor)
	}
	if (!acl.Present && (acl.Null || len(acl.ACEs) != 0)) || (acl.Null && len(acl.ACEs) != 0) {
		return nil, fmt.Errorf("%w: conflicting ACL states", ErrInvalidDescriptor)
	}
	old := descriptor.acl(at, flag)
	if old.Present == acl.Present && old.Null == acl.Null && old.Revision == acl.Revision && slices.EqualFunc(old.ACEs, acl.ACEs, bytes.Equal) {
		return &Descriptor{raw: slices.Clone(descriptor.raw)}, nil
	}
	if !acl.Present || acl.Null {
		return descriptor.withComponent(at, flag, acl.Present, nil)
	}
	raw, err := descriptor.encodeACL(at, acl)
	if err != nil {
		return nil, err
	}
	return descriptor.withComponent(at, flag, true, raw)
}

func (descriptor *Descriptor) encodeACL(at int, acl ACL) ([]byte, error) {
	if len(acl.ACEs) > math.MaxUint16 || (acl.Revision != 2 && acl.Revision != 4) {
		return nil, fmt.Errorf("%w: ACL revision or count", ErrInvalidDescriptor)
	}
	header := make([]byte, 8)
	var capacity []byte
	if offset := int(binary.LittleEndian.Uint32(descriptor.raw[at : at+4])); offset != 0 {
		original := descriptor.raw[offset:]
		copy(header, original[:8])
		position := 8
		for range int(binary.LittleEndian.Uint16(original[4:6])) {
			position += int(binary.LittleEndian.Uint16(original[position+2 : position+4]))
		}
		capacity = original[position:binary.LittleEndian.Uint16(original[2:4])]
	}
	length := 8 + len(capacity)
	for _, ace := range acl.ACEs {
		if len(ace) < 4 || len(ace) > math.MaxUint16 || len(ace)%4 != 0 ||
			int(binary.LittleEndian.Uint16(ace[2:4])) != len(ace) || !boundedACE(ace) {
			return nil, fmt.Errorf("%w: edited ACE bounds", ErrInvalidDescriptor)
		}
		length += len(ace)
		if length > math.MaxUint16 {
			return nil, fmt.Errorf("%w: edited ACL size", ErrInvalidDescriptor)
		}
		if objectACEType(ace[0]) {
			acl.Revision = 4
		}
	}
	result := make([]byte, 0, length)
	header[0] = acl.Revision
	count := len(acl.ACEs)
	if length < 8 || length > math.MaxUint16 || count < 0 || count > math.MaxUint16 {
		return nil, fmt.Errorf("%w: edited ACL wire fields", ErrInvalidDescriptor)
	}
	binary.LittleEndian.PutUint16(header[2:4], uint16(length)) // bounded above by the wire field
	binary.LittleEndian.PutUint16(header[4:6], uint16(count))
	result = append(result, header...)
	for _, ace := range acl.ACEs {
		result = append(result, ace...)
	}
	return append(result, capacity...), nil
}

func (descriptor *Descriptor) withComponent(at int, flag uint16, present bool, content []byte) (*Descriptor, error) {
	length := (len(descriptor.raw) + 3) &^ 3
	if length < descriptorHeaderSize || length > maxDescriptorBytes || length > maxDescriptorBytes-len(content) {
		return nil, fmt.Errorf("%w: edited descriptor size", ErrInvalidDescriptor)
	}
	result := slices.Clone(descriptor.raw)
	offset := uint32(0)
	if len(content) != 0 {
		result = append(result, make([]byte, length-len(result))...)
		offset = uint32(length) // descriptor size is capped at 16 MiB
		result = append(result, content...)
	}
	binary.LittleEndian.PutUint32(result[at:at+4], offset)
	control := binary.LittleEndian.Uint16(result[2:4]) &^ flag
	if present {
		control |= flag
	}
	binary.LittleEndian.PutUint16(result[2:4], control)
	return ParseDescriptor(result)
}
