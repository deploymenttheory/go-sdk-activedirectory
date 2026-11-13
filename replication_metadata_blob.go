package activedirectory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"unicode/utf16"
)

// MS-ADTS 2.2.6-2.2.8 defines packed little-endian wire packets, not the host
// ABI layout of the similarly named ntdsapi.h structs. In particular the link
// packet's first USN is at byte 60, without the native struct's padding.
type metadataBlob struct {
	data   []byte
	header uint32
	err    error
}

func (b *metadataBlob) text(field int) *string {
	offset := binary.LittleEndian.Uint32(b.data[field:])
	if offset == 0 {
		return nil
	}
	if offset < b.header || offset%2 != 0 || (b.header == 80 && offset%4 != 0) || uint64(offset)+2 > uint64(len(b.data)) {
		b.err = errors.Join(b.err, ErrInvalidResult)
		return nil
	}
	var units []uint16
	for cursor := uint64(offset); cursor+2 <= uint64(len(b.data)); cursor += 2 {
		unit := binary.LittleEndian.Uint16(b.data[cursor:])
		if unit == 0 {
			for i := 0; i < len(units); i++ {
				if units[i] >= 0xD800 && units[i] <= 0xDBFF {
					if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
						b.err = errors.Join(b.err, ErrInvalidResult)
						return nil
					}
					i++
				} else if units[i] >= 0xDC00 && units[i] <= 0xDFFF {
					b.err = errors.Join(b.err, ErrInvalidResult)
					return nil
				}
			}
			value := string(utf16.Decode(units))
			return &value
		}
		units = append(units, unit)
	}
	b.err = errors.Join(b.err, ErrInvalidResult)
	return nil
}

func metadataGUID(data []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(data), binary.LittleEndian.Uint16(data[4:]), binary.LittleEndian.Uint16(data[6:]), data[8:10], data[10:16])
}

func decodeMetadataAttribute(data []byte) (ReplicationAttributeMetadata, error) {
	if len(data) < 52 {
		return ReplicationAttributeMetadata{}, ErrInvalidResult
	}
	b := metadataBlob{data: data, header: 52}
	result := metadataStamp(&b, 4, 8, 16, 32, 40, 48)
	return result, b.err
}

func metadataStamp(b *metadataBlob, version, changed, invocation, originating, local, server int) ReplicationAttributeMetadata {
	result := ReplicationAttributeMetadata{
		Version:                 binary.LittleEndian.Uint32(b.data[version:]),
		LastOriginatingChange:   replicationTicks(binary.LittleEndian.Uint64(b.data[changed:])),
		OriginatingInvocationID: metadataGUID(b.data[invocation : invocation+16]),
		OriginatingUSN:          int64(binary.LittleEndian.Uint64(b.data[originating:])),
		LocalUSN:                int64(binary.LittleEndian.Uint64(b.data[local:])),
		OriginatingServerDN:     b.text(server),
	}
	name := b.text(0)
	if name == nil || !metadataProperty(*name) {
		b.err = errors.Join(b.err, ErrInvalidResult)
	} else {
		result.AttributeName = *name
	}
	return result
}

func decodeMetadataLink(data []byte) (ReplicationLinkedValueMetadata, error) {
	if len(data) < 80 {
		return ReplicationLinkedValueMetadata{}, ErrInvalidResult
	}
	b := metadataBlob{data: data, header: 80}
	result := ReplicationLinkedValueMetadata{
		ReplicationAttributeMetadata: metadataStamp(&b, 32, 36, 44, 60, 68, 76),
		ValueDN:                      b.text(4),
		Deleted:                      replicationTicks(binary.LittleEndian.Uint64(data[16:])),
		Created:                      replicationTicks(binary.LittleEndian.Uint64(data[24:])),
	}
	size, offset := uint64(binary.LittleEndian.Uint32(data[8:])), uint64(binary.LittleEndian.Uint32(data[12:]))
	if size != 0 {
		if offset < 80 || offset%4 != 0 || offset+size > uint64(len(data)) {
			b.err = errors.Join(b.err, ErrInvalidResult)
		} else {
			result.Data = slices.Clone(data[offset : offset+size])
		}
	} else if offset != 0 && (offset < 80 || offset%4 != 0 || offset > uint64(len(data))) {
		b.err = errors.Join(b.err, ErrInvalidResult)
	}
	return result, b.err
}

func decodeMetadataCursor(data []byte) (ReplicationCursor, error) {
	if len(data) < 36 {
		return ReplicationCursor{}, ErrInvalidResult
	}
	b := metadataBlob{data: data, header: 36}
	result := ReplicationCursor{InvocationID: metadataGUID(data[:16]), HighestUSN: int64(binary.LittleEndian.Uint64(data[16:])), LastSuccess: replicationTicks(binary.LittleEndian.Uint64(data[24:])), SourceServerDN: b.text(32)}
	return result, b.err
}
