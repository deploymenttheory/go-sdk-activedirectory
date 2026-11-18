package drsrwire

import (
	"context"
	"encoding/binary"
	"unicode/utf16"
)

const (
	maxStubBytes   = 16 << 20
	maxRecords     = 1 << 20
	maxStringUnits = 1 << 15
)

type cursor struct {
	ctx    context.Context
	data   []byte
	offset int
	err    error
}

func (c *cursor) take(size, alignment int) []byte {
	if c.err != nil {
		return nil
	}
	if err := context.Cause(c.ctx); err != nil {
		c.err = err
		return nil
	}
	pad := (-c.offset) & (alignment - 1)
	if pad > len(c.data)-c.offset || size > len(c.data)-c.offset-pad || size < 0 {
		c.err = ErrMalformedNDR
		return nil
	}
	c.offset += pad
	result := c.data[c.offset : c.offset+size]
	c.offset += size
	return result
}

func (c *cursor) u32() uint32 {
	b := c.take(4, 4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (c *cursor) u16() uint16 {
	b := c.take(2, 2)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}

func (c *cursor) signed64() int64 {
	b := c.take(8, 8)
	if b == nil {
		return 0
	}
	var value int64
	_, c.err = binary.Decode(b, binary.LittleEndian, &value)
	return value
}
func (c *cursor) guid() (out [16]byte) { copy(out[:], c.take(16, 4)); return out }
func (c *cursor) filetime() uint64 {
	low, high := c.u32(), c.u32()
	return uint64(low) | uint64(high)<<32
}

func (c *cursor) text(reference uint32) *string {
	if reference == 0 || c.err != nil {
		return nil
	}
	maximum, offset, count := c.u32(), c.u32(), c.u32()
	if c.err != nil {
		return nil
	}
	if maximum > maxStringUnits || count > maxStringUnits {
		c.err = ErrNDRLimit
		return nil
	}
	if offset != 0 || count < 1 || count > maximum {
		c.err = ErrMalformedNDR
		return nil
	}
	bytes := c.take(int(count)*2, 2)
	if bytes == nil {
		return nil
	}
	units := make([]uint16, int(count)-1)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(bytes[i*2:])
		if units[i] == 0 {
			c.err = ErrMalformedNDR
			return nil
		}
	}
	if binary.LittleEndian.Uint16(bytes[len(bytes)-2:]) != 0 {
		c.err = ErrMalformedNDR
		return nil
	}
	for i := 0; i < len(units); i++ {
		unit := units[i]
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				c.err = ErrMalformedNDR
				return nil
			}
			i++
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			c.err = ErrMalformedNDR
			return nil
		}
	}
	value := string(utf16.Decode(units))
	return &value
}
