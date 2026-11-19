package drsrwire

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ReplicationInfoRequest emits only the version-one diagnostic request, with a
// null source GUID. A nil object DN stays NULL; a supplied empty DN stays empty.
// Caller DN text is validated and copied without rewriting it.
func ReplicationInfoRequest(ctx context.Context, handle ContextHandle, kind uint32, objectDN *string) ([]byte, error) {
	if cause := context.Cause(ctx); cause != nil {
		return nil, fmt.Errorf("encode DRS diagnostic request: %w", cause)
	}
	if kind != 0 && kind != 3 && kind != 4 && kind != 5 || handle == [20]byte{} {
		return nil, ErrMalformedNDR
	}
	out := make([]byte, 52, 64)
	copy(out, handle[:])
	binary.LittleEndian.PutUint32(out[20:], 1)
	binary.LittleEndian.PutUint32(out[24:], 1)
	binary.LittleEndian.PutUint32(out[28:], kind)
	if objectDN == nil {
		return out, nil
	}
	if !utf8.ValidString(*objectDN) || strings.ContainsRune(*objectDN, 0) {
		return nil, ErrMalformedNDR
	}
	if len(*objectDN) > maxStringUnits*4 {
		return nil, ErrNDRLimit
	}
	units := utf16.Encode([]rune(*objectDN))
	unitCount := len(units) + 1
	if unitCount < 1 || unitCount > maxStringUnits {
		return nil, ErrNDRLimit
	}
	count := uint32(unitCount)
	binary.LittleEndian.PutUint32(out[32:], 33)
	out = append(out, make([]byte, 12+int(count)*2)...)
	binary.LittleEndian.PutUint32(out[52:], count)
	binary.LittleEndian.PutUint32(out[60:], count)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(out[64+i*2:], unit)
	}
	return out, nil
}
