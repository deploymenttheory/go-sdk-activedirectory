package conditions

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Aliasing is a valid relative-offset layout. The output limit must be enforced
// by this boundary, before the enclosing descriptor re-parses formatted SDDL.
func TestResourceClaimAliasedValuesHaveBoundedTextExpansion(t *testing.T) {
	for _, count := range []int{1, 128} {
		raw := make([]byte, 16+4*count)
		binary.LittleEndian.PutUint32(raw[:4], uint32(len(raw)))
		binary.LittleEndian.PutUint16(raw[4:6], 3)
		binary.LittleEndian.PutUint32(raw[12:16], uint32(count))
		raw = append(raw, encodeUTF16("Label", true)...)
		valueOffset := uint32(len(raw))
		raw = append(raw, encodeUTF16(strings.Repeat("x", 1024), true)...)
		for i := range count {
			binary.LittleEndian.PutUint32(raw[16+4*i:20+4*i], valueOffset)
		}
		text, err := formatResourceClaim(raw)
		if count == 1 {
			if err != nil || !strings.Contains(text, strings.Repeat("x", 1024)) {
				t.Fatal("valid bounded control was refused", err)
			}
		} else if !errors.Is(err, ErrUnrepresentableDescriptor) || text != "" {
			t.Fatalf("small aliased claim expanded past the output bound: bytes=%d error=%v", len(text), err)
		}
	}
}
