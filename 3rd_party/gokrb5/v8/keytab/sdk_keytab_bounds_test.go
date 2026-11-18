package keytab

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func TestSDKKeytabBoundsAndCheckedPrincipal(t *testing.T) {
	for _, b := range [][]byte{{5, 2, 0x80, 0, 0, 0}, {5, 2, 0xff, 0xff, 0xff, 0xff}, {5, 2, 0, 0, 0, 2, 0, 0}} {
		if err := New().Unmarshal(b); err == nil {
			t.Fatalf("accepted malformed keytab %x", b)
		}
	}
	e := newEntry()
	e.Timestamp = time.Unix(math.MaxUint32+1, 0)
	if _, err := e.marshal(2); err == nil {
		t.Fatal("accepted timestamp overflow")
	}
	if _, err := marshalString(string(bytes.Repeat([]byte{'x'}, 65536)), 2); err == nil {
		t.Fatal("accepted string length overflow")
	}
	var order binary.ByteOrder = binary.BigEndian
	p := math.MaxInt
	if _, err := readBytes([]byte{1}, &p, 1, &order); err == nil {
		t.Fatal("accepted invalid cursor")
	}
}

func FuzzSDKKeytabBounds(f *testing.F) {
	f.Add([]byte{5, 2, 0, 0, 0, 0})
	f.Add([]byte{5, 2, 0x80, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_ = New().Unmarshal(b)
	})
}
