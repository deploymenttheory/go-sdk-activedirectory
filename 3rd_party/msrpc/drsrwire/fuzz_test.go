package drsrwire

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func FuzzQualificationBoundedDiagnosticNDR(f *testing.F) {
	for _, kind := range []uint32{0, 3, 4, 5} {
		data, err := os.ReadFile("testdata/kind" + string(rune('0'+kind)) + ".hex")
		if err != nil {
			f.Fatal(err)
		}
		stub, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(kind), stub)
	}
	f.Add(uint8(0), []byte{})
	f.Fuzz(func(t *testing.T, kind uint8, stub []byte) {
		if kind != 0 && kind != 3 && kind != 4 && kind != 5 {
			return
		}
		before := bytes.Clone(stub)
		reply, err := DecodeReplicationInfo(context.Background(), uint32(kind), stub)
		if !bytes.Equal(stub, before) {
			t.Fatal("decoder mutated its caller's input")
		}
		if err == nil && reply.Status == 0 {
			if !reply.Present || reply.Kind != uint32(kind) || int(reply.Count) != len(reply.Neighbors)+len(reply.Failures)+len(reply.Operations) {
				t.Fatal("accepted incomplete diagnostic NDR")
			}
		}
	})
}
