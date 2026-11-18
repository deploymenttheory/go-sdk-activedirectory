package pac

import (
	"encoding/binary"
	"io"
	"log"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestSDKPACCountsAndOffsetsAreInputBounded(t *testing.T) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data, 0xffffffff)
	var p PACType
	if err := p.Unmarshal(data); err == nil {
		t.Fatal("accepted impossible buffer count")
	}
	for _, offset := range []uint64{8, 0xffffffffffffffff} {
		p = PACType{Data: make([]byte, 8), Buffers: []InfoBuffer{{ULType: 1, Offset: offset, CBBufferSize: 8}}}
		if err := p.ProcessPACInfoBuffers(types.EncryptionKey{}, log.New(io.Discard, "", 0)); err == nil {
			t.Fatal("accepted invalid PAC offset")
		}
	}
	if signedChecksumType(0xffffff76) != -138 {
		t.Fatal("signed checksum identifier changed")
	}
}
