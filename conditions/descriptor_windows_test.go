//go:build windows && (amd64 || arm64)

package conditions

import (
	"encoding/binary"
	"errors"
	"runtime"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
)

func TestDescriptorBytesNativeOwnershipAndComponents(t *testing.T) {
	api, ledger := auditedNativeAPI(t)
	for i := 0; i < 30; i++ {
		raw, err := api.descriptorBytes(`O:SYG:BAD:PAI(XA;;CR;;;WD;(@User.Department == "Finance"))S:(AU;SA;GA;;;WD)`)
		if err != nil {
			t.Fatal(err)
		}
		assertBalanced(t, ledger, i+1)
		runtime.GC()
		if len(raw) < 20 || raw[0] != 1 || binary.LittleEndian.Uint16(raw[2:4])&0x8000 == 0 {
			t.Fatal(raw)
		}
		for _, at := range []int{4, 8, 12, 16} {
			if offset := binary.LittleEndian.Uint32(raw[at : at+4]); offset < 20 || uint64(offset) >= uint64(len(raw)) {
				t.Fatal(at, offset)
			}
		}
	}
	if raw, err := DescriptorBytes("D:(A;;CR;;;WD)"); err != nil || len(raw) < 28 {
		t.Fatal(raw, err)
	}
}

func TestDescriptorBytesRejectsSyntaxAndRetainsCleanupErrors(t *testing.T) {
	for _, input := range []string{"", "garbage", "D:(A;;CR;;;WD)\x00x", `D:(XA;;CR;;;WD;(@User.Name === "x"))`} {
		if _, err := DescriptorBytes(input); err == nil {
			t.Fatal(input)
		}
	}
	api, ledger := auditedNativeAPI(t)
	free := api.free
	api.free = func(handle foundation.HLOCAL) (foundation.HLOCAL, error) {
		remaining, err := free(handle)
		return remaining, errors.Join(err, syscall.Errno(5))
	}
	raw, err := api.descriptorBytes("D:(A;;CR;;;WD)")
	if !errors.Is(err, syscall.Errno(5)) || len(raw) == 0 {
		t.Fatal(raw, err)
	}
	assertBalanced(t, ledger, 1)
}
