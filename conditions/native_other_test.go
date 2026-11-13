//go:build !windows || (!amd64 && !arm64)

package conditions

import (
	"errors"
	"testing"
)

func TestUnsupportedNativeRuntime(t *testing.T) {
	if _, err := Compile(ACE{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := NormalizeSDDL("D:"); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := DescriptorBytes("D:"); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
