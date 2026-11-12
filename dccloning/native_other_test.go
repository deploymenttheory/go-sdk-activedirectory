//go:build !windows || (!amd64 && !arm64)

package dccloning

import (
	"context"
	"errors"
	"testing"
)

func TestNativeCapabilityUnavailable(t *testing.T) {
	if _, err := Inspect(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("native discovery on unsupported platform: %v", err)
	}
	result, err := Generate(context.Background(), GenerateOptions{Directory: "/explicit"})
	if !errors.Is(err, ErrUnsupported) || result.Outcome != NotWritten {
		t.Fatalf("native generation on unsupported platform: %#v %v", result, err)
	}
}
