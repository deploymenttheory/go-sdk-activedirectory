//go:build !windows || (!amd64 && !arm64)

package activedirectory

import (
	"context"
	"errors"
	"testing"
)

func TestDialUnsupportedPlatform(t *testing.T) {
	client, err := Dial(context.Background(), Config{Endpoint: Endpoint{Host: "dc1.ad.sdk.test"}})
	if client != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial = %v, %v", client, err)
	}
}
