package krberror

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestVendorErrorfPreservesCause(t *testing.T) {
	cause := fmt.Errorf("reading KDC reply: %w", io.ErrUnexpectedEOF)
	first := Errorf(cause, NetworkingError, "AS exchange failed")
	second := Errorf(fmt.Errorf("caller context: %w", first), KRBMsgError, "authentication failed")
	if !errors.Is(second, io.ErrUnexpectedEOF) {
		t.Fatal("Kerberos context discarded the underlying transport error")
	}
	var wrapped Krberror
	if !errors.As(second, &wrapped) || wrapped.RootCause != NetworkingError {
		t.Fatalf("lost original Kerberos classification: %v", second)
	}
	if len(first.EText) != 1 || len(second.EText) != 2 {
		t.Fatalf("wrapping mutated the original context: first=%v second=%v", first, second)
	}
}
