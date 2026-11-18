package kadmin

import "testing"

func TestSDKPasswordReplyRejectsIncompleteEnvelope(t *testing.T) {
	for _, b := range [][]byte{nil, {0, 6, 0, 1, 0}, {0, 7, 0, 1, 0, 0}, {0, 6, 0, 1, 0, 1}, {0, 6, 0, 1, 0, 0}} {
		var reply Reply
		if err := reply.Unmarshal(b); err == nil {
			t.Fatalf("accepted incomplete reply %x", b)
		}
	}
}

func FuzzSDKPasswordReplyBounds(f *testing.F) {
	f.Add([]byte{0, 6, 0, 1, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			t.Skip()
		}
		var reply Reply
		_ = reply.Unmarshal(b)
	})
}
