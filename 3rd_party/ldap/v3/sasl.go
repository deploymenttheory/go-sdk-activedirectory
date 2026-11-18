package ldap

// SASLSecurityMode selects the RFC4752 per-message Kerberos security layer.
// None requires an independently verified TLS channel at the SDK boundary.
type SASLSecurityMode int

const (
	SASLSecurityNone SASLSecurityMode = 0
	SASLSecuritySign SASLSecurityMode = 2
	SASLSecuritySeal SASLSecurityMode = 4
)

const maxSASLPayload = 16 * 1024 * 1024

type saslReadBuffer struct {
	buf []byte
	pos int
}

func (b *saslReadBuffer) serve(p []byte) (int, bool) {
	if b.pos >= len(b.buf) {
		return 0, false
	}
	n := copy(p, b.buf[b.pos:])
	b.pos += n
	if b.pos >= len(b.buf) {
		b.buf, b.pos = nil, 0
	}
	return n, true
}

func (b *saslReadBuffer) store(data []byte) { b.buf, b.pos = data, 0 }
