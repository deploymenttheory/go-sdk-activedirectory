package ldap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	krbgssapi "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	ldapgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
)

// krbSASLConn wraps a net.Conn with Kerberos GSSAPI SASL framing.
// Each LDAP message on the wire becomes a 4-byte big-endian length prefix
// followed by a GSS WrapToken (RFC 4121). Supports both integrity-only
// (sign) and confidentiality (seal) modes.
type krbSASLConn struct {
	conn              net.Conn
	subkey            types.EncryptionKey
	mode              SASLSecurityMode
	acceptorSubkey    bool
	peerMaxTokenSize  uint32
	localMaxTokenSize uint32
	stateMu           sync.Mutex
	failure           error
	closeOnce         sync.Once
	closeErr          error

	// write side
	wSeqNum uint64
	wMu     sync.Mutex

	// read side
	rBuf    saslReadBuffer
	rSeqNum uint64
	rMu     sync.Mutex
}

var _ net.Conn = (*krbSASLConn)(nil)

func newKrbSASLConnWithContext(conn net.Conn, context ldapgss.SASLSecurityContext, mode SASLSecurityMode) (*krbSASLConn, error) {
	if conn == nil || (mode != SASLSecuritySign && mode != SASLSecuritySeal) || context.PeerMaxTokenSize == 0 || context.PeerMaxTokenSize > 0xffffff ||
		context.LocalMaxTokenSize == 0 || context.LocalMaxTokenSize > 0xffffff {
		return nil, fmt.Errorf("ldap: incomplete Kerberos SASL context")
	}
	// This RFC4121 wrapper implements the AES profiles, not legacy RFC1964 RC4.
	if context.KeyType < 17 || context.KeyType > 20 {
		return nil, fmt.Errorf("ldap: unsupported Kerberos SASL encryption profile")
	}
	encType, err := crypto.GetEtype(context.KeyType)
	if err != nil || len(context.KeyValue) != encType.GetKeyByteSize() {
		return nil, fmt.Errorf("ldap: invalid Kerberos SASL key")
	}
	result := &krbSASLConn{
		conn:              conn,
		subkey:            types.EncryptionKey{KeyType: context.KeyType, KeyValue: append([]byte(nil), context.KeyValue...)},
		mode:              mode,
		acceptorSubkey:    context.AcceptorSubkey,
		wSeqNum:           context.SendSequence,
		rSeqNum:           context.ReceiveSequence,
		peerMaxTokenSize:  context.PeerMaxTokenSize,
		localMaxTokenSize: context.LocalMaxTokenSize,
	}
	if result.maxPlaintextSize() <= 0 {
		clear(result.subkey.KeyValue)
		return nil, fmt.Errorf("ldap: negotiated SASL token limit cannot carry protected data")
	}
	return result, nil
}

func (s *krbSASLConn) tokenFlags(sealed bool) byte {
	var flags byte
	if s.acceptorSubkey {
		flags |= krbgssapi.MICTokenFlagAcceptorSubkey
	}
	if sealed {
		flags |= krbgssapi.MICTokenFlagSealed
	}
	return flags
}

func (s *krbSASLConn) maxPlaintextSize() int {
	encType, err := crypto.GetEtype(s.subkey.KeyType)
	if err != nil {
		return 0
	}
	overhead := krbgssapi.HdrLen + encType.GetHMACBitLength()/8
	if s.mode == SASLSecuritySeal {
		overhead += krbgssapi.HdrLen + encType.GetConfounderByteSize()
	}
	return int(s.peerMaxTokenSize) - overhead
}

func (s *krbSASLConn) failed() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.failure
}

func (s *krbSASLConn) poison(err error) error {
	s.stateMu.Lock()
	if s.failure == nil {
		s.failure = err
	}
	err = s.failure
	s.stateMu.Unlock()
	// Closing the transport unblocks both directions; clearing keys waits for
	// their locks in Close, after the failing Read/Write has returned.
	s.closeOnce.Do(func() { s.closeErr = s.conn.Close() })
	return err
}

func (s *krbSASLConn) validateHeader(raw []byte) error {
	if len(raw) < krbgssapi.HdrLen || raw[0] != 5 || raw[1] != 4 || raw[3] != krbgssapi.FillerByte {
		return fmt.Errorf("ldap: invalid Kerberos SASL token header")
	}
	wanted := s.tokenFlags(s.mode == SASLSecuritySeal) | krbgssapi.MICTokenFlagSentByAcceptor
	// RFC4121 requires receivers to ignore unknown flag bits.
	if raw[2]&7 != wanted || binary.BigEndian.Uint64(raw[8:16]) != s.rSeqNum {
		return fmt.Errorf("ldap: Kerberos SASL direction, protection or sequence mismatch")
	}
	return nil
}

// Write wraps p (a complete BER-encoded LDAP message) in a Kerberos GSSAPI
// SASL frame and writes it to the underlying connection.
func (s *krbSASLConn) Write(p []byte) (int, error) {
	s.wMu.Lock()
	defer s.wMu.Unlock()
	if err := s.failed(); err != nil {
		return 0, err
	}
	// SASL frames may fragment one LDAP BER message. Enforce the peer's actual
	// output-token limit for every frame, rather than imposing a plaintext limit.
	maxPlaintext := s.maxPlaintextSize()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlaintext {
			chunk = chunk[:maxPlaintext]
		}
		var wireBytes []byte
		var err error
		if s.mode == SASLSecuritySeal {
			wireBytes, err = s.sealWrite(chunk)
		} else {
			wireBytes, err = s.signWrite(chunk)
		}
		tokenSize := int64(len(wireBytes))
		if err != nil || tokenSize > int64(s.peerMaxTokenSize) || tokenSize > 0xffffff {
			return written, s.poison(fmt.Errorf("ldap: Kerberos SASL wrapping failed or exceeded the negotiated limit"))
		}
		s.wSeqNum++
		frame := make([]byte, 4+len(wireBytes))
		binary.BigEndian.PutUint32(frame[:4], uint32(tokenSize))
		copy(frame[4:], wireBytes)
		n, err := s.conn.Write(frame)
		if err != nil || n != len(frame) {
			if err == nil {
				err = io.ErrShortWrite
			}
			return written, s.poison(err)
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// signWrite builds a WrapToken with integrity-only protection.
func (s *krbSASLConn) signWrite(p []byte) ([]byte, error) {
	encType, err := crypto.GetEtype(s.subkey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL write: %w", err)
	}
	checksumLength := encType.GetHMACBitLength() / 8
	if checksumLength <= 0 || checksumLength > 65535 {
		return nil, fmt.Errorf("ldap: invalid Kerberos SASL checksum size")
	}

	// Flags: acceptor_subkey=1, sealed=0, from_acceptor=0
	token := &krbgssapi.WrapToken{
		Flags:     s.tokenFlags(false),
		EC:        uint16(checksumLength),
		RRC:       0,
		SndSeqNum: s.wSeqNum,
		Payload:   p,
	}

	if err := token.SetCheckSum(s.subkey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL checksum: %w", err)
	}

	wireBytes, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL marshal: %w", err)
	}
	return wireBytes, nil
}

// sealWrite builds a WrapToken with confidentiality (encryption + integrity).
// Per RFC 4121 §4.2.4: encrypt(plaintext || header_copy) with EC=0, RRC=0.
func (s *krbSASLConn) sealWrite(p []byte) ([]byte, error) {
	encType, err := crypto.GetEtype(s.subkey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL write: %w", err)
	}

	// Build the 16-byte GSS header with EC=0, RRC=0 for encryption input.
	// Flags: acceptor_subkey=1, sealed=1, from_acceptor=0
	flags := s.tokenFlags(true)
	header := make([]byte, krbgssapi.HdrLen)
	header[0] = 0x05
	header[1] = 0x04
	header[2] = byte(flags)
	header[3] = krbgssapi.FillerByte
	// EC=0, RRC=0 (bytes 4-7 are already zero)
	binary.BigEndian.PutUint64(header[8:16], s.wSeqNum)

	// Construct plaintext: data || header (no filler since EC=0).
	plain := make([]byte, len(p)+krbgssapi.HdrLen)
	copy(plain, p)
	copy(plain[len(p):], header)

	// Encrypt with the etype's EncryptMessage which prepends a confounder
	// and appends an integrity HMAC.
	_, encData, err := encType.EncryptMessage(s.subkey.KeyValue, plain, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL encrypt: %w", err)
	}

	// Wire token: [header][encrypted data]
	// The header on the wire uses EC=0, RRC=0 (matching what was encrypted).
	wire := make([]byte, krbgssapi.HdrLen+len(encData))
	copy(wire, header)
	copy(wire[krbgssapi.HdrLen:], encData)
	return wire, nil
}

// Read serves unwrapped plaintext to the caller. Internally it reads complete
// Kerberos GSSAPI SASL frames, verifies/decrypts them, and buffers the plaintext.
func (s *krbSASLConn) Read(p []byte) (int, error) {
	s.rMu.Lock()
	defer s.rMu.Unlock()
	if err := s.failed(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}

	if n, ok := s.rBuf.serve(p); ok {
		return n, nil
	}

	// Read a complete SASL frame.
	var hdr [4]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return 0, s.poison(err)
	}
	msgLen := binary.BigEndian.Uint32(hdr[:])
	if msgLen > s.localMaxTokenSize {
		return 0, s.poison(fmt.Errorf("ldap: SASL frame too large for the negotiated receive limit"))
	}
	if msgLen < krbgssapi.HdrLen {
		return 0, s.poison(fmt.Errorf("ldap: SASL frame too small (%d bytes)", msgLen))
	}

	raw := make([]byte, msgLen)
	if _, err := io.ReadFull(s.conn, raw); err != nil {
		return 0, s.poison(err)
	}
	if err := s.validateHeader(raw); err != nil {
		return 0, s.poison(err)
	}

	var plaintext []byte
	var err error

	if s.mode == SASLSecuritySeal {
		plaintext, err = s.unsealRead(raw)
	} else {
		plaintext, err = s.verifyRead(raw)
	}
	if err != nil {
		return 0, s.poison(err)
	}
	s.rSeqNum++

	s.rBuf.store(plaintext)
	n, _ := s.rBuf.serve(p)
	return n, nil
}

// verifyRead parses an integrity-only WrapToken and verifies its checksum.
func (s *krbSASLConn) verifyRead(raw []byte) ([]byte, error) {
	token, err := unmarshalKrbWrapToken(raw)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL unmarshal: %w", err)
	}
	encType, err := crypto.GetEtype(s.subkey.KeyType)
	if err != nil || int(token.EC) != encType.GetHMACBitLength()/8 {
		return nil, fmt.Errorf("ldap: invalid Kerberos SASL checksum length")
	}

	if _, err := token.Verify(s.subkey, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, fmt.Errorf("ldap: Kerberos SASL integrity verification failed")
	}
	return token.Payload, nil
}

// unsealRead parses a sealed WrapToken: un-rotates by RRC, decrypts, and
// strips the trailing filler + header copy to return the plaintext.
func (s *krbSASLConn) unsealRead(raw []byte) ([]byte, error) {
	if len(raw) < krbgssapi.HdrLen {
		return nil, fmt.Errorf("ldap: sealed frame too short")
	}

	// Verify Token ID.
	if raw[0] != 0x05 || raw[1] != 0x04 {
		return nil, fmt.Errorf("ldap: wrong Token ID: expected 0504, got %02x%02x", raw[0], raw[1])
	}
	if raw[3] != krbgssapi.FillerByte {
		return nil, fmt.Errorf("ldap: unexpected filler byte: %02x", raw[3])
	}

	ec := binary.BigEndian.Uint16(raw[4:6])
	rrc := binary.BigEndian.Uint16(raw[6:8])

	encType, err := crypto.GetEtype(s.subkey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL unseal: %w", err)
	}

	// Copy the encrypted data portion (after the 16-byte header).
	data := make([]byte, len(raw)-krbgssapi.HdrLen)
	copy(data, raw[krbgssapi.HdrLen:])

	// Un-rotate if RRC > 0. Right rotation moved the last RRC bytes to
	// the front; undo by moving the first RRC bytes to the end.
	if rrc > 0 && len(data) > 0 {
		r := int(rrc) % len(data)
		if r > 0 {
			tmp := make([]byte, len(data))
			copy(tmp, data[r:])
			copy(tmp[len(data)-r:], data[:r])
			data = tmp
		}
	}

	// Decrypt: EncryptMessage output is [ciphertext(with confounder)][HMAC].
	// DecryptMessage strips the HMAC, decrypts, verifies integrity, and
	// removes the confounder, returning: plaintext_data || filler || header_copy.
	plain, err := encType.DecryptMessage(s.subkey.KeyValue, data, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL decrypt: %w", err)
	}

	// Strip trailing header_copy (16 bytes) and filler (EC bytes).
	trailerLen := int(ec) + krbgssapi.HdrLen
	if len(plain) < trailerLen {
		return nil, fmt.Errorf("ldap: decrypted payload too short: %d bytes, need %d trailer", len(plain), trailerLen)
	}
	// RFC4121 4.2.4 authenticates the original header inside the ciphertext.
	// RRC is zero for this protected header; every other byte must match.
	normalizedHeader := append([]byte(nil), raw[:krbgssapi.HdrLen]...)
	normalizedHeader[6], normalizedHeader[7] = 0, 0
	if !bytes.Equal(plain[len(plain)-krbgssapi.HdrLen:], normalizedHeader) {
		return nil, fmt.Errorf("ldap: Kerberos SASL encrypted header mismatch")
	}
	return plain[:len(plain)-trailerLen], nil
}

// unmarshalKrbWrapToken parses an integrity-only GSS WrapToken from wire bytes,
// handling RRC (Right Rotation Count) un-rotation. The server may send tokens
// where the data portion (after the 16-byte header) has been right-rotated by
// RRC bytes.
//
// Wire format after rotation: [header(16)][rotated data...]
// After un-rotation the data is: [payload][checksum(EC bytes)]
func unmarshalKrbWrapToken(b []byte) (*krbgssapi.WrapToken, error) {
	if len(b) < krbgssapi.HdrLen {
		return nil, fmt.Errorf("bytes shorter than header length")
	}

	// Verify Token ID (0x0504).
	if b[0] != 0x05 || b[1] != 0x04 {
		return nil, fmt.Errorf("wrong Token ID: expected 0504, got %02x%02x", b[0], b[1])
	}

	flags := b[2]
	if b[3] != krbgssapi.FillerByte {
		return nil, fmt.Errorf("unexpected filler byte: expected 0xFF, got %02x", b[3])
	}

	ec := binary.BigEndian.Uint16(b[4:6])
	rrc := binary.BigEndian.Uint16(b[6:8])
	seqNum := binary.BigEndian.Uint64(b[8:16])

	data := make([]byte, len(b)-krbgssapi.HdrLen)
	copy(data, b[krbgssapi.HdrLen:])

	// Un-rotate data if RRC > 0.
	// Right rotation by RRC means the last RRC bytes were moved to the front.
	// To undo: move the first RRC bytes to the end.
	if rrc > 0 && len(data) > 0 {
		r := int(rrc) % len(data)
		if r > 0 {
			tmp := make([]byte, len(data))
			copy(tmp, data[r:])
			copy(tmp[len(data)-r:], data[:r])
			data = tmp
		}
	}

	// After un-rotation: [payload][checksum(EC bytes)]
	if int(ec) > len(data) {
		return nil, fmt.Errorf("EC (%d) exceeds data length (%d)", ec, len(data))
	}

	payloadEnd := len(data) - int(ec)
	payload := data[:payloadEnd]
	checksum := data[payloadEnd:]

	return &krbgssapi.WrapToken{
		Flags:     flags,
		EC:        ec,
		RRC:       rrc,
		SndSeqNum: seqNum,
		Payload:   payload,
		CheckSum:  checksum,
	}, nil
}

// Delegate remaining net.Conn methods to the underlying connection.
func (s *krbSASLConn) Close() error {
	_ = s.poison(net.ErrClosed)
	s.wMu.Lock()
	defer s.wMu.Unlock()
	s.rMu.Lock()
	defer s.rMu.Unlock()
	clear(s.subkey.KeyValue)
	s.rBuf.buf = nil
	return s.closeErr
}
func (s *krbSASLConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *krbSASLConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *krbSASLConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *krbSASLConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *krbSASLConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
