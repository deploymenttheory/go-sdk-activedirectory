package acceptance

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
)

// The fixture implements the acceptor direction independently of the private
// production wrapper. It validates actual tokens on a TCP connection after the
// real AS/TGS/AP exchange; it never substitutes a bind result or SDK session.
type portableSASLPeer struct {
	net.Conn
	key          types.EncryptionKey
	mode         ldap.SASLSecurityMode
	sendSequence uint64
	recvSequence uint64
	pending      []byte
	readFrames   atomic.Int32
	writeFrames  atomic.Int32
	corrupt      string
}

func (p *portableSASLPeer) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if len(p.pending) != 0 {
		n := copy(buffer, p.pending)
		p.pending = p.pending[n:]
		return n, nil
	}
	var prefix [4]byte
	if _, err := io.ReadFull(p.Conn, prefix[:]); err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size < 16 || size > 100 {
		return 0, errors.New("SDK submitted an unprotected or oversized application token")
	}
	wire := make([]byte, size)
	if _, err := io.ReadFull(p.Conn, wire); err != nil {
		return 0, err
	}
	flags := byte(4)
	if p.mode == ldap.SASLSecuritySeal {
		flags |= 2
	}
	if wire[0] != 5 || wire[1] != 4 || wire[2] != flags || wire[3] != 255 || binary.BigEndian.Uint64(wire[8:16]) != p.recvSequence {
		return 0, errors.New("SDK submitted an application token with incorrect protection, direction or sequence")
	}
	var plain []byte
	if p.mode == ldap.SASLSecuritySign {
		var token krbgss.WrapToken
		if err := token.Unmarshal(wire, false); err != nil {
			return 0, err
		}
		if ok, err := token.Verify(p.key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil || !ok {
			return 0, errors.New("SDK application signature did not verify")
		}
		plain = bytes.Clone(token.Payload)
	} else {
		et, err := crypto.GetEtype(p.key.KeyType)
		if err != nil {
			return 0, err
		}
		plain, err = et.DecryptMessage(p.key.KeyValue, wire[16:], keyusage.GSSAPI_INITIATOR_SEAL)
		if err != nil || len(plain) < 16 || !bytes.Equal(plain[len(plain)-16:], wire[:16]) {
			return 0, errors.New("SDK encrypted application token did not verify")
		}
		plain = plain[:len(plain)-16]
	}
	p.recvSequence++
	p.readFrames.Add(1)
	if len(plain) == 0 {
		return 0, errors.New("SDK emitted an empty application fragment")
	}
	p.pending = plain
	n := copy(buffer, p.pending)
	p.pending = p.pending[n:]
	return n, nil
}

func (p *portableSASLPeer) token(plain []byte, seq uint64) ([]byte, error) {
	et, err := crypto.GetEtype(p.key.KeyType)
	if err != nil {
		return nil, err
	}
	if p.mode == ldap.SASLSecuritySign {
		token := &krbgss.WrapToken{Flags: 5, EC: uint16(et.GetHMACBitLength() / 8), SndSeqNum: seq, Payload: plain}
		if err := token.SetCheckSum(p.key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
			return nil, err
		}
		return token.Marshal()
	}
	header := []byte{5, 4, 7, 255, 0, 0, 0, 0}
	header = binary.BigEndian.AppendUint64(header, seq)
	input := append(bytes.Clone(plain), header...)
	defer clear(input)
	_, encrypted, err := et.EncryptMessage(p.key.KeyValue, input, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, err
	}
	return append(header, encrypted...), nil
}

func (p *portableSASLPeer) Write(plain []byte) (int, error) {
	if p.corrupt == "plaintext" {
		n, err := p.Conn.Write(plain)
		_ = p.Conn.Close()
		return n, err
	}
	written := 0
	for len(plain) != 0 {
		chunk := plain
		if len(chunk) > 64 {
			chunk = chunk[:64]
		}
		seq := p.sendSequence
		if p.corrupt == "reordered" {
			seq++
		}
		wire, err := p.token(chunk, seq)
		if err != nil {
			return written, err
		}
		p.sendSequence++
		if p.corrupt == "tampered" {
			wire[len(wire)-1] ^= 1
		}
		frame := binary.BigEndian.AppendUint32(nil, uint32(len(wire)))
		frame = append(frame, wire...)
		if p.corrupt == "truncated-prefix" {
			frame = frame[:3]
		} else if p.corrupt == "truncated-body" {
			frame = frame[:len(frame)-1]
		}
		if _, err := p.Conn.Write(frame); err != nil {
			return written, err
		}
		p.writeFrames.Add(1)
		if p.corrupt != "" {
			_ = p.Conn.Close()
			return len(plain), nil
		}
		written += len(chunk)
		plain = plain[len(chunk):]
	}
	return written, nil
}
