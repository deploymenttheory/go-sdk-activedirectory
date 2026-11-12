package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	maxFrameBytes = 64 * 1024
	maxLDAPBytes  = 1024 * 1024
	startTLSOID   = "1.3.6.1.4.1.1466.20037"
)

var errFraming = errors.New("unsupported LDAP framing")

// LDAP uses definite BER lengths; accept WinLDAP's non-minimal long form too.
// Read exact frame boundaries so no TLS ClientHello bytes are consumed early.
func readElement(r io.Reader) ([]byte, []byte, error) {
	header := make([]byte, 2, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, fmt.Errorf("read BER header: %w", err)
	}
	length := int(header[1])
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 {
			return nil, nil, errFraming
		}
		header = append(header, make([]byte, count)...)
		if _, err := io.ReadFull(r, header[2:]); err != nil {
			return nil, nil, fmt.Errorf("read BER length: %w", err)
		}
		var value uint64
		for _, b := range header[2:] {
			value = value<<8 | uint64(b)
		}
		if value > maxFrameBytes {
			return nil, nil, errFraming
		}
		length = int(value)
	}
	if length > maxFrameBytes-len(header) {
		return nil, nil, errFraming
	}
	frame := append(header, make([]byte, length)...)
	if _, err := io.ReadFull(r, frame[len(header):]); err != nil {
		clear(frame)
		return nil, nil, fmt.Errorf("read BER content: %w", err)
	}
	return frame, frame[len(header):], nil
}

type ldapMessage struct {
	frame   []byte
	id      []byte
	op      byte
	content []byte
}

func readLDAP(r io.Reader) (ldapMessage, error) {
	frame, body, err := readElement(r)
	if err != nil {
		return ldapMessage{}, err
	}
	fail := func() (ldapMessage, error) { clear(frame); return ldapMessage{}, errFraming }
	if frame[0] != 0x30 {
		return fail()
	}
	fields := bytes.NewReader(body)
	id, value, err := readElement(fields)
	if err != nil || id[0] != 2 || len(value) == 0 || len(value) > 4 || value[0]&0x80 != 0 {
		return fail()
	}
	var number uint32
	for _, b := range value {
		number = number<<8 | uint32(b)
	}
	if number == 0 || number > 0x7fffffff {
		return fail()
	}
	op, content, err := readElement(fields)
	if err != nil {
		return fail()
	}
	// Controls are opaque; no credentials or attribute values are decoded.
	if fields.Len() != 0 {
		controls, _, err := readElement(fields)
		if err != nil || controls[0] != 0xa0 || fields.Len() != 0 {
			clear(op)
			return fail()
		}
		clear(controls)
	}
	return ldapMessage{frame: frame, id: id, op: op[0], content: content}, nil
}

func (m *ldapMessage) clear() {
	clear(m.frame)
	clear(m.id)
	clear(m.content)
}

func (m *ldapMessage) startTLS() bool {
	if m.op != 0x77 {
		return false
	}
	reader := bytes.NewReader(m.content)
	name, value, err := readElement(reader)
	defer clear(name)
	return err == nil && name[0] == 0x80 && string(value) == startTLSOID && reader.Len() == 0
}

func (m *ldapMessage) startTLSResponse() []byte {
	body := append(append([]byte{}, m.id...), 0x78, 7, 0x0a, 1, 0, 4, 0, 4, 0)
	return append([]byte{0x30, byte(len(body))}, body...)
}
