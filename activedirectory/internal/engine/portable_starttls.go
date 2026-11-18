package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

const InternalPortableStartTLSOID = "1.3.6.1.4.1.1466.20037"

const portableStartTLSMaxResponse = 64 * 1024

var errPortableStartTLSResponse = errors.New("invalid StartTLS extended response")

// InternalRequestPortableStartTLS performs the sole unauthenticated LDAP exchange
// before TLS. No library read loop or other outstanding operation may exist.
// RFC 4511 section 4.14 requires this response and the TLS handshake before any
// subsequent LDAP PDU. The caller owns cancellation/deadlines and closes on error.
func InternalRequestPortableStartTLS(connection io.ReadWriter) error {
	request := append([]byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}, InternalPortableStartTLSOID...)
	n, err := connection.Write(request)
	if err == nil && n != len(request) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("submit StartTLS request: %w", err)
	}
	return InternalReadPortableStartTLSResponse(connection)
}

// InternalReadPortableStartTLSResponse bounds untrusted BER and accepts only the
// matching successful ExtendedResponse, with an absent responseValue and optional
// matching responseName. Diagnostics/referrals are never logged or followed.
func InternalReadPortableStartTLSResponse(reader io.Reader) error {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("read StartTLS envelope: %w", err)
	}
	if header[0] != 0x30 {
		return errPortableStartTLSResponse
	}
	count := internalPortableBERLengthOctets(header[1])
	if count < 0 {
		return errPortableStartTLSResponse
	}
	var extra [4]byte
	if _, err := io.ReadFull(reader, extra[:count]); err != nil {
		return fmt.Errorf("read StartTLS length: %w", err)
	}
	length, err := internalPortableBERLength(header[1], extra[:count])
	if err != nil {
		return err
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return fmt.Errorf("read StartTLS result: %w", err)
	}
	return internalPortableStartTLSBody(body)
}

func internalPortableStartTLSBody(body []byte) error {
	messageID, remaining, err := internalPortableBERTake(body, 0x02)
	if err != nil {
		return err
	}
	id, err := internalPortableBERUnsigned(messageID)
	if err != nil || id != 1 {
		return errPortableStartTLSResponse
	}
	response, trailing, err := internalPortableBERTake(remaining, 0x78)
	if err != nil || len(trailing) != 0 {
		return errPortableStartTLSResponse
	}
	encodedCode, remaining, err := internalPortableBERTake(response, 0x0a)
	if err != nil {
		return err
	}
	code, err := internalPortableBERUnsigned(encodedCode)
	if err != nil {
		return err
	}
	matchedDN, remaining, err := internalPortableBERTake(remaining, 0x04)
	if err != nil {
		return err
	}
	diagnostic, remaining, err := internalPortableBERTake(remaining, 0x04)
	if err != nil {
		return err
	}
	if !utf8.Valid(matchedDN) || !utf8.Valid(diagnostic) {
		return errPortableStartTLSResponse
	}
	if code != 0 {
		return &admodel.LDAPError{Operation: "StartTLS", Code: code, MatchedDN: string(matchedDN), Diagnostic: string(diagnostic)}
	}
	if len(remaining) == 0 {
		return nil
	}
	name, trailing, err := internalPortableBERTake(remaining, 0x8a)
	if err != nil || !bytes.Equal(name, []byte(InternalPortableStartTLSOID)) || len(trailing) != 0 {
		return errPortableStartTLSResponse
	}
	return nil
}

func internalPortableBERTake(encoded []byte, tag byte) ([]byte, []byte, error) {
	if len(encoded) < 2 || encoded[0] != tag {
		return nil, nil, errPortableStartTLSResponse
	}
	count := internalPortableBERLengthOctets(encoded[1])
	if count < 0 || len(encoded) < 2+count {
		return nil, nil, errPortableStartTLSResponse
	}
	length, err := internalPortableBERLength(encoded[1], encoded[2:2+count])
	if err != nil || length > len(encoded)-2-count {
		return nil, nil, errPortableStartTLSResponse
	}
	offset := 2 + count
	return encoded[offset : offset+length], encoded[offset+length:], nil
}

func internalPortableBERLengthOctets(first byte) int {
	if first&0x80 == 0 {
		return 0
	}
	count := int(first & 0x7f)
	if count == 0 || count > 4 {
		return -1
	}
	return count
}

func internalPortableBERLength(first byte, extra []byte) (int, error) {
	if first&0x80 == 0 {
		return int(first), nil
	}
	var length uint64
	for _, value := range extra {
		length = length*256 + uint64(value)
	}
	if length > portableStartTLSMaxResponse {
		return 0, errPortableStartTLSResponse
	}
	return int(length), nil
}

func internalPortableBERUnsigned(encoded []byte) (uint32, error) {
	if len(encoded) == 0 || len(encoded) > 4 || encoded[0]&0x80 != 0 {
		return 0, errPortableStartTLSResponse
	}
	var value uint32
	for _, part := range encoded {
		value = value*256 + uint32(part)
	}
	return value, nil
}
