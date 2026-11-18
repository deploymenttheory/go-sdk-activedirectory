package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/errorcode"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
)

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	if cause := kdcContextCause(cl.settings.context()); cause != nil {
		return nil, cause
	}
	var rb []byte
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		// 1 means we should always use TCP
		rb, errtcp := cl.sendKDCTCP(realm, b)
		if errtcp != nil {
			var e messages.KRBError
			if errors.As(errtcp, &e) {
				return rb, e
			}
			return rb, fmt.Errorf("communication error with KDC via TCP: %w", errtcp)
		}
		return rb, nil
	}
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		// Try UDP first, TCP second
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			var e messages.KRBError
			if errors.As(errudp, &e) && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Got a KRBError from KDC
				// If this is not a KRB_ERR_RESPONSE_TOO_BIG we will return immediately otherwise will try TCP.
				return rb, e
			}
			// Try TCP
			r, errtcp := cl.sendKDCTCP(realm, b)
			if errtcp != nil {
				var e messages.KRBError
				if errors.As(errtcp, &e) {
					// Got a KRBError
					return r, e
				}
				return r, fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%w) and then TCP (%w)", errudp, errtcp)
			}
			rb = r
		}
		return rb, nil
	}
	// Try TCP first, UDP second
	rb, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp != nil {
		var e messages.KRBError
		if errors.As(errtcp, &e) {
			// Got a KRBError from KDC so returning and not trying UDP.
			return rb, e
		}
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			var e messages.KRBError
			if errors.As(errudp, &e) {
				// Got a KRBError
				return rb, e
			}
			return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with TCP (%w) and then UDP (%w)", errtcp, errudp)
		}
	}
	return rb, nil
}

// sendKDCUDP sends bytes to the KDC via UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) ([]byte, error) {
	var r []byte
	kdcs, err := cl.kdcAddresses(realm, "udp")
	if err != nil {
		return r, err
	}
	r, err = dialSendKDCContext(cl.settings.context(), "udp", kdcs, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialSendUDP establishes a UDP connection to a KDC.
func dialSendUDP(kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []error
	for i := 1; i <= len(kdcs); i++ {
		// Retained context-free API; both connection establishment and I/O are bounded.
		//nolint:noctx // This retained API has no context parameter; its five-second bounds remain enforced.
		conn, err := net.DialTimeout("udp", kdcs[i], 5*time.Second)
		if err != nil {
			errs = append(errs, fmt.Errorf("error establishing connection to %s: %w", kdcs[i], err))
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			_ = conn.Close()
			errs = append(errs, fmt.Errorf("error setting deadline on connection to %s: %w", kdcs[i], err))
			continue
		}
		// conn is guaranteed to be a UDPConn
		rb, err := sendUDP(conn.(*net.UDPConn), b)
		if err != nil {
			errs = append(errs, fmt.Errorf("error sending to %s: %w", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, fmt.Errorf("error sending to a KDC: %w", errors.Join(errs...))
}

// sendUDP sends bytes to connection over UDP.
func sendUDP(conn *net.UDPConn, b []byte) ([]byte, error) {
	var r []byte
	defer conn.Close()
	n, err := conn.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %w", conn.RemoteAddr().String(), err)
	}
	udpbuf := make([]byte, 4096)
	n, _, err = conn.ReadFrom(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %w", conn.RemoteAddr().String(), err)
	}
	if len(r) < 1 {
		return r, fmt.Errorf("no response data from %s", conn.RemoteAddr().String())
	}
	return r, nil
}

// sendKDCTCP sends bytes to the KDC via TCP.
func (cl *Client) sendKDCTCP(realm string, b []byte) ([]byte, error) {
	var r []byte
	kdcs, err := cl.kdcAddresses(realm, "tcp")
	if err != nil {
		return r, err
	}
	r, err = dialSendKDCContext(cl.settings.context(), "tcp", kdcs, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialKDCTCP establishes a TCP connection to a KDC.
func dialSendTCP(kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []error
	for i := 1; i <= len(kdcs); i++ {
		// Retained context-free API; both connection establishment and I/O are bounded.
		//nolint:noctx // This retained API has no context parameter; its five-second bounds remain enforced.
		conn, err := net.DialTimeout("tcp", kdcs[i], 5*time.Second)
		if err != nil {
			errs = append(errs, fmt.Errorf("error establishing connection to %s: %w", kdcs[i], err))
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			_ = conn.Close()
			errs = append(errs, fmt.Errorf("error setting deadline on connection to %s: %w", kdcs[i], err))
			continue
		}
		// conn is guaranteed to be a TCPConn
		rb, err := sendTCP(conn.(*net.TCPConn), b)
		if err != nil {
			errs = append(errs, fmt.Errorf("error sending to %s: %w", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, fmt.Errorf("error sending to a KDC: %w", errors.Join(errs...))
}

// Bound peer-controlled allocation independently of the RFC 4120 31-bit wire limit.
const maxKDCMessageSize = 16 * 1024 * 1024

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn net.Conn, b []byte) ([]byte, error) {
	defer conn.Close()
	var r []byte
	requestSize := len(b)
	if requestSize > maxKDCMessageSize {
		return nil, fmt.Errorf("KDC request exceeds %d-byte bound", maxKDCMessageSize)
	}
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(hb, uint32(requestSize))
	b = append(hb, b...)

	n, err := conn.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %w", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4, 4)
	_, err = io.ReadFull(conn, sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %w", err)
	}
	s := binary.BigEndian.Uint32(sh)
	if s == 0 || s > maxKDCMessageSize {
		return nil, fmt.Errorf("KDC response length %d is outside 1..%d", s, maxKDCMessageSize)
	}

	rb := make([]byte, s, s)
	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %w", err)
	}
	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return rb, nil
}

// checkForKRBError checks if the response bytes from the KDC are a KRBError.
func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
