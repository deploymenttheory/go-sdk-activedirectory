package ldap

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
)

// This mechanism double isolates LDAP acceptance and transport installation.
// Actual AP-REP and authenticated layer-token validation have separate tests.
type bindResultMechanism struct {
	mode       int
	key        []byte
	deleted    bool
	wrongFacts bool
	wrongLayer bool
}

func (m *bindResultMechanism) InitSecContext(string, []byte) ([]byte, bool, error) {
	return []byte("initial"), false, nil
}
func (m *bindResultMechanism) InitSecContextWithOptions(s string, b []byte, _ []int) ([]byte, bool, error) {
	return m.InitSecContext(s, b)
}
func (m *bindResultMechanism) SetSASLSecurity(mode int) { m.mode = mode }
func (m *bindResultMechanism) NegotiateSaslAuth(b []byte, _ string) ([]byte, error) {
	if !bytes.Equal(b, []byte("offer")) {
		return nil, errors.New("unexpected mechanism offer")
	}
	return []byte("selection"), nil
}
func (m *bindResultMechanism) DeleteSecContext() error {
	clear(m.key)
	m.deleted = true
	return nil
}
func (m *bindResultMechanism) AuthenticationContext() (gssapi.AuthenticationContext, error) {
	if m.deleted {
		return gssapi.AuthenticationContext{}, errors.New("context deleted before observation")
	}
	return gssapi.AuthenticationContext{MutualAuthentication: true, ChannelBindingSent: true,
		SASLSecurity: m.mode, Complete: !m.wrongFacts, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (m *bindResultMechanism) SASLContext() (gssapi.SASLSecurityContext, error) {
	mode := m.mode
	if m.wrongLayer {
		mode = 0
	}
	return gssapi.SASLSecurityContext{KeyType: 17, KeyValue: bytes.Clone(m.key), SASLSecurity: mode,
		PeerMaxTokenSize: 65535, LocalMaxTokenSize: 65535, SendSequence: 871, ReceiveSequence: 917}, nil
}

func runBindResultPeer(conn net.Conn, firstCode, finalCode uint16) error {
	for index, code := range []uint16{firstCode, finalCode} {
		request, err := ber.ReadPacket(conn)
		if err != nil {
			return err
		}
		id, err := packetInt64At(request, 0)
		if err != nil {
			return err
		}
		response := newResultProtocolOp(ApplicationBindResponse, int64(code))
		if index == 0 && code == LDAPResultSaslBindInProgress {
			response.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "offer", "Server SASL credentials"))
		}
		if _, err := conn.Write(newDecodeEnvelope(id, response).Bytes()); err != nil {
			return err
		}
		if code != LDAPResultSaslBindInProgress {
			return nil
		}
	}
	return nil
}

func TestGSSAPIBindResultRequiresAcceptedInstalledLayer(t *testing.T) {
	for _, tlsActive := range []bool{false, true} {
		for _, mode := range []SASLSecurityMode{SASLSecurityNone, SASLSecuritySign, SASLSecuritySeal} {
			t.Run(fmt.Sprintf("tls=%t/mode=%d", tlsActive, mode), func(t *testing.T) {
				client, server := net.Pipe()
				t.Cleanup(func() { _ = server.Close() })
				if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				connection := NewConn(client, tlsActive)
				connection.Start()
				t.Cleanup(func() { _ = connection.Close() })
				peer := make(chan error, 1)
				go func() { peer <- runBindResultPeer(server, LDAPResultSaslBindInProgress, LDAPResultSuccess) }()
				mechanism := &bindResultMechanism{key: bytes.Repeat([]byte{0x41}, 16)}
				result, err := connection.GSSAPIBindRequestWithResult(mechanism, &GSSAPIBindRequest{SASLSecurity: mode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := <-peer; err != nil {
					t.Fatal(err)
				}
				if !mechanism.deleted || !result.ProtectionEstablished || result.SASLSecurity != mode ||
					!result.Authentication.ChannelBindingSent || result.Authentication.ChannelBound {
					t.Fatalf("missing measured result or context cleanup: %+v", result)
				}
				if mode == SASLSecurityNone {
					if result.SASLCipherBits != 0 || result.SASLEncryptionType != 0 {
						t.Fatal("no-layer result claims SASL encryption")
					}
					return
				}
				wrapped, ok := connection.conn.(*krbSASLConn)
				if !ok || wrapped.mode != mode || !bytes.Equal(wrapped.subkey.KeyValue, bytes.Repeat([]byte{0x41}, 16)) {
					t.Fatal("accepted layer was not retained independently of mechanism deletion")
				}
				if result.SASLEncryptionType != 17 || (mode == SASLSecuritySeal && result.SASLCipherBits != 128) ||
					(mode == SASLSecuritySign && result.SASLCipherBits != 0) {
					t.Fatal("layer observations do not match installed protection")
				}
			})
		}
	}
}

func TestGSSAPIBindResultRefusesIncompleteOrUnacceptedLayer(t *testing.T) {
	for _, scenario := range []string{"early-success", "final-rejection", "final-in-progress", "incomplete-facts", "mismatched-export"} {
		t.Run(scenario, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			connection := NewConn(client, false)
			connection.Start()
			mechanism := &bindResultMechanism{key: bytes.Repeat([]byte{0x41}, 16),
				wrongFacts: scenario == "incomplete-facts", wrongLayer: scenario == "mismatched-export"}
			firstCode, finalCode := uint16(LDAPResultSaslBindInProgress), uint16(LDAPResultSuccess)
			switch scenario {
			case "early-success":
				firstCode = LDAPResultSuccess
			case "final-rejection":
				finalCode = LDAPResultInvalidCredentials
			case "final-in-progress":
				finalCode = LDAPResultSaslBindInProgress
			}
			go func() { _ = runBindResultPeer(server, firstCode, finalCode) }()
			result, err := connection.GSSAPIBindRequestWithResult(mechanism, &GSSAPIBindRequest{SASLSecurity: SASLSecuritySeal}, nil)
			if err == nil || result != nil || !connection.IsClosing() || !mechanism.deleted {
				t.Fatalf("unaccepted/incomplete layer left a usable session: result=%+v error=%v", result, err)
			}
		})
	}
}
