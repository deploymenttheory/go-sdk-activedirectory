package acceptance

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/asn1tools"
	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	record "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/ssp/krb5/crypto"
)

const replicationRPCPrincipal = "RPC/11111111-2222-3333-4444-555555555555._msdcs.ad.sdk.test"

type replicationRPCFixture struct {
	listener net.Listener
	kdc      *portableKerberosKDC
	mapper   bool
	scenario string
	done     chan error
	requests atomic.Int32
	started  chan struct{}
	fixtures map[string][]byte
}

func newReplicationRPCFixture(t *testing.T, kdc *portableKerberosKDC, mapper bool, scenario string) *replicationRPCFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &replicationRPCFixture{
		listener: listener,
		kdc:      kdc,
		mapper:   mapper,
		scenario: scenario,
		done:     make(chan error, 1),
		started:  make(chan struct{}),
		fixtures: make(map[string][]byte),
	}
	for _, name := range []string{"drs-bind-response", "kind0", "kind3", "kind4", "kind5", "map-response"} {
		packageName := "drsrwire"
		if name == "map-response" {
			packageName = "epmwire"
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "3rd_party", "msrpc", packageName, "testdata", name+".hex"))
		if err != nil {
			t.Fatal(err)
		}
		f.fixtures[name], err = hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
	}
	go func() { f.done <- f.serve(t.Context()) }()
	t.Cleanup(func() { _ = listener.Close() })
	return f
}

func (f *replicationRPCFixture) wait(t *testing.T) {
	t.Helper()
	_ = f.listener.Close()
	select {
	case err := <-f.done:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned RPC fixture did not retire")
	}
}

func replicationRPCRead(connection net.Conn) ([]byte, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint16(header[8:]))
	if length < 16 {
		return nil, errors.New("synthetic RPC peer received short fragment")
	}
	frame := make([]byte, length)
	copy(frame, header)
	_, err := io.ReadFull(connection, frame[16:])
	return frame, err
}

func replicationRPCControl(token []byte) []byte {
	frame := make([]byte, 64+len(token))
	frame[0], frame[2], frame[3], frame[4] = 5, 12, 7, 16
	binary.LittleEndian.PutUint16(frame[8:], uint16(len(frame)))
	binary.LittleEndian.PutUint16(frame[10:], uint16(len(token)))
	binary.LittleEndian.PutUint32(frame[12:], 1)
	binary.LittleEndian.PutUint16(frame[16:], 4096)
	binary.LittleEndian.PutUint16(frame[18:], 4096)
	frame[28] = 1
	copy(frame[36:], []byte{4, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 8, 0, 0x2b, 0x10, 0x48, 0x60, 2, 0, 0, 0})
	frame[56], frame[57] = 16, 6
	binary.LittleEndian.PutUint32(frame[60:], 1)
	copy(frame[64:], token)
	return frame
}

func replicationRPCAPReply(key types.EncryptionKey, part messages.EncAPRepPart) ([]byte, error) {
	plain, err := asn1.Marshal(part)
	if err != nil {
		return nil, err
	}
	plain = asn1tools.AddASNAppTag(plain, 27)
	defer clear(plain)
	ed, err := krbcrypto.GetEncryptedData(plain, key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, err
	}
	token, err := asn1.Marshal(messages.APRep{PVNO: 5, MsgType: 15, EncPart: ed})
	if err != nil {
		return nil, err
	}
	return asn1tools.AddASNAppTag(token, 15), nil
}

func (f *replicationRPCFixture) serve(ctx context.Context) error {
	connection, err := f.listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if err = connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	bind, err := replicationRPCRead(connection)
	if err != nil {
		return err
	}
	if len(bind) < 80 || bind[2] != 11 {
		return errors.New("synthetic RPC peer did not receive bind")
	}
	var syntax [20]byte
	copy(syntax[:], bind[32:52])
	authLength := int(binary.LittleEndian.Uint16(bind[10:]))
	if authLength > len(bind)-80 {
		return errors.New("synthetic RPC bind authentication bounds")
	}
	var ap messages.APReq
	if err = ap.Unmarshal(bind[len(bind)-authLength:]); err != nil {
		return err
	}
	expected := "ldap/" + portableTLSHost
	if f.mapper {
		expected = replicationRPCPrincipal
	}
	if strings.Join(ap.Ticket.SName.NameString, "/") != expected {
		return errors.New("RPC stage used another service ticket")
	}
	if valid, err := ap.Verify(f.kdc.keys, 5*time.Minute, types.HostAddress{}, nil); err != nil || !valid {
		return errors.Join(errors.New("synthetic RPC service did not authenticate ticket"), err)
	}
	checksum := ap.Authenticator.Cksum.Checksum
	if len(checksum) != 24 || binary.LittleEndian.Uint32(checksum[20:]) != 0x103e {
		return errors.New("DCE authentication flags missing or delegation requested")
	}
	et, err := krbcrypto.GetEtype(18)
	if err != nil {
		return err
	}
	peerKey, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return err
	}
	defer clear(peerKey.KeyValue)
	token, err := replicationRPCAPReply(
		ap.Ticket.DecryptedEncPart.Key,
		messages.EncAPRepPart{CTime: ap.Authenticator.CTime, Cusec: ap.Authenticator.Cusec, Subkey: peerKey, SequenceNumber: 42},
	)
	if err != nil {
		return err
	}
	if _, err = connection.Write(replicationRPCControl(token)); err != nil {
		return err
	}
	third, err := replicationRPCRead(connection)
	if err != nil {
		return err
	}
	if third[2] != 16 || binary.LittleEndian.Uint32(third[12:]) != 2 {
		return errors.New("missing actual DCE third RPC leg")
	}
	var final messages.APRep
	if err = final.Unmarshal(third[len(third)-int(binary.LittleEndian.Uint16(third[10:])):]); err != nil {
		return err
	}
	plain, err := krbcrypto.DecryptEncPart(final.EncPart, ap.Ticket.DecryptedEncPart.Key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return err
	}
	defer clear(plain)
	var finalPart messages.EncAPRepPart
	if err = finalPart.Unmarshal(plain); err != nil {
		return err
	}
	if finalPart.SequenceNumber != 42 || len(finalPart.Subkey.KeyValue) != 0 {
		return errors.New("invalid DCE final sequence/subkey")
	}
	receive, err := record.NewCipher(ctx, record.CipherSetting{Type: et, Key: peerKey, IsLocal: true, IsSubKey: true, DCEStyle: true})
	if err != nil {
		return err
	}
	defer receive.Destroy()
	send, err := record.NewCipher(ctx, record.CipherSetting{Type: et, Key: peerKey, IsLocal: false, IsSubKey: true, DCEStyle: true})
	if err != nil {
		return err
	}
	defer send.Destroy()
	sendSequence, receiveSequence := uint64(42), uint64(ap.Authenticator.SeqNumber)
	for call := uint32(3); ; call++ {
		frame, err := replicationRPCRead(connection)
		if err != nil {
			return err
		}
		f.requests.Add(1)
		if frame[2] != 0 || frame[3] != 3 || binary.LittleEndian.Uint32(frame[12:]) != call {
			return errors.New("RPC call/order changed")
		}
		authLength := int(binary.LittleEndian.Uint16(frame[10:]))
		end := len(frame) - authLength - 8
		if end < 24 {
			return errors.New("RPC application authentication bounds")
		}
		trailer, body := frame[end:end+8], frame[24:end]
		if ok, err := receive.UnwrapEx(ctx, receiveSequence, [][]byte{frame[:24], body, trailer}, [][]byte{body}, frame[end+8:]); err != nil || !ok {
			return errors.Join(errors.New("RPC request not protected"), err)
		}
		receiveSequence++
		body = body[:len(body)-int(trailer[2])]
		if len(body) < 60 || !bytes.Equal(body[len(body)-40:len(body)-20], syntax[:]) {
			return errors.New("RPC verification trailer did not bind interface")
		}
		body = body[:len(body)-60]
		op := binary.LittleEndian.Uint16(frame[22:])
		var response []byte
		if f.mapper {
			if op != 3 || len(body) != 116 {
				return errors.New("unexpected endpoint-map method")
			}
			response = bytes.Clone(f.fixtures["map-response"])
			if f.scenario == "epm-refusal" || f.scenario == "epm-empty" {
				response = make([]byte, 40)
				binary.LittleEndian.PutUint32(response[24:], 1)
				if f.scenario == "epm-refusal" {
					binary.LittleEndian.PutUint32(response[36:], 1753)
				}
			}
			if f.scenario == "epm-malformed" {
				binary.LittleEndian.PutUint32(response[32:], 2)
			}
		} else {
			switch op {
			case 0:
				response = bytes.Clone(f.fixtures["drs-bind-response"])
			case 1:
				response = make([]byte, 24)
			case 19:
				if len(body) < 52 {
					return errors.New("short DRS diagnostic request")
				}
				kind := binary.LittleEndian.Uint32(body[28:])
				response = bytes.Clone(f.fixtures[fmt.Sprintf("kind%d", kind)])
				if f.scenario == "empty" {
					size := 28
					if kind == 5 {
						size = 32
					}
					response = make([]byte, size)
					binary.LittleEndian.PutUint32(response, kind)
					binary.LittleEndian.PutUint32(response[4:], kind)
					binary.LittleEndian.PutUint32(response[8:], 1)
				}
				if response == nil {
					return errors.New("unexpected DRS diagnostic type")
				}
				if f.scenario == "lost" {
					return nil
				}
				if f.scenario == "cancel" {
					close(f.started)
					var one [1]byte
					_, err = connection.Read(one[:])
					return err
				}
				if f.scenario == "refusal" && kind == 3 {
					binary.LittleEndian.PutUint32(response[len(response)-4:], 8453)
				}
				if f.scenario == "malformed" && kind == 3 {
					binary.LittleEndian.PutUint32(response[16:], 2)
				}
			default:
				return errors.New("non-diagnostic RPC operation was submitted")
			}
		}
		if err = replicationRPCRespond(
			ctx,
			connection,
			send,
			sendSequence,
			call,
			response,
			(f.scenario == "tampered" && op == 19) || f.scenario == "epm-tampered",
			f.scenario == "fault" && op == 19,
		); err != nil {
			return err
		}
		sendSequence++
		if f.mapper || op == 1 || (f.scenario == "malformed" || f.scenario == "tampered" || f.scenario == "fault") && op == 19 {
			return nil
		}
	}
}

func replicationRPCRespond(ctx context.Context, connection net.Conn, cipher record.Cipher, sequence uint64, call uint32, stub []byte, tamper, fault bool) error {
	headerSize := 24
	if fault {
		headerSize = 32
		stub = nil
	}
	pad := (-len(stub)) & 15
	end := headerSize + len(stub) + pad
	frame := make([]byte, end+8+cipher.Size(ctx, true))
	frame[0], frame[2], frame[3], frame[4] = 5, 2, 3, 16
	if fault {
		frame[2] = 3
		binary.LittleEndian.PutUint32(frame[24:], 5)
	}
	binary.LittleEndian.PutUint16(frame[8:], uint16(len(frame)))
	binary.LittleEndian.PutUint16(frame[10:], uint16(cipher.Size(ctx, true)))
	binary.LittleEndian.PutUint32(frame[12:], call)
	copy(frame[headerSize:], stub)
	trailer, body := frame[end:end+8], frame[headerSize:end]
	trailer[0], trailer[1], trailer[2] = 16, 6, byte(pad)
	binary.LittleEndian.PutUint32(trailer[4:], 1)
	token, err := cipher.WrapEx(ctx, sequence, [][]byte{frame[:headerSize], body, trailer}, [][]byte{body})
	if err != nil {
		return err
	}
	copy(frame[end+8:], token)
	if tamper {
		frame[len(frame)-1] ^= 1
	}
	_, err = connection.Write(frame)
	return err
}
