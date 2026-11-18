package rpcwire

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/drsrwire"
)

type qualificationPeer struct {
	raw                           net.Conn
	tr                            *transport
	send, receive                 rpcRecordCipher
	sendSequence, receiveSequence uint64
	syntax                        [20]byte
	call                          uint32
}

func qualificationPeerAuthenticate(ctx context.Context, raw net.Conn, key types.EncryptionKey) (*qualificationPeer, error) {
	settings := NewTransport()
	settings.MaxRecvFrag, settings.MaxXmitFrag = 65535, 65535
	p := &qualificationPeer{raw: raw, tr: &transport{settings: &settings, cc: NewBufferedConn(raw, 65535)}}
	frame := make([]byte, 65535)
	h, err := p.tr.ReadBuffer(ctx, frame)
	if err != nil {
		return nil, err
	}
	if h.PacketType != PacketTypeBind || h.CallID != 1 || frame[28] != 0 || frame[30] != 1 {
		return nil, ErrMalformedFragment
	}
	copy(p.syntax[:], frame[32:52])
	var req messages.APReq
	if err := req.Unmarshal(frame[int(h.FragLength)-int(h.AuthLength) : h.FragLength]); err != nil {
		return nil, err
	}
	if err := req.DecryptAuthenticator(key); err != nil {
		return nil, err
	}
	peerKey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x42}, 32)}
	token, err := qualificationAPReply(key, messages.EncAPRepPart{CTime: req.Authenticator.CTime, Cusec: req.Authenticator.Cusec, Subkey: peerKey, SequenceNumber: 42})
	if err != nil {
		return nil, err
	}
	body := make([]byte, 40)
	binary.LittleEndian.PutUint16(body, 4096)
	binary.LittleEndian.PutUint16(body[2:], 4096)
	body[12] = 1
	transfer := transferSyntax()
	copy(body[20:], transfer[:])
	ack, err := controlPacket(PacketTypeBindAck, 1, body, token)
	if err != nil {
		return nil, err
	}
	ack[3] |= 4
	if _, err = raw.Write(ack); err != nil {
		return nil, err
	}
	h, err = p.tr.ReadBuffer(ctx, frame)
	if err != nil {
		return nil, err
	}
	if h.PacketType != PacketTypeAuth3 || h.CallID != 2 || h.PacketFlags != 7 {
		return nil, ErrMalformedFragment
	}
	var final messages.APRep
	if err = final.Unmarshal(frame[int(h.FragLength)-int(h.AuthLength) : h.FragLength]); err != nil {
		return nil, err
	}
	plain, err := krbcrypto.DecryptEncPart(final.EncPart, key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var part messages.EncAPRepPart
	if err = part.Unmarshal(plain); err != nil {
		return nil, err
	}
	if part.SequenceNumber != 42 || len(part.Subkey.KeyValue) != 0 {
		return nil, ErrNoSecurityContext
	}
	p.send, err = qualificationBoundCipher(peerKey, false)
	if err != nil {
		return nil, err
	}
	p.receive, err = qualificationBoundCipher(peerKey, true)
	if err != nil {
		p.send.Destroy()
		return nil, err
	}
	p.sendSequence, p.receiveSequence = 42, uint64(req.Authenticator.SeqNumber)
	return p, nil
}

func (p *qualificationPeer) close() { p.send.Destroy(); p.receive.Destroy(); _ = p.raw.Close() }

func (p *qualificationPeer) request(ctx context.Context, opnum uint16) ([]byte, error) {
	var stub []byte
	first := true
	for {
		frame := make([]byte, 65535)
		h, err := p.tr.ReadBuffer(ctx, frame)
		if err != nil {
			return nil, err
		}
		if h.PacketType != PacketTypeRequest || h.PacketFlags.IsSet(PacketFlagFirstFrag) != first || binary.LittleEndian.Uint16(frame[22:]) != opnum {
			return nil, ErrMalformedFragment
		}
		if first {
			if h.CallID != p.call+1 && !(p.call == 0 && h.CallID == 3) {
				return nil, ErrMalformedFragment
			}
			p.call = h.CallID
		} else if h.CallID != p.call {
			return nil, ErrMalformedFragment
		}
		frame = frame[:h.FragLength]
		end := len(frame) - int(h.AuthLength) - 8
		trailer, data := frame[end:end+8], frame[24:end]
		if trailer[0] != 16 || trailer[1] != 6 || binary.LittleEndian.Uint32(trailer[4:]) != 1 || int(trailer[2]) > len(data) {
			return nil, ErrMalformedFragment
		}
		ok, err := p.receive.UnwrapEx(ctx, p.receiveSequence, [][]byte{frame[:24], data, trailer}, [][]byte{data}, frame[end+8:])
		if err != nil || !ok {
			return nil, errors.Join(ErrNoSecurityContext, err)
		}
		p.receiveSequence++
		data = data[:len(data)-int(trailer[2])]
		stub = append(stub, data...)
		if h.PacketFlags.IsSet(PacketFlagLastFrag) {
			if len(data) < 60 || len(stub) < 60 {
				return nil, errors.New("verification trailer split across fragments")
			}
			vt := data[len(data)-60:]
			if !bytes.Equal(vt[:8], []byte{0x8a, 0xe3, 0x13, 0x71, 2, 0xf4, 0x36, 0x71}) || binary.LittleEndian.Uint16(vt[8:]) != 0x8001 ||
				binary.LittleEndian.Uint16(vt[10:]) != 4 || binary.LittleEndian.Uint32(vt[12:]) != 1 || binary.LittleEndian.Uint16(vt[16:]) != 0xc002 ||
				binary.LittleEndian.Uint16(vt[18:]) != 40 {
				return nil, ErrMalformedFragment
			}
			transfer := transferSyntax()
			if !bytes.Equal(vt[20:40], p.syntax[:]) || !bytes.Equal(vt[40:], transfer[:]) {
				return nil, ErrNoSecurityContext
			}
			return stub[:len(stub)-60], nil
		}
		first = false
	}
}

func (p *qualificationPeer) respond(ctx context.Context, stub []byte, fault bool) error {
	for first := true; first || len(stub) > 0; first = false {
		n := min(48, len(stub))
		last := n == len(stub)
		flags := byte(0)
		if first {
			flags |= 1
		}
		if last {
			flags |= 2
		}
		headerSize := 24
		if fault {
			headerSize = 32
		}
		pad := (-n) & 15
		end := headerSize + n + pad
		frame := make([]byte, end+8+p.send.Size(ctx, true))
		frame[0], frame[2], frame[3], frame[4] = 5, 2, flags, 16
		if fault {
			frame[2] = 3
			binary.LittleEndian.PutUint32(frame[24:], 5)
		}
		binary.LittleEndian.PutUint16(frame[8:], uint16(len(frame)))
		binary.LittleEndian.PutUint16(frame[10:], uint16(p.send.Size(ctx, true)))
		binary.LittleEndian.PutUint32(frame[12:], p.call)
		copy(frame[headerSize:], stub[:n])
		trailer, body := frame[end:end+8], frame[headerSize:end]
		trailer[0], trailer[1], trailer[2] = 16, 6, byte(pad)
		binary.LittleEndian.PutUint32(trailer[4:], 1)
		token, err := p.send.WrapEx(ctx, p.sendSequence, [][]byte{frame[:headerSize], body, trailer}, [][]byte{body})
		if err != nil {
			return err
		}
		p.sendSequence++
		copy(frame[end+8:], token)
		if _, err = p.raw.Write(frame); err != nil {
			return err
		}
		stub = stub[n:]
	}
	return nil
}

func qualificationWireFixture(t *testing.T, packageName, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../" + packageName + "/testdata/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err = hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestQualificationAuthenticatedDRSContextAndEveryDiagnosticArm(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed-final-%t", malformed), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			raw, server := net.Pipe()
			defer raw.Close()
			defer server.Close()
			actor, key := qualificationBindActor(t)
			done := make(chan error, 1)
			fixtures := map[uint32][]byte{}
			for _, kind := range []uint32{0, 3, 4, 5} {
				fixtures[kind] = qualificationWireFixture(t, "drsrwire", fmt.Sprintf("kind%d", kind))
			}
			bindReply := qualificationWireFixture(t, "drsrwire", "drs-bind-response")
			go func() {
				p, err := qualificationPeerAuthenticate(ctx, server, key)
				if err != nil {
					done <- err
					return
				}
				defer p.close()
				if _, err = p.request(ctx, 0); err == nil {
					err = p.respond(ctx, bindReply, false)
				}
				for _, kind := range []uint32{0, 3, 4, 5} {
					if err != nil {
						break
					}
					var request []byte
					request, err = p.request(ctx, 19)
					if err != nil {
						break
					}
					if len(request) != 52 || binary.LittleEndian.Uint32(request[28:]) != kind {
						err = ErrMalformedFragment
						break
					}
					response := bytes.Clone(fixtures[kind])
					if kind == 3 {
						binary.LittleEndian.PutUint32(response[len(response)-4:], 8453)
					}
					if kind == 5 && malformed {
						binary.LittleEndian.PutUint32(response[24:], 3)
					}
					err = p.respond(ctx, response, false)
				}
				if err == nil && !malformed {
					_, err = p.request(ctx, 1)
					if err == nil {
						err = p.respond(ctx, make([]byte, 24), false)
					}
				}
				done <- err
			}()
			client, err := Bind(ctx, raw, actor, DirectoryReplication, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := client.BindDiagnostics(ctx)
			if err != nil || reply.Status != 0 {
				t.Fatal(reply, err)
			}
			for _, kind := range []uint32{0, 3, 4, 5} {
				observed, err := client.ReadReplicationInfo(ctx, reply.Handle, kind, nil)
				if malformed && kind == 5 {
					if !errors.Is(err, drsrwire.ErrMalformedNDR) || observed.Count != 3 || len(observed.Operations) != 2 {
						t.Fatalf("malformed final response lost valid prefix: %+v %v", observed, err)
					}
					if _, err = client.ReadReplicationInfo(ctx, reply.Handle, 0, nil); err == nil {
						t.Fatal("malformed context reused")
					}
				} else if err != nil || kind == 3 && observed.Status != 8453 || kind != 3 && observed.Status != 0 {
					t.Fatalf("kind%d actual status/decode failed: %+v %v", kind, observed, err)
				}
			}
			if !malformed {
				if status, err := client.UnbindDiagnostics(ctx, reply.Handle); err != nil || status != 0 {
					t.Fatal(status, err)
				}
			}
			_ = client.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type qualificationSyntaxSubstitution struct{ net.Conn }

func (c *qualificationSyntaxSubstitution) Write(frame []byte) (int, error) {
	if len(frame) > 52 && PacketType(frame[2]) == PacketTypeBind {
		frame = bytes.Clone(frame)
		syntax, _ := interfaceSyntax(EndpointMapping)
		copy(frame[32:52], syntax[:])
	}
	return c.Conn.Write(frame)
}

func TestQualificationRPCBindSyntaxSubstitutionRefusedBeforeDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, server := net.Pipe()
	defer raw.Close()
	defer server.Close()
	actor, key := qualificationBindActor(t)
	done := make(chan error, 1)
	go func() {
		p, err := qualificationPeerAuthenticate(ctx, server, key)
		if err != nil {
			done <- err
			return
		}
		defer p.close()
		_, err = p.request(ctx, 19)
		if !errors.Is(err, ErrNoSecurityContext) {
			done <- errors.New("substituted interface reached dispatch")
			return
		}
		done <- p.respond(ctx, nil, true)
	}()
	client, err := Bind(ctx, &qualificationSyntaxSubstitution{raw}, actor, DirectoryReplication, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Call(ctx, 19, []byte("diagnostic"))
	var fault *rpcFaultError
	if !errors.As(err, &fault) || fault.Status != 5 {
		t.Fatalf("authenticated verification rejection lost: %v", err)
	}
	if _, err = client.Call(ctx, 19, nil); err == nil {
		t.Fatal("substituted association reused")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
