package rpcwire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	record "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/ssp/krb5/crypto"
)

func qualificationRecord(t *testing.T, initiator bool) rpcRecordCipher {
	t.Helper()
	et, err := krbcrypto.GetEtype(18)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := record.NewCipher(
		context.Background(),
		record.CipherSetting{Type: et, Key: types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x71}, 32)}, IsLocal: initiator, IsSubKey: true, DCEStyle: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	return cipher.(rpcRecordCipher)
}

func qualificationResponse(ctx context.Context, cipher rpcRecordCipher, call uint32, sequence uint64, flags byte, body []byte, fault bool) ([]byte, error) {
	headerSize := 24
	ptype := PacketTypeResponse
	if fault {
		headerSize = 32
		ptype = PacketTypeFault
	}
	pad := (-len(body)) & 15
	end := headerSize + len(body) + pad
	frame := make([]byte, end+8+cipher.Size(ctx, true))
	frame[0], frame[2], frame[3], frame[4] = 5, byte(ptype), flags, 0x10
	binary.LittleEndian.PutUint16(frame[8:], uint16(len(frame)))
	binary.LittleEndian.PutUint16(frame[10:], uint16(cipher.Size(ctx, true)))
	binary.LittleEndian.PutUint32(frame[12:], call)
	binary.LittleEndian.PutUint32(frame[16:], 0xffffffff) // untrusted hint is never an allocation request
	binary.LittleEndian.PutUint16(frame[20:], 3)
	if fault {
		binary.LittleEndian.PutUint32(frame[24:], 5)
	}
	copy(frame[headerSize:], body)
	trailer := frame[end : end+8]
	trailer[0], trailer[1], trailer[2] = 16, 6, byte(pad)
	binary.LittleEndian.PutUint32(trailer[4:], 9)
	sealed := frame[headerSize:end]
	token, err := cipher.WrapEx(ctx, sequence, [][]byte{frame[:headerSize], sealed, trailer}, [][]byte{sealed})
	if err != nil {
		return nil, err
	}
	copy(frame[end+8:], token)
	return frame, nil
}

func qualificationReadRequest(ctx context.Context, tr *transport, cipher rpcRecordCipher) ([]byte, uint32, error) {
	var result []byte
	var call uint32
	for sequence := uint64(0); ; sequence++ {
		frame := make([]byte, tr.settings.MaxRecvFrag)
		hdr, err := tr.ReadBuffer(ctx, frame)
		if err != nil {
			return nil, 0, err
		}
		if hdr.PacketType != PacketTypeRequest || hdr.PacketFlags.IsSet(PacketFlagFirstFrag) != (sequence == 0) {
			return nil, 0, ErrMalformedFragment
		}
		if sequence == 0 {
			call = hdr.CallID
		} else if call != hdr.CallID {
			return nil, 0, ErrMalformedFragment
		}
		frame = frame[:hdr.FragLength]
		end := len(frame) - int(hdr.AuthLength) - 8
		trailer := frame[end : end+8]
		body := frame[24:end]
		ok, err := cipher.UnwrapEx(ctx, sequence, [][]byte{frame[:24], body, trailer}, [][]byte{body}, frame[end+8:])
		if err != nil || !ok {
			return nil, 0, errors.Join(ErrNoSecurityContext, err)
		}
		if binary.LittleEndian.Uint16(frame[22:]) != 19 {
			return nil, 0, ErrMalformedFragment
		}
		result = append(result, body[:len(body)-int(trailer[2])]...)
		if hdr.PacketFlags.IsSet(PacketFlagLastFrag) {
			return result, call, nil
		}
	}
}

func TestQualificationProtectedRPCActualStream(t *testing.T) {
	for _, mode := range []string{
		"valid", "wrong-call", "missing-first", "repeated-first", "replayed-record",
		"tampered-data", "tampered-auth", "truncated", "unsigned-fault", "authenticated-fault",
	} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			send, receive := qualificationRecord(t, true), qualificationRecord(t, false)
			stream, err := newProtectedStream(client, send, receive, 160, 3, 9)
			if err != nil {
				t.Fatal(err)
			}
			peerReceive, peerSend := qualificationRecord(t, true), qualificationRecord(t, false)
			peerDone := make(chan error, 1)
			request := bytes.Repeat([]byte("read-only-diagnostic-"), 7)
			go func() {
				defer server.Close()
				settings := NewTransport()
				settings.MaxRecvFrag, settings.MaxXmitFrag = 160, 160
				tr := &transport{settings: &settings, cc: NewBufferedConn(server, 160)}
				body, call, err := qualificationReadRequest(ctx, tr, peerReceive)
				if err != nil {
					peerDone <- err
					return
				}
				if !bytes.Equal(body, request) {
					peerDone <- fmt.Errorf("peer did not authenticate exact fragmented request")
					return
				}
				flags := byte(PacketFlagFirstFrag)
				if mode == "wrong-call" {
					call++
				}
				if mode == "missing-first" {
					flags = 0
				}
				fault := mode == "unsigned-fault" || mode == "authenticated-fault"
				if fault {
					flags |= byte(PacketFlagLastFrag)
				}
				frame, err := qualificationResponse(ctx, peerSend, call, 0, flags, []byte("copied partial "), fault)
				if err != nil {
					peerDone <- err
					return
				}
				switch mode {
				case "tampered-data":
					frame[25] ^= 1
				case "tampered-auth":
					frame[len(frame)-1] ^= 1
				case "unsigned-fault":
					binary.LittleEndian.PutUint16(frame[10:], 0)
				case "truncated":
					frame = frame[:len(frame)-7]
				}
				_, err = server.Write(frame)
				if err != nil || fault || mode == "truncated" {
					peerDone <- nil
					return
				}
				flags = byte(PacketFlagLastFrag)
				if mode == "repeated-first" {
					flags |= byte(PacketFlagFirstFrag)
				}
				sequence := uint64(1)
				if mode == "replayed-record" {
					sequence = 0
				}
				frame, err = qualificationResponse(ctx, peerSend, call, sequence, flags, []byte("complete result"), false)
				if err == nil {
					_, err = server.Write(frame)
				}
				peerDone <- nil // rejection may close the socket before the second write
			}()
			result, err := stream.exchange(ctx, 19, request)
			if mode == "valid" {
				if err != nil || string(result) != "copied partial complete result" {
					t.Fatalf("valid protected fragmented exchange failed: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("malformed protected exchange accepted")
				}
				if stream.transport.HasErr() == nil {
					t.Fatal("rejected association remains reusable")
				}
				if _, retryErr := stream.exchange(ctx, 19, nil); retryErr == nil {
					t.Fatal("poisoned association retried")
				}
				var fault *rpcFaultError
				if mode == "authenticated-fault" {
					if !errors.As(err, &fault) || fault.Status != 5 {
						t.Fatalf("authenticated status lost: %v", err)
					}
				} else if errors.As(err, &fault) {
					t.Fatal("unverified bytes became a server status")
				}
				if mode == "repeated-first" || mode == "replayed-record" {
					if string(result) != "copied partial " {
						t.Fatal("verified prefix lost or unauthenticated suffix published")
					}
				}
				if _, keyErr := send.WrapEx(ctx, 0, nil, nil); !errors.Is(keyErr, record.ErrRetiredContext) {
					t.Fatal("rejected association retained its record key")
				}
			}
			select {
			case err := <-peerDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("peer I/O leaked")
			}
		})
	}
}

func TestQualificationProtectedRPCOperationCancellation(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	send, receive := qualificationRecord(t, true), qualificationRecord(t, false)
	stream, err := newProtectedStream(client, send, receive, 256, 3, 9)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("owned protected RPC cancellation")
	peerDone := make(chan error, 1)
	peerCipher := qualificationRecord(t, true)
	go func() {
		settings := NewTransport()
		settings.MaxRecvFrag, settings.MaxXmitFrag = 256, 256
		tr := &transport{settings: &settings, cc: NewBufferedConn(server, 256)}
		_, _, err := qualificationReadRequest(context.Background(), tr, peerCipher)
		if err != nil {
			peerDone <- err
			return
		}
		cancel(cause)
		_, err = server.Read(make([]byte, 1))
		if err == nil {
			peerDone <- errors.New("canceled peer remained open")
			return
		}
		peerDone <- nil
	}()
	_, err = stream.exchange(ctx, 19, []byte("read-only"))
	if !errors.Is(err, cause) || stream.transport.HasErr() == nil {
		t.Fatalf("operation cancellation lost or association reusable: %v", err)
	}
	select {
	case err := <-peerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled peer I/O leaked")
	}
}
