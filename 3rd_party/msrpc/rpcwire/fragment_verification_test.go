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
)

func TestQualificationVerificationTrailerStaysInLastProtectedFragment(t *testing.T) {
	for _, length := range []int{0, 1, 3, 4, 19, 20, 21, 63, 64, 65, 95, 96, 97, 100, 127, 128, 1024} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			raw, server := net.Pipe()
			defer raw.Close()
			defer server.Close()
			send, receive := qualificationRecord(t, true), qualificationRecord(t, false)
			stream, err := newProtectedStream(raw, send, receive, 176, 3, 9)
			if err != nil {
				t.Fatal(err)
			}
			peerReceive, peerSend := qualificationRecord(t, true), qualificationRecord(t, false)
			defer peerReceive.Destroy()
			defer peerSend.Destroy()
			syntax, _ := interfaceSyntax(DirectoryReplication)
			request, err := addVerification(bytes.Repeat([]byte{0x51}, length), syntax)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				settings := NewTransport()
				settings.MaxRecvFrag, settings.MaxXmitFrag = 176, 176
				tr := &transport{settings: &settings, cc: NewBufferedConn(server, 176)}
				var all []byte
				for sequence := uint64(0); ; sequence++ {
					frame := make([]byte, 176)
					h, err := tr.ReadBuffer(ctx, frame)
					if err != nil {
						done <- err
						return
					}
					frame = frame[:h.FragLength]
					end := len(frame) - int(h.AuthLength) - 8
					data, trailer := frame[24:end], frame[end:end+8]
					ok, err := peerReceive.UnwrapEx(ctx, sequence, [][]byte{frame[:24], data, trailer}, [][]byte{data}, frame[end+8:])
					if err != nil || !ok {
						done <- errors.Join(ErrNoSecurityContext, err)
						return
					}
					data = data[:len(data)-int(trailer[2])]
					all = append(all, data...)
					if h.PacketFlags.IsSet(PacketFlagLastFrag) {
						if len(data) < 60 || !bytes.Equal(data[len(data)-60:], request[len(request)-60:]) || !bytes.Equal(all, request) {
							done <- errors.New("verification trailer split or request bytes changed")
							return
						}
						response, err := qualificationResponse(ctx, peerSend, h.CallID, 0, 3, []byte("ok"), false)
						if err == nil {
							_, err = server.Write(response)
						}
						done <- err
						return
					}
					if len(data)%4 != 0 {
						done <- errors.New("nonfinal stub not aligned for verification trailer")
						return
					}
				}
			}()
			if _, err := stream.exchangeWithTail(ctx, 19, request, 60); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQualificationAuthenticatedEndpointMapUsesOnlyReturnedPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, server := net.Pipe()
	defer raw.Close()
	defer server.Close()
	actor, key := qualificationBindActorFor(t, "RPC/11111111-2222-3333-4444-555555555555.msdcs.example.test")
	response := qualificationWireFixture(t, "epmwire", "map-response")
	// A real issued lookup handle requires op4 on this same association.
	response[8] = 0x71
	done := make(chan error, 1)
	go func() {
		p, err := qualificationPeerAuthenticate(ctx, server, key)
		if err != nil {
			done <- err
			return
		}
		defer p.close()
		request, err := p.request(ctx, 3)
		if err == nil && (len(request) != 116 || binary.LittleEndian.Uint32(request[112:]) != 1) {
			err = ErrMalformedFragment
		}
		if err == nil {
			err = p.respond(ctx, response, false)
		}
		if err == nil {
			request, err = p.request(ctx, 4)
		}
		if err == nil && (len(request) != 20 || request[8] != 0x71) {
			err = ErrMalformedFragment
		}
		if err == nil {
			err = p.respond(ctx, make([]byte, 24), false)
		}
		done <- err
	}()
	client, err := Bind(ctx, raw, actor, EndpointMapping, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := client.MapDRSPort(ctx)
	if err != nil || reply.Port != 49153 || reply.MapStatus != 0 || reply.FreeStatus != 0 {
		t.Fatalf("actual protected EPM map/free failed: %+v %v", reply, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
