package rpcwire

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/drsrwire"
)

func TestQualificationProtectedRPCNDRSessionBoundary(t *testing.T) {
	data, err := os.ReadFile("../drsrwire/testdata/kind0.hex")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []bool{false, true} {
		name := "valid"
		if malformed {
			name = "invalid-container-count"
		}
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := newProtectedStream(client, qualificationRecord(t, true), qualificationRecord(t, false), 160, 3, 9)
			if err != nil {
				t.Fatal(err)
			}
			peerReceive, peerSend := qualificationRecord(t, true), qualificationRecord(t, false)
			peerDone := make(chan error, 1)
			go func() {
				defer server.Close()
				settings := NewTransport()
				settings.MaxRecvFrag, settings.MaxXmitFrag = 160, 160
				tr := &transport{settings: &settings, cc: NewBufferedConn(server, 160)}
				_, call, err := qualificationReadRequest(ctx, tr, peerReceive)
				if err != nil {
					peerDone <- err
					return
				}
				stub := append([]byte(nil), fixture...)
				if malformed {
					binary.LittleEndian.PutUint32(stub[16:], 2)
				}
				for sequence := uint64(0); len(stub) > 0; sequence++ {
					count := min(len(stub), 32)
					flags := byte(0)
					if sequence == 0 {
						flags |= byte(PacketFlagFirstFrag)
					}
					if count == len(stub) {
						flags |= byte(PacketFlagLastFrag)
					}
					frame, err := qualificationResponse(ctx, peerSend, call, sequence, flags, stub[:count], false)
					if err == nil {
						_, err = server.Write(frame)
					}
					if err != nil {
						peerDone <- err
						return
					}
					stub = stub[count:]
				}
				peerDone <- nil
			}()
			reply, err := stream.replicationInfo(ctx, 0, []byte("synthetic read-only request stub"))
			if malformed {
				if !errors.Is(err, drsrwire.ErrMalformedNDR) || stream.transport.HasErr() == nil || reply.Count != 2 || len(reply.Neighbors) != 1 {
					t.Fatalf("invalid NDR did not retain prefix and retire stream: %v", err)
				}
			} else if err != nil || len(reply.Neighbors) != 1 || reply.Neighbors[0].PartitionDN == nil || *reply.Neighbors[0].PartitionDN != "A" {
				t.Fatalf("canonical protected NDR failed: %v", err)
			}
			select {
			case err := <-peerDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("synthetic peer leaked")
			}
		})
	}
}
