package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

var acceptedBind = []byte{0x30, 12, 2, 1, 1, 0x61, 7, 10, 1, 0, 4, 0, 4, 0}

func testProtectedRecord(payload []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...)
}

func TestRelayPreservesBoundaryAndInjectsOnlyProtectedTraffic(t *testing.T) {
	for _, scenario := range []string{"pass", "tampered", "reordered", "truncated-prefix", "truncated-body"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			client, clientRelay := net.Pipe()
			backend, backendRelay := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = backend.Close() })
			result := make(chan observations, 1)
			go func() { result <- relay(ctx, clientRelay, backendRelay, scenario) }()
			secret := []byte("opaque-credential-marker-never-in-evidence")
			bind := append([]byte{0x30, byte(len(secret))}, secret...)
			request := testProtectedRecord(bytes.Repeat([]byte{0x71}, 32))
			first := testProtectedRecord(bytes.Repeat([]byte{0x72}, 32))
			second := testProtectedRecord(bytes.Repeat([]byte{0x73}, 32))
			peerDone := make(chan error, 1)
			go func() {
				received, protected, err := readRecord(backend, func() bool { return false })
				if err != nil || protected || !bytes.Equal(received, bind) {
					peerDone <- io.ErrUnexpectedEOF
					return
				}
				if err = writeRecord(backend, acceptedBind); err != nil {
					peerDone <- err
					return
				}
				received, protected, err = readRecord(backend, func() bool { return true })
				if err != nil || !protected || !bytes.Equal(received, request) {
					peerDone <- io.ErrUnexpectedEOF
					return
				}
				err = writeRecord(backend, append(bytes.Clone(first), second...))
				if scenario != "pass" {
					err = nil // Client retirement can interrupt the deliberate fault.
				}
				peerDone <- err
			}()
			if err := writeRecord(client, bind); err != nil {
				t.Fatal(err)
			}
			response, protected, err := readRecord(client, func() bool { return false })
			if err != nil || protected || !bytes.Equal(response, acceptedBind) {
				t.Fatal("proxy changed the authentication exchange")
			}
			if err := writeRecord(client, request); err != nil {
				t.Fatal(err)
			}
			response, _, err = readRecord(client, func() bool { return true })
			switch scenario {
			case "pass":
				if err != nil || !bytes.Equal(response, first) {
					t.Fatalf("valid protected control changed: %v", err)
				}
				response, _, err = readRecord(client, func() bool { return true })
				if err != nil || !bytes.Equal(response, second) {
					t.Fatal("valid second record changed")
				}
			case "tampered":
				first[len(first)-1] ^= 1
				if err != nil || !bytes.Equal(response, first) {
					t.Fatal("fault did not alter exactly the selected protected octet")
				}
			case "reordered":
				if err != nil || !bytes.Equal(response, second) {
					t.Fatal("fault did not deliver the later protected record first")
				}
			default:
				if err == nil {
					t.Fatal("deliberate truncation returned a complete protected record")
				}
			}
			_ = client.Close()
			select {
			case observed := <-result:
				encoded, encodeErr := json.Marshal(observed)
				if encodeErr != nil || bytes.Contains(encoded, secret) || !observed.Complete || observed.ClientProtectedRecords != 1 ||
					observed.ClientRecordsAfterInjection != 0 || observed.Injected != (scenario != "pass") {
					t.Fatalf("incorrect or secret-bearing metadata: %s, %v", encoded, encodeErr)
				}
			case <-ctx.Done():
				t.Fatal("proxy did not retire both directions")
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadRecordRejectsUnboundedMalformedAndTruncatedInputs(t *testing.T) {
	for _, test := range []struct {
		wire      []byte
		protected bool
	}{
		{[]byte{0x30, 0x80}, false},
		{[]byte{0x30, 0x85}, false},
		{[]byte{0x30, 0x84, 255, 255, 255, 255}, false},
		{[]byte{0x30, 3, 1}, false},
		{[]byte{0, 0, 0, 15}, true},
		{[]byte{255, 255, 255, 255}, true},
		{[]byte{0, 0, 0}, true},
	} {
		if _, _, err := readRecord(bytes.NewReader(test.wire), func() bool { return test.protected }); err == nil {
			t.Fatal("invalid record passed fixture bounds")
		}
	}
	if !successfulBind(acceptedBind) {
		t.Fatal("valid final BindResponse was not recognized")
	}
	for _, wire := range [][]byte{nil, {0x30, 0x80}, append(bytes.Clone(acceptedBind), 0)} {
		if successfulBind(wire) {
			t.Fatal("incomplete or trailing record activated protection")
		}
	}
	refused := bytes.Clone(acceptedBind)
	refused[9] = 14
	if successfulBind(refused) {
		t.Fatal("continuing bind activated protection prematurely")
	}
}
