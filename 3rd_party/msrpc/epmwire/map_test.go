package epmwire

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	b, err = hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestQualificationEndpointMapCanonicalEncodingAndPort(t *testing.T) {
	if !bytes.Equal(MapRequest(), fixture(t, "map-request")) {
		t.Fatal("request differs from independent canonical encoder")
	}
	stub := fixture(t, "map-response")
	reply, err := DecodeMap(context.Background(), stub)
	if err != nil || reply.Port != 49153 || reply.Status != 0 {
		t.Fatalf("canonical map failed: %+v %v", reply, err)
	}
	// An endpoint mapper may advertise a multihomed address. It never becomes
	// an endpoint-selection input: the only returned routing datum is the port.
	copy(stub[119:123], []byte{203, 0, 113, 250})
	reply, err = DecodeMap(context.Background(), stub)
	if err != nil || reply.Port != 49153 {
		t.Fatalf("opaque advertised IPv4 affected pinned-port decoding: %v", err)
	}
	refusal, err := DecodeMap(context.Background(), fixture(t, "map-refusal"))
	if err != nil || refusal.Status != 1753 || refusal.Port != 0 {
		t.Fatalf("actual server status lost: %+v %v", refusal, err)
	}
	status, err := DecodeFree(context.Background(), fixture(t, "map-free"))
	if status != 0 || err != nil {
		t.Fatal(status, err)
	}
}

func TestQualificationEndpointMapRejectsEveryTruncation(t *testing.T) {
	stub := fixture(t, "map-response")
	for n := 0; n < len(stub); n++ {
		reply, err := DecodeMap(context.Background(), stub[:n])
		if !errors.Is(err, ErrMalformed) || reply.Status != 0 || reply.Port != 0 {
			t.Fatalf("prefix%d published an endpoint/status: %+v %v", n, reply, err)
		}
	}
}

func TestQualificationEndpointMapRejectsUnmatchedTowerAndCounts(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"num-towers":          func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 2) },
		"conformance":         func(b []byte) { binary.LittleEndian.PutUint32(b[24:], 2) },
		"offset":              func(b []byte) { binary.LittleEndian.PutUint32(b[28:], 1) },
		"actual-count":        func(b []byte) { binary.LittleEndian.PutUint32(b[32:], 0) },
		"null-tower":          func(b []byte) { clear(b[36:40]) },
		"tower-conformance":   func(b []byte) { binary.LittleEndian.PutUint32(b[40:], 0xffffffff) },
		"tower-length":        func(b []byte) { binary.LittleEndian.PutUint32(b[44:], 74) },
		"floor-count":         func(b []byte) { b[48] = 4 },
		"different-interface": func(b []byte) { b[53] ^= 1 },
		"different-transfer":  func(b []byte) { b[78] ^= 1 },
		"connectionless":      func(b []byte) { b[102] = 0x0a },
		"http":                func(b []byte) { b[109] = 0x1f },
		"invalid-ip-size":     func(b []byte) { b[117] = 16 },
	} {
		t.Run(name, func(t *testing.T) {
			stub := fixture(t, "map-response")
			mutate(stub)
			if reply, err := DecodeMap(context.Background(), stub); !errors.Is(err, ErrMalformed) || reply.Port != 0 || reply.Status != 0 {
				t.Fatalf("malformed tower published routing/status: %+v %v", reply, err)
			}
		})
	}
	stub := fixture(t, "map-response")
	clear(stub[112:114])
	if reply, err := DecodeMap(context.Background(), stub); !errors.Is(err, ErrNoEndpoint) || reply.Port != 0 {
		t.Fatalf("zero port accepted: %+v %v", reply, err)
	}
	stub = fixture(t, "map-refusal")
	clear(stub[len(stub)-4:])
	if _, err := DecodeMap(context.Background(), stub); !errors.Is(err, ErrNoEndpoint) {
		t.Fatalf("zero towers promoted to success: %v", err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("caller cancelled map")
	cancel(cause)
	if _, err := DecodeMap(ctx, fixture(t, "map-response")); !errors.Is(err, cause) {
		t.Fatal("caller cause lost")
	}
}

func TestQualificationLookupHandleIsCopied(t *testing.T) {
	var handle [20]byte
	handle[8] = 7
	request := FreeRequest(handle)
	request[8] = 1
	if handle[8] != 7 {
		t.Fatal("lookup handle aliased request")
	}
}
