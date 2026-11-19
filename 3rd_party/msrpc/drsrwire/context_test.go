package drsrwire

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

func contextFixture(t *testing.T, name string) []byte {
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

func TestQualificationDRSContextCanonicalMessages(t *testing.T) {
	ctx := context.Background()
	if !bytes.Equal(BindRequest(), contextFixture(t, "drs-bind-request")) {
		t.Fatal("DRS bind differs from independent canonical encoder")
	}
	reply, err := DecodeBind(ctx, contextFixture(t, "drs-bind-response"))
	if err != nil || reply.Status != 0 || reply.Flags != 0x84001 || reply.ReplicationEpoch != 0 {
		t.Fatalf("canonical bind: %+v %v", reply, err)
	}
	if !bytes.Equal(UnbindRequest(reply.Handle), contextFixture(t, "drs-unbind-request")) {
		t.Fatal("DRS unbind differs from canonical encoder")
	}
	status, err := DecodeUnbind(ctx, contextFixture(t, "drs-unbind-response"))
	if status != 0 || err != nil {
		t.Fatal(status, err)
	}
	name := "DC=example,DC=test"
	request, err := ReplicationInfoRequest(ctx, reply.Handle, 0, &name)
	if err != nil || !bytes.Equal(request, contextFixture(t, "drs-info-request")) {
		t.Fatalf("DN query differs from canonical encoder: %v", err)
	}
	request, err = ReplicationInfoRequest(ctx, reply.Handle, 5, nil)
	if err != nil || !bytes.Equal(request, contextFixture(t, "drs-queue-request")) {
		t.Fatalf("NULL query differs from canonical encoder: %v", err)
	}
	refusal, err := DecodeBind(ctx, contextFixture(t, "drs-bind-refusal"))
	if err != nil || refusal.Status != 8453 || refusal.Handle != [20]byte{} {
		t.Fatalf("actual DRS refusal lost: %+v %v", refusal, err)
	}
}

func TestQualificationDRSBindMalformedDoesNotPublishStatusOrHandle(t *testing.T) {
	stub := contextFixture(t, "drs-bind-response")
	for n := 0; n < len(stub); n++ {
		reply, err := DecodeBind(context.Background(), stub[:n])
		if err == nil || reply.Status != 0 || reply.Handle != [20]byte{} {
			t.Fatalf("prefix%d published bind state: %+v %v", n, reply, err)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"conformance-mismatch": func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 51) },
		"zero-extension":       func(b []byte) { clear(b[8:12]) },
		"large-extension":      func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 10001) },
		"zero-handle":          func(b []byte) { clear(b[64:84]) },
	} {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(stub)
			mutate(b)
			if reply, err := DecodeBind(context.Background(), b); err == nil || reply.Handle != [20]byte{} || reply.Status != 0 {
				t.Fatalf("malformed bind accepted: %+v %v", reply, err)
			}
		})
	}
	b := bytes.Clone(stub)
	binary.LittleEndian.PutUint32(b[12:], 0x80001)
	if reply, err := DecodeBind(context.Background(), b); !errors.Is(err, ErrUnsupportedServer) || reply.Flags != 0x80001 {
		t.Fatalf("missing advertised capability became healthy: %+v %v", reply, err)
	}
	b = bytes.Clone(stub)
	binary.LittleEndian.PutUint32(b[36:], 7)
	if reply, err := DecodeBind(context.Background(), b); err != nil || reply.ReplicationEpoch != 7 {
		t.Fatalf("actual server epoch not retained: %+v %v", reply, err)
	}
}

func TestQualificationDRSRequestPreservesNullableDNAndRejectsInvalidInputs(t *testing.T) {
	var handle ContextHandle
	handle[4] = 1
	empty := ""
	nullRequest, err := ReplicationInfoRequest(context.Background(), handle, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyRequest, err := ReplicationInfoRequest(context.Background(), handle, 0, &empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(nullRequest) != 52 || len(emptyRequest) != 66 || binary.LittleEndian.Uint32(emptyRequest[32:]) == 0 {
		t.Fatal("NULL and present-empty DN collapsed")
	}
	for _, dn := range []string{"a\x00b", string([]byte{0xff}), strings.Repeat("x", 1<<16)} {
		if _, err := ReplicationInfoRequest(context.Background(), handle, 0, &dn); err == nil {
			t.Fatal("invalid DN encoding accepted")
		}
	}
	if _, err := ReplicationInfoRequest(context.Background(), handle, 1, nil); !errors.Is(err, ErrMalformedNDR) {
		t.Fatal("unsupported info type accepted")
	}
	if _, err := ReplicationInfoRequest(context.Background(), ContextHandle{}, 0, nil); !errors.Is(err, ErrMalformedNDR) {
		t.Fatal("null DRS context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReplicationInfoRequest(ctx, handle, 0, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation lost")
	}
}
