package drsrwire

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func qualificationFixture(t *testing.T, kind uint32) []byte {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("testdata/kind%d.hex", kind))
	if err != nil {
		t.Fatal(err)
	}
	stub, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return stub
}

func TestQualificationCanonicalNDRDiagnosticArms(t *testing.T) {
	for _, kind := range []uint32{0, 3, 4, 5} {
		stub := qualificationFixture(t, kind)
		before := bytes.Clone(stub)
		reply, err := DecodeReplicationInfo(context.Background(), kind, stub)
		if err != nil || reply.Kind != kind || !reply.Present || reply.Status != 0 {
			t.Fatalf("kind%d canonical positive failed: %v", kind, err)
		}
		if !bytes.Equal(stub, before) {
			t.Fatal("caller wire data changed")
		}
		switch kind {
		case 0:
			if len(reply.Neighbors) != 1 || reply.Neighbors[0].PartitionDN == nil || *reply.Neighbors[0].PartitionDN != "A" || reply.Neighbors[0].PartnerDN != nil ||
				reply.Neighbors[0].LastObjectUSN != -9 || reply.Neighbors[0].ReplicaFlags != 0x80000001 {
				t.Fatal("neighbor fields changed")
			}
		case 3:
			if len(reply.Failures) != 1 || reply.Failures[0].PartnerDN == nil || *reply.Failures[0].PartnerDN != "CN=peer" || reply.Failures[0].LastResult != 8453 ||
				reply.Failures[0].FailureCount != 7 {
				t.Fatal("failure values changed")
			}
		case 4:
			if len(reply.Failures) != 1 || reply.Failures[0].PartnerDN != nil || reply.Failures[0].LastResult != 0 {
				t.Fatal("reported zero-error record lost")
			}
		case 5:
			if len(reply.Operations) != 2 || reply.Operations[0].SerialNumber != 22 || reply.Operations[1].SerialNumber != 21 || reply.Operations[0].Type != 65535 ||
				reply.Operations[0].Options != 0x80000001 || reply.Operations[0].PartitionDN == nil || *reply.Operations[0].PartitionDN != "DC=example" ||
				reply.Operations[1].PartnerDN == nil || *reply.Operations[1].PartnerDN != "CN=other" || reply.Started != 0 {
				t.Fatal("queue order/unknown values changed")
			}
		}
	}
}

func TestQualificationNDRPointerPresence(t *testing.T) {
	original := qualificationFixture(t, 0)
	empty := bytes.Clone(original)
	binary.LittleEndian.PutUint32(empty[152:], 1)
	binary.LittleEndian.PutUint32(empty[160:], 1)
	binary.LittleEndian.PutUint16(empty[164:], 0)
	reply, err := DecodeReplicationInfo(context.Background(), 0, empty)
	if err != nil || reply.Neighbors[0].PartitionDN == nil || *reply.Neighbors[0].PartitionDN != "" {
		t.Fatalf("reported empty pointer lost: %v", err)
	}
	null := append(bytes.Clone(original[:152]), original[168:]...)
	binary.LittleEndian.PutUint32(null[24:], 0)
	reply, err = DecodeReplicationInfo(context.Background(), 0, null)
	if err != nil || reply.Neighbors[0].PartitionDN != nil {
		t.Fatalf("null string pointer became empty: %v", err)
	}
}

func TestQualificationNDRMalformedAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
		want   error
	}{
		{"mismatched-count", 16, 2, ErrMalformedNDR},
		{"huge-conformance", 12, 0xffffffff, ErrNDRLimit},
		{"huge-count", 16, 0xffffffff, ErrNDRLimit},
		{"union-mismatch", 4, 3, ErrMalformedNDR},
		{"string-offset", 156, 1, ErrMalformedNDR},
		{"huge-string", 152, maxStringUnits + 1, ErrNDRLimit},
		{"string-zero-count", 160, 0, ErrMalformedNDR},
		{"surrogate", 164, 0xd800, ErrMalformedNDR},
		{"interior-nul", 164, 0, ErrMalformedNDR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := qualificationFixture(t, 0)
			binary.LittleEndian.PutUint32(stub[tc.offset:], tc.value)
			reply, err := DecodeReplicationInfo(context.Background(), 0, stub)
			if !errors.Is(err, tc.want) {
				t.Fatalf("malformed NDR accepted/misclassified: %v", err)
			}
			if tc.name == "mismatched-count" && (reply.Count != 2 || len(reply.Neighbors) != 1) {
				t.Fatal("valid copied prefix or actual count lost")
			}
		})
	}
	stub := qualificationFixture(t, 0)
	for size := range len(stub) {
		if _, err := DecodeReplicationInfo(context.Background(), 0, stub[:size]); err == nil {
			t.Fatalf("truncated stub accepted at%d", size)
		}
	}
	if _, err := DecodeReplicationInfo(context.Background(), 0, append(stub, 0, 0, 0, 0)); !errors.Is(err, ErrMalformedNDR) {
		t.Fatal("trailing bytes accepted")
	}
	misplaced := qualificationFixture(t, 0)
	binary.LittleEndian.PutUint32(misplaced[12:], 0)
	reply, err := DecodeReplicationInfo(context.Background(), 0, misplaced)
	if err == nil || reply.Status != 0 {
		t.Fatal("misplaced array bytes became a DRS return status")
	}
}

func TestQualificationNDREmptyRefusalAndCancellation(t *testing.T) {
	// Complete NDR32 null output pointer plus actual Win32 status. Error outparams
	// need not identify the requested category; status is still preserved exactly.
	refusal := make([]byte, 16)
	binary.LittleEndian.PutUint32(refusal[12:], 8453)
	reply, err := DecodeReplicationInfo(context.Background(), 3, refusal)
	if err != nil || reply.Status != 8453 || reply.Present {
		t.Fatalf("actual refusal lost: %v", err)
	}
	if _, err := DecodeReplicationInfo(context.Background(), 0, make([]byte, 16)); !errors.Is(err, ErrMalformedNDR) {
		t.Fatal("missing successful container became empty")
	}
	for _, kind := range []uint32{0, 3, 4, 5} {
		size := 28
		if kind == 5 {
			size = 32
		}
		empty := make([]byte, size)
		binary.LittleEndian.PutUint32(empty, kind)
		binary.LittleEndian.PutUint32(empty[4:], kind)
		binary.LittleEndian.PutUint32(empty[8:], 9)
		reply, err := DecodeReplicationInfo(context.Background(), kind, empty)
		if err != nil || !reply.Present || reply.Count != 0 {
			t.Fatalf("actual confirmed empty kind%d failed: %v", kind, err)
		}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("owned NDR caller cancellation")
	cancel(cause)
	if _, err := DecodeReplicationInfo(ctx, 0, qualificationFixture(t, 0)); !errors.Is(err, cause) {
		t.Fatalf("NDR cancellation lost: %v", err)
	}
}
