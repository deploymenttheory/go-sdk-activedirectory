package rpcwire

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type qualificationCloseOwner struct {
	net.Conn
	count atomic.Int32
	cause error
}

func (c *qualificationCloseOwner) Close() error {
	c.count.Add(1)
	return errors.Join(c.Conn.Close(), c.cause)
}

func TestQualificationFailedBindClosesOwnedSocketOnceAndPreservesCloseCause(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, server := net.Pipe()
	defer raw.Close()
	defer server.Close()
	cause := errors.New("synthetic socket close cause")
	owner := &qualificationCloseOwner{Conn: raw, cause: cause}
	actor, key := qualificationBindActor(t)
	done := make(chan error, 1)
	go func() { done <- qualificationBindPeer(ctx, server, key, "wrong-time") }()
	client, err := Bind(ctx, owner, actor, DirectoryReplication, time.Second)
	if client != nil || !errors.Is(err, cause) || owner.count.Load() != 1 {
		t.Fatalf("failed construction lost ownership/close cause: count%d %v", owner.count.Load(), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type qualificationFailingWrite struct{ cause error }

func (*qualificationFailingWrite) Read([]byte) (int, error)  { return 0, io.EOF }
func (*qualificationFailingWrite) Write([]byte) (int, error) { return 0, io.ErrShortWrite }
func (c *qualificationFailingWrite) Close() error            { return c.cause }

func TestQualificationProtectedRetirementPreservesBothWriteAndCloseCauses(t *testing.T) {
	cause := errors.New("synthetic protected close cause")
	stream, err := newProtectedStream(&qualificationFailingWrite{cause}, qualificationRecord(t, true), qualificationRecord(t, false), 160, 3, 9)
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.exchange(context.Background(), 19, []byte("diagnostic"))
	if !errors.Is(err, io.ErrShortWrite) || !errors.Is(err, cause) {
		t.Fatalf("retirement dropped the actual I/O or close cause: %v", err)
	}
}
