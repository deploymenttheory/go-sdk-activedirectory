package rpcwire

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type qualificationBlockedConn struct {
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
	active  atomic.Int32
}

func newQualificationBlockedConn() *qualificationBlockedConn {
	return &qualificationBlockedConn{entered: make(chan struct{}), closed: make(chan struct{})}
}

func (c *qualificationBlockedConn) Read(b []byte) (int, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	close(c.entered)
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *qualificationBlockedConn) Write(b []byte) (int, error) { return c.Read(b) }
func (c *qualificationBlockedConn) Close() error                { c.once.Do(func() { close(c.closed) }); return nil }

func TestQualificationCanceledSocketRetiresBeforeReturn(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[write], func(t *testing.T) {
			raw := newQualificationBlockedConn()
			t.Cleanup(func() { _ = raw.Close() })
			settings := NewTransport()
			settings.MaxRecvFrag, settings.MaxXmitFrag = 128, 128
			tr := &transport{settings: &settings, cc: NewBufferedConn(raw, 128)}
			ctx, cancel := context.WithCancelCause(context.Background())
			cause := errors.New("owned caller cancellation")
			done := make(chan error, 1)
			go func() {
				if write {
					done <- tr.WriteBuffer(ctx, Header{RPCVersion: 5, PacketDRep: defaultDataRepresentation(), FragLength: 24}, make([]byte, 24))
					return
				}
				_, err := tr.ReadBuffer(ctx, make([]byte, 128))
				done <- err
			}()
			select {
			case <-raw.entered:
			case err := <-done:
				t.Fatalf("I/O never started: %v", err)
			case <-time.After(time.Second):
				t.Fatal("I/O never started")
			}
			cancel(cause)
			select {
			case err := <-done:
				if !errors.Is(err, cause) {
					t.Errorf("caller cause lost: %v", err)
				}
				if raw.active.Load() != 0 {
					t.Error("returned with network I/O still owning caller buffers")
				}
				select {
				case <-raw.closed:
				default:
					t.Error("canceled connection remains open")
				}
				if tr.HasErr() == nil {
					t.Error("canceled connection remains reusable")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt I/O")
			}
		})
	}
}

func TestQualificationConfiguredTimeoutRetiresSocket(t *testing.T) {
	raw := newQualificationBlockedConn()
	t.Cleanup(func() { _ = raw.Close() })
	settings := NewTransport()
	settings.MaxRecvFrag = 128
	settings.Timeout = 10 * time.Millisecond
	tr := &transport{settings: &settings, cc: NewBufferedConn(raw, 128)}
	_, err := tr.ReadBuffer(context.Background(), make([]byte, 128))
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("configured deadline or network cause lost: %v", err)
	}
	if raw.active.Load() != 0 || tr.HasErr() == nil {
		t.Fatal("deadline returned before socket retirement")
	}
}

type qualificationShortIO struct{ closed bool }

func (*qualificationShortIO) Read([]byte) (int, error)    { return 0, nil }
func (*qualificationShortIO) Write(b []byte) (int, error) { return len(b) - 1, nil }
func (c *qualificationShortIO) Close() error              { c.closed = true; return nil }

func TestQualificationNonconformingIORetires(t *testing.T) {
	for _, write := range []bool{false, true} {
		raw := &qualificationShortIO{}
		settings := NewTransport()
		settings.MaxRecvFrag, settings.MaxXmitFrag = 128, 128
		tr := &transport{settings: &settings, cc: NewBufferedConn(raw, 128)}
		var err error
		if write {
			err = tr.WriteBuffer(context.Background(), Header{RPCVersion: 5, PacketDRep: defaultDataRepresentation(), FragLength: 24}, make([]byte, 24))
		} else {
			_, err = tr.ReadBuffer(context.Background(), make([]byte, 128))
		}
		want := io.ErrNoProgress
		if write {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) || !raw.closed || tr.HasErr() == nil {
			t.Fatalf("invalid IO reused, write=%t err=%v", write, err)
		}
	}
}
