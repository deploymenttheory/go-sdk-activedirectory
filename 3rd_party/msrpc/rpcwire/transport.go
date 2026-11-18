package rpcwire

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

type (
	RawConn      interface{ io.ReadWriteCloser }
	BufferedConn struct{ RawConn }
)

// One raw ownership token is shared across bind I/O, application I/O and failed
// construction cleanup. Cancellation and a deferred cleanup cannot close twice.
type ownedRawConn struct {
	RawConn
	once sync.Once
	err  error
}

func (c *ownedRawConn) Close() error { c.once.Do(func() { c.err = c.RawConn.Close() }); return c.err }

func NewBufferedConn(raw RawConn, _ int) *BufferedConn { return &BufferedConn{raw} }

type Transport struct {
	MaxRecvFrag, MaxXmitFrag int
	Timeout                  time.Duration
}

func NewTransport() Transport {
	return Transport{MaxRecvFrag: 4096, MaxXmitFrag: 4096, Timeout: 30 * time.Second}
}

type transport struct {
	mu         sync.Mutex
	retireOnce sync.Once
	settings   *Transport
	cc         *BufferedConn
	err        error
	closeErr   error
}

func (t *transport) HasErr() error { t.mu.Lock(); defer t.mu.Unlock(); return t.err }
func (t *transport) WithErr(err error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.err == nil {
		t.err = err
	}
	return t.err
}

func (t *transport) WriteBuffer(ctx context.Context, header Header, frame []byte) error {
	if int(header.FragLength) > t.settings.MaxXmitFrag {
		return ErrPacketTooLong
	}
	if err := header.validatePDU(len(frame)); err != nil {
		return err
	}
	return t.boundedIO(ctx, func() error {
		n, err := t.cc.Write(frame[:header.FragLength])
		if n < 0 || n > int(header.FragLength) {
			return ErrMalformedFragment
		}
		if err == nil && n != int(header.FragLength) {
			return io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("write RPC fragment: %w", err)
		}
		return nil
	})
}

func (t *transport) ReadBuffer(ctx context.Context, frame []byte) (header Header, err error) {
	if t.settings.MaxRecvFrag < HeaderSize || t.settings.MaxRecvFrag > 65535 || len(frame) < t.settings.MaxRecvFrag {
		return header, ErrBufferTooSmall
	}
	frame = frame[:t.settings.MaxRecvFrag]
	err = t.boundedIO(ctx, func() error {
		if err := readExact(t.cc, frame[:HeaderSize]); err != nil {
			return err
		}
		var err error
		header, err = decodeHeader(frame[:HeaderSize])
		if err != nil {
			return err
		}
		if err := header.validatePDU(len(frame)); err != nil {
			return err
		}
		return readExact(t.cc, frame[HeaderSize:header.FragLength])
	})
	return header, err
}
