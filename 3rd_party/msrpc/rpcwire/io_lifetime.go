package rpcwire

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// boundedIO keeps buffer ownership on the calling goroutine. Cancellation closes
// the connection and is joined before return, so no detached I/O can reuse data.
func (t *transport) boundedIO(ctx context.Context, operation func() error) error {
	if err := t.HasErr(); err != nil {
		return err
	}
	if err := context.Cause(ctx); err != nil {
		return fmt.Errorf("begin RPC I/O: %w", err)
	}
	if t.settings.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.settings.Timeout)
		defer cancel()
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(joined)
		_ = t.retire(context.Cause(ctx))
	})
	err := operation()
	if !stop() {
		<-joined
	}
	err = errors.Join(err, context.Cause(ctx))
	if err != nil {
		return t.retire(err)
	}
	return nil
}

func (t *transport) retire(err error) error {
	err = errors.Join(err, t.WithErr(err))
	t.retireOnce.Do(func() { t.closeErr = t.cc.Close() })
	return errors.Join(err, t.closeErr)
}

// readExact rejects a stalled/nonconforming Reader instead of spinning forever.
func readExact(reader io.Reader, buffer []byte) error {
	for read := 0; read < len(buffer); {
		n, err := reader.Read(buffer[read:])
		if n < 0 || n > len(buffer)-read {
			return ErrMalformedFragment
		}
		read += n
		if read == len(buffer) {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) && read > 0 {
				return errors.Join(io.ErrUnexpectedEOF, err)
			}
			return fmt.Errorf("read RPC fragment: %w", err)
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
