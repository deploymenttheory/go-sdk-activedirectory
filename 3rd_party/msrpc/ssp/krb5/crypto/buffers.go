package crypto

import (
	"errors"
	"fmt"
	"io"
)

var errBufferType = errors.New("unsupported Kerberos message buffer type")

// writeHash preserves complete writes across the fixed RPC signing buffers.
func writeHash(writer io.Writer, parts ...any) error {
	write := func(value []byte) error {
		n, err := writer.Write(value)
		if err == nil && n != len(value) {
			return io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("write Kerberos signing buffer: %w", err)
		}
		return nil
	}
	for _, part := range parts {
		switch value := part.(type) {
		case []byte:
			if err := write(value); err != nil {
				return err
			}
		case [][]byte:
			for _, item := range value {
				if err := write(item); err != nil {
					return err
				}
			}
		default:
			return errBufferType
		}
	}
	return nil
}
