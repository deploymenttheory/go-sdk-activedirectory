//go:build !windows || (!amd64 && !arm64)

package activedirectory

import "context"

func dialNative(context.Context, Config) (directorySession, error) {
	return nil, ErrUnsupported
}
