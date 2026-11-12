//go:build !windows || (!amd64 && !arm64)

package dccloning

import "context"

func generateConfigNative(_ context.Context, options ConfigOptions) (Configured, error) {
	return Configured{Outcome: NotWritten, ChecksSkipped: options.Offline}, ErrUnsupported
}
