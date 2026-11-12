//go:build !windows || (!amd64 && !arm64)

package dccloning

import "context"

func inspectNative(context.Context) (Result, error) { return Result{}, ErrUnsupported }
func generateNative(context.Context, GenerateOptions) (Generated, error) {
	return Generated{Outcome: NotWritten}, ErrUnsupported
}
