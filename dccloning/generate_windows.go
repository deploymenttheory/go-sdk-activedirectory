//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
)

func generateNative(ctx context.Context, options GenerateOptions) (Generated, error) {
	api := systemAPI()
	if err := api.available(true); err != nil {
		return Generated{Outcome: NotWritten}, err
	}
	publish := func(temporary, destination string, overwrite bool) error {
		flags := filesystem.MOVEFILE_WRITE_THROUGH
		if overwrite {
			flags |= filesystem.MOVEFILE_REPLACE_EXISTING
		}
		return nativeFailure("MoveFileExW", api.move(temporary, &destination, flags))
	}
	return generate(ctx, nativeMachine{api}, options, readList, publish)
}
