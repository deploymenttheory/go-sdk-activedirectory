//go:build !windows || (!amd64 && !arm64)

package activedirectory

import "context"

type unsupportedLocalServiceAccountBackend struct{}

func newLocalServiceAccountBackend() localServiceAccountBackend {
	return unsupportedLocalServiceAccountBackend{}
}
func (unsupportedLocalServiceAccountBackend) host(context.Context) (LocalServiceAccountHost, error) {
	return LocalServiceAccountHost{}, ErrUnsupported
}
func (unsupportedLocalServiceAccountBackend) installed(context.Context, string) (*bool, error) {
	return nil, ErrUnsupported
}
func (unsupportedLocalServiceAccountBackend) install(_ context.Context, _ string, _ []byte, flags uint32) LocalServiceAccountAttempt {
	return LocalServiceAccountAttempt{Operation: "NetAddServiceAccount", Flags: flags, Error: ErrUnsupported}
}
func (unsupportedLocalServiceAccountBackend) uninstall(_ context.Context, _ string, flags uint32) LocalServiceAccountAttempt {
	return LocalServiceAccountAttempt{Operation: "NetRemoveServiceAccount", Flags: flags, Error: ErrUnsupported}
}
