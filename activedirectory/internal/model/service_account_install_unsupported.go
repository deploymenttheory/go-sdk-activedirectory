//go:build !windows || (!amd64 && !arm64)

package model

import "context"

type InternalUnsupportedLocalServiceAccountBackend struct{}

func InternalNewLocalServiceAccountBackend() InternalLocalServiceAccountBackend {
	return InternalUnsupportedLocalServiceAccountBackend{}
}

func (InternalUnsupportedLocalServiceAccountBackend) InternalHost(
	context.Context,
) (LocalServiceAccountHost, error) {
	return LocalServiceAccountHost{}, ErrUnsupported
}

func (InternalUnsupportedLocalServiceAccountBackend) InternalInstalled(
	context.Context,
	string,
) (*bool, error) {
	return nil, ErrUnsupported
}

func (InternalUnsupportedLocalServiceAccountBackend) InternalInstall(
	_ context.Context,
	_ string,
	_ []byte,
	flags uint32,
) LocalServiceAccountAttempt {
	return LocalServiceAccountAttempt{
		Operation: "NetAddServiceAccount",
		Flags:     flags,
		Error:     ErrUnsupported,
	}
}

func (InternalUnsupportedLocalServiceAccountBackend) InternalUninstall(
	_ context.Context,
	_ string,
	flags uint32,
) LocalServiceAccountAttempt {
	return LocalServiceAccountAttempt{
		Operation: "NetRemoveServiceAccount",
		Flags:     flags,
		Error:     ErrUnsupported,
	}
}
