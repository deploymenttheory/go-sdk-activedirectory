//go:build !windows || (!amd64 && !arm64)

package activedirectory

import "context"

func readReplicationNative(context.Context, Config, RootDSE, []byte, replicationRequest) (map[replicationInfo]replicationNativeReply, error) {
	return nil, ErrUnsupported
}
