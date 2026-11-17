package engine

import (
	"context"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalTopologyMutationContext(
	ctx context.Context,
	c *Client,
) (context.Context, context.CancelFunc, error) {
	if c == nil || c.session == nil {
		return ctx, func() {}, admodel.ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	return bounded, cancel, nil
}
