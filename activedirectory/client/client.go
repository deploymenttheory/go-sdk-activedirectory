// Package client provides the client SDK interface.
package client

import (
	context "context"

	config "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
)

// Client owns one authenticated native session.
type Client = adengine.Client

// Dial opens the generic directory session without composing resource modules.
func Dial(ctx context.Context, options config.Config) (*Client, error) {
	return adengine.Dial(ctx, options)
}
