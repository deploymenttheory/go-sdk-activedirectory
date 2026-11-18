// Package discovery provides native locator and directory topology reads.
package discovery

import (
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
)

// Service reads topology through the owning client's authenticated endpoint.
type Service = engine.DirectoryService

// New returns the discovery service bound to the supplied directory client.
// The service shares the client's connection and lifetime; it does not open a separate session.
func New(connection *client.Client) *Service { return connection.Directory() }
