// Package discovery provides native locator and directory topology reads.
package discovery

import (
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
)

// Service reads topology through the owning client's authenticated endpoint.
type Service = engine.DirectoryService

// New binds discovery reads to the shared directory session.
func New(connection *client.Client) *Service { return connection.Directory() }
