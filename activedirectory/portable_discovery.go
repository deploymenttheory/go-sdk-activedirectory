package activedirectory

import (
	"context"

	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
)

// DialDomainController authenticates one explicitly configured portable endpoint
// and verifies its AD domain/DC identity before composing resource modules. DNS
// candidates alone are never authority. Failure closes the new session and
// preserves partial observations; the caller owns and closes a successful client.
func DialDomainController(ctx context.Context, options config.Config, selection discovery.DomainControllerSelection) (*Client, discovery.AuthenticatedController, error) {
	connection, observed, err := discovery.DialDomainController(ctx, options, selection)
	if err != nil {
		return nil, observed, err
	}
	return compose(connection), observed, nil
}
