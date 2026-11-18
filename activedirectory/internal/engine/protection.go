package engine

import (
	"context"
	"errors"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Protection reads measured session protection under the shared operation gate.
// A missing observer is unsupported; requested settings are never evidence.
// Partial observations are retained, but Complete is false whenever an error occurs.
func (c *Client) Protection(ctx context.Context) (admodel.SessionProtection, error) {
	var result admodel.SessionProtection
	err := InternalClientRead(c, ctx, func(bounded context.Context) error {
		observer, ok := c.session.(admodel.InternalSessionProtectionObserver)
		if !ok {
			return &admodel.BackendUnavailableError{
				Backend: c.config.Backend, Authentication: c.config.Authentication, Feature: "measured session protection observations",
			}
		}
		var observationErr error
		result, observationErr = observer.InternalSessionProtection(bounded)
		if !result.Complete {
			observationErr = errors.Join(observationErr, admodel.ErrIncompleteResult)
		}
		return observationErr
	})
	if err != nil {
		result.Complete = false
	}
	return result, err
}
