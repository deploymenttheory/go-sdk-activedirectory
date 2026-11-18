package engine

import (
	"context"
	"fmt"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Search reads every page unless ResultLimit is reached or an error occurs.
// The whole search is bounded by Config.Timeout and the caller's deadline.
// Partial objects are returned with *SearchError. Client.Close cancels an active
// search, and cleanup finishes before either method releases the session.
func (c *Client) Search(
	ctx context.Context,
	options admodel.SearchOptions,
) (admodel.SearchResult, error) {
	if c == nil || c.session == nil {
		return admodel.SearchResult{}, admodel.ErrClosed
	}
	normalize := admodel.InternalSearchOptionsNormalized
	if c.config.Backend == admodel.BackendPortable {
		normalize = admodel.InternalPortableSearchOptionsNormalized
	}
	options, err := normalize(options)
	if err != nil {
		return admodel.SearchResult{}, err
	}
	operation, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(c.lifetime, func() { cancel(admodel.ErrClosed) }) //nolint:contextcheck // Close must cancel the inherited caller operation.
	defer stop()
	defer cancel(nil)
	bounded, finish := context.WithTimeout(operation, c.config.Timeout)
	defer finish()
	select {
	case <-bounded.Done():
		return admodel.SearchResult{}, fmt.Errorf("LDAP search cancelled: %w", context.Cause(bounded))
	case <-c.lifetime.Done():
		return admodel.SearchResult{}, admodel.ErrClosed
	case <-c.gate:
	}
	defer func() { c.gate <- struct{}{} }()
	if err := context.Cause(bounded); err != nil {
		return admodel.SearchResult{}, fmt.Errorf("LDAP search cancelled: %w", err)
	}
	if err := context.Cause(c.lifetime); err != nil { //nolint:contextcheck // The client lifetime is independent of each caller.
		return admodel.SearchResult{}, fmt.Errorf("LDAP session closed: %w", err)
	}
	cursor, err := c.session.InternalStartSearch(bounded, options)
	if err != nil {
		return admodel.SearchResult{}, &admodel.SearchError{Cause: err}
	}
	result, err := admodel.InternalCollectSearch(bounded, cursor, options)
	if err != nil {
		result.Complete = false
		return result, &admodel.SearchError{Returned: len(result.Objects), Cause: err}
	}
	return result, nil
}
