package activedirectory

import "context"

// Feature-specific controls share the native paged cursor, including cookie
// release with identical controls. Ordinary public Search behavior is unchanged.
type ldapControlledSearchSession interface {
	startSearchControls(context.Context, SearchOptions, []ldapWriteControl) (searchCursor, error)
}

type controlledSearchSession struct {
	directorySession
	controls []ldapWriteControl
}

func (s controlledSearchSession) startSearch(ctx context.Context, options SearchOptions) (searchCursor, error) {
	controlled, ok := s.directorySession.(ldapControlledSearchSession)
	if !ok {
		return nil, ErrUnsupported
	}
	return controlled.startSearchControls(ctx, options, s.controls)
}
