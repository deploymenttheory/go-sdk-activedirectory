package model

import "context"

// Feature-specific controls share the native paged cursor, including cookie
// release with identical controls. Ordinary public Search behavior is unchanged.
type InternalLdapControlledSearchSession interface {
	InternalStartSearchControls(
		context.Context,
		SearchOptions,
		[]InternalLdapWriteControl,
	) (InternalSearchCursor, error)
}

type InternalControlledSearchSession struct {
	InternalDirectorySession
	InternalControls []InternalLdapWriteControl
}

func (s InternalControlledSearchSession) InternalStartSearch(
	ctx context.Context,
	options SearchOptions,
) (InternalSearchCursor, error) {
	controlled, ok := s.InternalDirectorySession.(InternalLdapControlledSearchSession)
	if !ok {
		return nil, ErrUnsupported
	}
	return controlled.InternalStartSearchControls(ctx, options, s.InternalControls)
}
