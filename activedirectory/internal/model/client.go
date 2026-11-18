package model

import (
	"context"
	"errors"
)

var (
	ErrUnsupported = errors.New(
		"active directory operation is unsupported by the selected backend or directory",
	)
	ErrClosed           = errors.New("active directory client is closed")
	ErrInvalidResult    = errors.New("invalid LDAP result")
	ErrInvalidProperty  = errors.New("invalid LDAP attribute selection")
	ErrIncompleteResult = errors.New("LDAP result requires additional retrieval")
	ErrTLSNegotiation   = errors.New("validated TLS connection could not be established")
)

// LDAPError preserves LDAP status separately from Windows system error codes.
// Diagnostic and MatchedDN may contain directory information; Error deliberately
// omits them so ordinary error logging does not disclose server diagnostics.
type LDAPError struct {
	Operation  string
	Code       uint32
	Diagnostic string
	MatchedDN  string
}

type InternalDirectorySession interface {
	InternalStartSearch(context.Context, SearchOptions) (InternalSearchCursor, error)
	InternalBaseObject(context.Context, string, []string) (map[string][][]byte, error)
	InternalRangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
	InternalClose() error
}
