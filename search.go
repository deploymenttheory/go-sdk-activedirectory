package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

var ErrInvalidSearch = errors.New("invalid LDAP search")

// SearchScope selects which entries relative to Base are searched. The zero
// value searches Base itself; no domain or naming context is inferred.
type SearchScope uint32

const (
	ScopeBase SearchScope = iota
	ScopeOneLevel
	ScopeSubtree
)

// SearchOptions describes an LDAP search. Filter accepts explicit raw LDAP,
// not PowerShell expressions. TypedFilter composes escaped literal values.
// They are mutually exclusive; both unset means (objectClass=*).
type SearchOptions struct {
	Base        string
	Scope       SearchScope
	Filter      string
	TypedFilter Filter
	// Properties selects LDAP attribute descriptions, replacing the defaults
	// (distinguishedName, name, objectClass, objectGUID). "*" requests the
	// server's user attributes, not every operational property. "1.1" alone
	// requests no attributes; each result still has its DistinguishedName.
	Properties []string
	// PageSize defaults to 256. ResultLimit zero reads to server completion;
	// a positive limit stops after that many objects, including within a page.
	PageSize    int
	ResultLimit int
}

func (o SearchOptions) normalized() (SearchOptions, error) {
	if o.Scope > ScopeSubtree || o.PageSize < 0 || uint64(o.PageSize) > math.MaxUint32 || o.ResultLimit < 0 {
		return SearchOptions{}, ErrInvalidSearch
	}
	if !utf8.ValidString(o.Base) || strings.ContainsRune(o.Base, 0) || !utf8.ValidString(o.Filter) || strings.ContainsRune(o.Filter, 0) {
		return SearchOptions{}, ErrInvalidSearch
	}
	if !o.TypedFilter.unset() {
		if o.Filter != "" {
			return SearchOptions{}, ErrConflictingFilters
		}
		var err error
		o.Filter, err = o.TypedFilter.nativeLDAP()
		if err != nil {
			return SearchOptions{}, err
		}
		// Keep normalization idempotent and the native search boundary unchanged.
		o.TypedFilter = Filter{}
	}
	if o.PageSize == 0 {
		o.PageSize = 256
	}
	if o.Filter == "" {
		o.Filter = "(objectClass=*)"
	}
	if len(o.Properties) == 0 {
		o.Properties = []string{"distinguishedName", "name", "objectClass", "objectGUID"}
	}
	properties := make([]string, 0, len(o.Properties))
	seen := make(map[string]bool, len(o.Properties))
	for _, name := range o.Properties {
		if name != "*" && !attributeDescription.MatchString(name) {
			return SearchOptions{}, ErrInvalidProperty
		}
		key := strings.ToLower(name)
		if !seen[key] {
			properties = append(properties, name)
			seen[key] = true
		}
	}
	if seen["1.1"] && len(properties) != 1 {
		return SearchOptions{}, ErrInvalidProperty
	}
	o.Properties = properties
	return o, nil
}

// Validate checks portable input constraints without loading Windows APIs.
// Raw LDAP grammar, DN syntax and attribute availability are server-validated.
func (o SearchOptions) Validate() error { _, err := o.normalized(); return err }

// AttributeState distinguishes not requested, requested but not returned, a
// complete returned value set, and a server-returned range requiring more reads.
type AttributeState uint8

const (
	AttributeUnloaded AttributeState = iota
	AttributeAbsent
	AttributePresent
	AttributePartial
)

// Object owns copied raw LDAP values. Keys are lowercase attribute descriptions;
// binary bytes and ranged descriptions are preserved without schema conversion.
// RequestedProperties records explicit selection. Absent does not prove an
// attribute is unset: access controls and server policy can hide values.
type Object struct {
	DistinguishedName   string
	Attributes          map[string][][]byte
	RequestedProperties []string
}

// Attribute returns raw values and their retrieval state. An unreturned name
// selected only through "*" remains Unloaded: without schema information the
// SDK cannot know whether it is an operational attribute omitted by the wildcard.
// Ranged values remain in Attributes under the exact returned range description.
func (o Object) Attribute(name string) ([][]byte, AttributeState) {
	key := strings.ToLower(name)
	if values, found := o.Attributes[key]; found {
		return values, AttributePresent
	}
	for returned := range o.Attributes {
		if strings.HasPrefix(returned, key+";range=") {
			return nil, AttributePartial
		}
	}
	for _, requested := range o.RequestedProperties {
		if strings.EqualFold(name, requested) {
			return nil, AttributeAbsent
		}
	}
	return nil, AttributeUnloaded
}

// SearchResult reports why retrieval stopped. Complete means the server ended
// the entire search successfully. LimitReached means the caller's bound stopped
// retrieval; it does not prove that additional matches exist. Always check err.
type SearchResult struct {
	Objects      []Object
	Complete     bool
	LimitReached bool
}

// SearchError explicitly identifies an incomplete search, including zero-entry
// failures. Unwrap preserves cancellation, LDAP diagnostics and cleanup errors.
type SearchError struct {
	Returned int
	Cause    error
}

func (e *SearchError) Error() string {
	return fmt.Sprintf("LDAP search incomplete after %d objects: %v", e.Returned, e.Cause)
}
func (e *SearchError) Unwrap() []error { return []error{ErrIncompleteResult, e.Cause} }

type searchCursor interface {
	next(context.Context, uint32) ([]Object, bool, error)
	close() error
}

// Search reads every page unless ResultLimit is reached or an error occurs.
// The whole search is bounded by Config.Timeout and the caller's deadline.
// Partial objects are returned with *SearchError. Client.Close cancels an active
// search, and cleanup finishes before either method releases the session.
func (c *Client) Search(ctx context.Context, options SearchOptions) (SearchResult, error) {
	if c == nil || c.session == nil {
		return SearchResult{}, ErrClosed
	}
	options, err := options.normalized()
	if err != nil {
		return SearchResult{}, err
	}
	operation, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(c.lifetime, func() { cancel(ErrClosed) })
	defer stop()
	defer cancel(nil)
	bounded, finish := context.WithTimeout(operation, c.config.Timeout)
	defer finish()
	select {
	case <-bounded.Done():
		return SearchResult{}, context.Cause(bounded)
	case <-c.lifetime.Done():
		return SearchResult{}, ErrClosed
	case <-c.gate:
	}
	defer func() { c.gate <- struct{}{} }()
	if err := context.Cause(bounded); err != nil {
		return SearchResult{}, err
	}
	if err := context.Cause(c.lifetime); err != nil {
		return SearchResult{}, err
	}
	cursor, err := c.session.startSearch(bounded, options)
	if err != nil {
		return SearchResult{}, &SearchError{Cause: err}
	}
	result, err := collectSearch(bounded, cursor, options)
	if err != nil {
		result.Complete = false
		return result, &SearchError{Returned: len(result.Objects), Cause: err}
	}
	return result, nil
}

func collectSearch(ctx context.Context, cursor searchCursor, options SearchOptions) (result SearchResult, err error) {
	defer func() { err = errors.Join(err, cursor.close(), context.Cause(ctx)) }()
	for {
		if err := context.Cause(ctx); err != nil {
			return result, err
		}
		size := options.PageSize
		if options.ResultLimit > 0 {
			remaining := options.ResultLimit - len(result.Objects)
			if remaining == 0 {
				result.LimitReached = true
				return result, nil
			}
			if size > remaining {
				size = remaining
			}
		}
		objects, done, nextErr := cursor.next(ctx, uint32(size))
		if len(objects) > size {
			nextErr = errors.Join(nextErr, fmt.Errorf("%w: server exceeded requested page size", ErrInvalidResult))
			objects = objects[:size]
		}
		for i := range objects {
			objects[i].RequestedProperties = slices.Clone(options.Properties)
		}
		result.Objects = append(result.Objects, objects...)
		if nextErr != nil {
			return result, nextErr
		}
		if done {
			result.Complete = true
			return result, nil
		}
	}
}
