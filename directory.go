package activedirectory

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidDirectoryQuery   = errors.New("invalid directory query")
	ErrDirectoryObjectNotFound = errors.New("directory query returned no matching object")
)

// DirectoryService reads topology through the client's authenticated endpoint.
// It never discovers another endpoint, rebinds, or retains credentials.
type DirectoryService struct{ client *Client }

func (c *Client) Directory() *DirectoryService { return &DirectoryService{client: c} }

// DirectoryObservation records the raw inputs to a projection. Complete means
// all planned reads and conversions finished, not that every attribute exists
// or was visible to this identity. Sequential reads are not an atomic snapshot.
// Absent, unloaded and ranged values remain distinguishable through Object.Attribute.
type DirectoryObservation struct {
	Source   Endpoint
	RootDSE  RootDSE
	Objects  []Object
	Complete bool
}

// DirectoryReadError preserves partial, native, capability, and context errors.
type DirectoryReadError struct {
	Operation string
	Cause     error
}

func (e *DirectoryReadError) Error() string {
	return fmt.Sprintf("%s incomplete: %v", e.Operation, e.Cause)
}
func (e *DirectoryReadError) Unwrap() []error { return []error{ErrIncompleteResult, e.Cause} }

type directoryRead struct {
	client      *Client
	ctx         context.Context
	cancel      context.CancelFunc
	operation   string
	observation DirectoryObservation
	err         error
	ready       bool
	categories  map[string]*bool
}

func (d *DirectoryService) begin(ctx context.Context, operation string, requireADDS bool) (*directoryRead, error) {
	if d == nil || d.client == nil || d.client.session == nil {
		return nil, ErrClosed
	}
	// This deadline includes every public read and each wait for the client gate.
	// No gate is held here: RootDSE and Search acquire/release it themselves.
	bounded, cancel := context.WithTimeout(ctx, d.client.config.Timeout)
	r := &directoryRead{client: d.client, ctx: bounded, cancel: cancel, operation: operation, categories: make(map[string]*bool)}
	r.observation.Source = d.client.config.Endpoint
	r.observation.Complete = true
	var err error
	r.observation.RootDSE, err = d.client.RootDSE(bounded, RootDSEOptions{})
	r.add(err)
	if err == nil && requireADDS {
		r.add(r.observation.RootDSE.Capabilities().RequireADDS(operation))
	}
	r.ready = r.err == nil
	return r, nil
}

func (r *directoryRead) add(err error) {
	if err != nil {
		r.err = errors.Join(r.err, err)
		r.observation.Complete = false
	}
}

func (r *directoryRead) finish(observation *DirectoryObservation) error {
	r.add(context.Cause(r.ctx))
	if context.Cause(r.client.lifetime) != nil {
		r.add(ErrClosed)
	}
	r.cancel()
	*observation = r.observation
	if r.err != nil {
		return &DirectoryReadError{Operation: r.operation, Cause: r.err}
	}
	return nil
}

func (r *directoryRead) search(options SearchOptions) SearchResult {
	if err := context.Cause(r.ctx); err != nil {
		r.add(err)
		return SearchResult{}
	}
	result, err := r.client.Search(r.ctx, options)
	r.observation.Objects = append(r.observation.Objects, result.Objects...)
	if !result.Complete {
		r.observation.Complete = false
		if !result.LimitReached && err == nil {
			r.add(ErrIncompleteResult)
		}
	}
	for _, object := range result.Objects {
		if object.DistinguishedName == "" {
			r.add(ErrInvalidResult)
		}
		for name := range object.Attributes {
			if strings.Contains(name, ";range=") {
				r.add(ErrIncompleteResult)
			}
		}
	}
	r.add(err)
	return result
}

func (r *directoryRead) one(base, filter string, properties []string) Object {
	if base == "" {
		r.add(fmt.Errorf("%w: missing base DN for linked read", ErrIncompleteResult))
		return Object{}
	}
	result := r.search(SearchOptions{Base: base, Scope: ScopeBase, Filter: filter, Properties: properties})
	if len(result.Objects) == 1 {
		return result.Objects[0]
	}
	if len(result.Objects) > 1 {
		r.add(fmt.Errorf("%w: base read returned multiple objects", ErrInvalidResult))
	} else if result.Complete {
		r.add(ErrDirectoryObjectNotFound)
	}
	return Object{}
}

// AD Integer attributes can render a bitmask as signed decimal. Preserve all
// 32 bits while still rejecting values outside either supported representation.
func parseDirectoryMask(value string) (uint32, error) {
	if result, err := parseUint32(value); err == nil {
		return result, nil
	}
	result, err := strconv.ParseInt(value, 10, 32)
	return uint32(result), err
}

func (r *directoryRead) require(value *string, attribute string) string {
	if value == nil || *value == "" {
		r.add(fmt.Errorf("%w: required attribute %s was not returned", ErrIncompleteResult, attribute))
		return ""
	}
	return *value
}

func (r *directoryRead) selectedDomain(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if r.client.config.Partition != "" {
		return r.client.config.Partition
	}
	return r.require(r.observation.RootDSE.DefaultNamingContext, "defaultNamingContext")
}

func validDirectoryText(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

// Only fixed schema attributes and literal values are composed here. General
// PowerShell expressions and identity resolution belong to their shared layers.
func ldapLiteral(value string) string {
	var b strings.Builder
	for _, v := range []byte(value) {
		switch v {
		case 0, '(', ')', '*', '\\':
			fmt.Fprintf(&b, "\\%02x", v)
		default:
			b.WriteByte(v)
		}
	}
	return b.String()
}

// Parent traversal only splits server-returned DNs; it does not normalize or
// resolve user identities. Preserve escaped commas and quoted legacy RDNs.
func parentDirectoryDN(dn string) (string, error) {
	quoted := false
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++
		case '"':
			quoted = !quoted
		case ',':
			if !quoted && i > 0 && i+1 < len(dn) {
				return dn[i+1:], nil
			}
		}
	}
	return "", fmt.Errorf("%w: linked DN has no parent", ErrInvalidResult)
}

func (r *directoryRead) parent(dn string) string {
	parent, err := parentDirectoryDN(dn)
	r.add(err)
	return parent
}

func copiedBinary(d *rootDSEDecoder, name string, length int) []byte {
	values, ok := d.attributes[strings.ToLower(name)]
	if !ok {
		return nil
	}
	if len(values) != 1 || len(values[0]) == 0 || (length > 0 && len(values[0]) != length) {
		d.invalid(name)
		return nil
	}
	return slices.Clone(values[0])
}

const (
	wellKnownSystem         = "AB1D30F3768811D1ADED00C04FD8D5CD"
	wellKnownInfrastructure = "2FBAC1870ADE11D297C400C04FD8D5CD"
)

// Keys use the AD well-known GUID hexadecimal representation, not objectGUID
// byte order. Values are maintained by the server across container redirection.
func wellKnownContainers(d *rootDSEDecoder) map[string]string {
	values := d.texts("wellKnownObjects")
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for _, value := range values {
		parts := strings.SplitN(value, ":", 4)
		if len(parts) != 4 || parts[0] != "B" || parts[1] != "32" || len(parts[2]) != 32 || parts[3] == "" {
			d.invalid("wellKnownObjects")
			continue
		}
		if _, err := hex.DecodeString(parts[2]); err != nil {
			d.invalid("wellKnownObjects")
			continue
		}
		key := strings.ToUpper(parts[2])
		if _, exists := result[key]; exists {
			d.invalid("wellKnownObjects")
			continue
		}
		result[key] = parts[3]
	}
	return result
}

func (r *directoryRead) container(containers map[string]string, key string) string {
	value := containers[key]
	if value == "" {
		r.add(fmt.Errorf("%w: required well-known container was not returned", ErrIncompleteResult))
	}
	return value
}
