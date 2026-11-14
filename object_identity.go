package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidIdentity     = errors.New("invalid explicit directory identity")
	ErrUnsupportedIdentity = errors.New("identity form is not supported for this operation")
	ErrIdentityScope       = errors.New("identity is outside the selected naming context")
	ErrAmbiguousIdentity   = errors.New("identity matches more than one object")
)

type IdentityForm uint8

const (
	IdentityFormDN IdentityForm = iota + 1
	IdentityFormGUID
	IdentityFormSID
	IdentityFormAccountName
)

// Identity has an explicit form; the SDK never guesses whether text is a DN,
// GUID, SID, account name or filter. Its zero value is invalid.
type Identity struct {
	form   IdentityForm
	value  string
	binary []byte
}

func (i Identity) Form() IdentityForm { return i.form }

// String is the identity's value without its form, because that is what a
// diagnostic wants to show. It is deliberately not round-trippable: the four
// forms are not distinguishable by inspection, and guessing which one a string
// is is exactly what this type exists to prevent. Use MarshalText to persist
// an identity and ParseIdentity to read one back.
func (i Identity) String() string { return i.value }

// identityFormNames are the prefixes of the round-trippable text form. They
// are part of the API: a persisted identity must still parse after an upgrade,
// so a name here may be added but never changed or reused.
var identityFormNames = map[IdentityForm]string{
	IdentityFormDN:          "dn",
	IdentityFormGUID:        "guid",
	IdentityFormSID:         "sid",
	IdentityFormAccountName: "sam",
}

// String names the form. The zero value is reported rather than treated as a
// default, because no form is a reasonable guess.
func (f IdentityForm) String() string {
	if name, ok := identityFormNames[f]; ok {
		return name
	}
	return "invalid identity form"
}

// MarshalText encodes the identity as its form, a colon, and its value —
// "guid:9b4a…", "dn:CN=sdk,DC=example,DC=test". Unlike String this round-trips
// through ParseIdentity, so it is the encoding to use for an identifier that
// has to survive being written down: a stored resource identifier, a command
// line argument, a line in an artifact.
//
// The zero Identity has no form and is refused rather than encoded, so an
// unset identity cannot be persisted as though it named something.
func (i Identity) MarshalText() ([]byte, error) {
	name, ok := identityFormNames[i.form]
	if !ok {
		return nil, ErrInvalidIdentity
	}
	return []byte(name + ":" + i.value), nil
}

// UnmarshalText parses the encoding MarshalText produces. It validates through
// the same constructors as any other identity, so a malformed value is refused
// here rather than at the first read.
func (i *Identity) UnmarshalText(text []byte) error {
	parsed, err := ParseIdentity(string(text))
	if err != nil {
		return err
	}
	*i = parsed
	return nil
}

// ParseIdentity reads the form-prefixed encoding MarshalText produces and
// returns the identity it names. It is the inverse of MarshalText and the only
// way to recover an identity from text, because an unprefixed value does not
// say which form it is.
//
// Parsing dispatches to IdentityByDN, IdentityByGUID, IdentityBySID or
// IdentityByAccountName, so every validation those apply applies here too, and
// a GUID or SID reconstructs the same bytes it was built from. Only the first
// colon separates the prefix from the value, so a distinguished name holding
// one is unaffected.
func ParseIdentity(value string) (Identity, error) {
	prefix, remainder, found := strings.Cut(value, ":")
	if !found {
		return Identity{}, fmt.Errorf(
			"%w: text identity needs an explicit form prefix (dn, guid, sid or sam)",
			ErrInvalidIdentity)
	}
	switch prefix {
	case identityFormNames[IdentityFormDN]:
		return IdentityByDN(remainder)
	case identityFormNames[IdentityFormGUID]:
		return IdentityByGUID(remainder)
	case identityFormNames[IdentityFormSID]:
		return IdentityBySID(remainder)
	case identityFormNames[IdentityFormAccountName]:
		return IdentityByAccountName(remainder)
	}
	return Identity{}, fmt.Errorf("%w: unknown identity form %q", ErrInvalidIdentity, prefix)
}

func IdentityByDN(value string) (Identity, error) {
	if _, err := parseIdentityDN(value); err != nil {
		return Identity{}, err
	}
	return Identity{form: IdentityFormDN, value: value}, nil
}
func IdentityByGUID(value string) (Identity, error) {
	guid, err := ParseGUID(value)
	if err != nil {
		return Identity{}, errors.Join(ErrInvalidIdentity, err)
	}
	return Identity{form: IdentityFormGUID, value: guid.String(), binary: guid.Bytes()}, nil
}
func IdentityBySID(value string) (Identity, error) {
	sid, err := ParseSID(value)
	if err != nil {
		return Identity{}, errors.Join(ErrInvalidIdentity, err)
	}
	return Identity{form: IdentityFormSID, value: sid.String(), binary: sid.Bytes()}, nil
}

// IdentityByAccountName selects a literal unqualified sAMAccountName. UPN and
// DOMAIN\name are not aliases for it. No wildcard expansion is performed.
func IdentityByAccountName(value string) (Identity, error) {
	if value == "" || !validDirectoryText(value) || strings.ContainsAny(value, `\/@`) {
		return Identity{}, ErrInvalidIdentity
	}
	return Identity{form: IdentityFormAccountName, value: value}, nil
}

// IdentityTarget defines this operation's allowed forms. Generic object reads
// accept DN/GUID; AD DS account reads additionally accept SID/sAMAccountName and
// require objectSid to be present. Future operations must choose their own rule.
type IdentityTarget uint8

const (
	IdentityTargetObject IdentityTarget = iota
	IdentityTargetAccount
)

type ResolveIdentityOptions struct {
	Target IdentityTarget
	// Partition overrides Config.Partition. If both are empty, a DN selects
	// its longest advertised NC; other forms use defaultNamingContext.
	Partition  string
	Properties []string
}

// IdentityResult retains up to two raw candidates even on ambiguity or search
// failure. Object is set only after complete, unique, in-scope resolution.
// Complete does not assert every selected attribute was visible or returned.
type IdentityResult struct {
	Source     Endpoint
	Partition  string
	Object     *Object
	Candidates []Object
	Complete   bool
}

func validateIdentityOperation(identity Identity, options ResolveIdentityOptions) error {
	if identity.form < IdentityFormDN || identity.form > IdentityFormAccountName || options.Target > IdentityTargetAccount {
		return ErrInvalidIdentity
	}
	if options.Target == IdentityTargetObject && identity.form > IdentityFormGUID {
		return ErrUnsupportedIdentity
	}
	if options.Partition != "" {
		if _, err := parseIdentityDN(options.Partition); err != nil {
			return err
		}
	}
	return (SearchOptions{Properties: options.Properties}).Validate()
}

// ResolveIdentity resolves only on this authenticated connection, with no
// discovery, referral chasing, credential forwarding or fallback partition.
// All reads share one timeout. Errors retain native/permission/cleanup details;
// an incomplete single match is never treated as a unique object.
func (c *Client) ResolveIdentity(ctx context.Context, identity Identity, options ResolveIdentityOptions) (IdentityResult, error) {
	var result IdentityResult
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	if err := validateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	result.Source = c.config.Endpoint
	err := c.read(ctx, func(bounded context.Context) error {
		root, readErr := readIdentityRoot(bounded, c.session)
		if readErr != nil {
			return readErr
		}
		result, readErr = resolveIdentitySession(bounded, c.session, c.config, root, identity, options)
		return readErr
	})
	return result, err
}

// These helpers run under the caller's session gate, allowing mutation workflows
// to resolve and write without recursively acquiring Client's gate.
func readIdentityRoot(ctx context.Context, session directorySession) (RootDSE, error) {
	properties := defaultRootDSEAttributes()
	attributes, err := session.baseObject(ctx, "", properties)
	root, decodeErr := decodeRootDSE(attributes, properties)
	return root, errors.Join(err, decodeErr)
}

func resolveIdentitySession(ctx context.Context, session directorySession, config Config, root RootDSE, identity Identity, options ResolveIdentityOptions) (IdentityResult, error) {
	result := IdentityResult{Source: config.Endpoint}
	err := validateIdentityOperation(identity, options)
	if err != nil {
		return result, err
	}
	capabilities := root.Capabilities()
	if options.Target == IdentityTargetAccount || capabilities.Type == DirectoryUnknown {
		if err := capabilities.RequireADDS("ResolveIdentity"); err != nil {
			return result, err
		}
	}
	partition := options.Partition
	if partition == "" {
		partition = config.Partition
	}
	selected, contexts, err := identityPartition(identity, partition, root)
	if err != nil {
		return result, err
	}
	result.Partition = root.NamingContexts[selected]
	query := identitySearch(identity, result.Partition, options)
	search, searchErr := searchIdentitySession(ctx, session, query)
	result.Candidates = search.Objects
	for _, object := range result.Candidates {
		dn, parseErr := parseIdentityDN(object.DistinguishedName)
		if parseErr != nil {
			searchErr = errors.Join(searchErr, ErrInvalidResult)
			continue
		}
		if identityNamingContext(dn, contexts) != selected {
			searchErr = errors.Join(searchErr, ErrIdentityScope)
		}
		if identity.form == IdentityFormDN {
			expected, _ := parseIdentityDN(identity.value)
			if !sameIdentityDN(dn, expected) {
				searchErr = errors.Join(searchErr, ErrInvalidResult)
			}
		}
	}
	if len(result.Candidates) > 1 {
		return result, errors.Join(ErrAmbiguousIdentity, searchErr)
	}
	// A continuation reference names a naming context this search did not ask
	// about, so it cannot make a unique in-scope match wrong. Every Active
	// Directory domain holds subordinate contexts beneath its root, which is
	// where a GUID, SID or account name is searched for, so refusing on a
	// reference alone would make those forms unusable against any domain.
	// Search still reports it: a caller enumerating a subtree does need to know.
	referencesOnly := identityReferencesOnly(searchErr)
	if searchErr != nil && !referencesOnly {
		return result, searchErr
	}
	if !search.Complete && !referencesOnly {
		return result, ErrIncompleteResult
	}
	if len(result.Candidates) == 0 {
		return result, ErrDirectoryObjectNotFound
	}
	result.Object = &result.Candidates[0]
	result.Complete = true
	return result, nil
}

// identityReferencesOnly reports whether an incomplete search failed for no
// reason beyond continuation references. The join tree is walked rather than
// matched with errors.Is, because that would also answer yes when a reference
// accompanied some other failure that must still be reported.
func identityReferencesOnly(err error) bool {
	if err == nil {
		return false
	}
	found := false
	var walk func(error) bool
	walk = func(e error) bool {
		if e == nil {
			return true
		}
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			for _, inner := range joined.Unwrap() {
				if !walk(inner) {
					return false
				}
			}
			return true
		}
		switch {
		case e == ErrIncompleteResult:
			// The category every incomplete search carries, not a cause.
			return true
		case errors.Is(e, ErrSearchReferences):
			found = true
			return true
		}
		return false
	}
	return walk(err) && found
}
func searchIdentitySession(ctx context.Context, session directorySession, query SearchOptions) (SearchResult, error) {
	query, err := query.normalized()
	if err != nil {
		return SearchResult{}, err
	}
	cursor, err := session.startSearch(ctx, query)
	if err != nil {
		return SearchResult{}, &SearchError{Cause: err}
	}
	result, err := collectSearch(ctx, cursor, query)
	if err != nil {
		result.Complete = false
		return result, &SearchError{Returned: len(result.Objects), Cause: err}
	}
	return result, nil
}

func identityPartition(identity Identity, explicit string, root RootDSE) (int, []identityDN, error) {
	if len(root.NamingContexts) == 0 {
		return 0, nil, ErrIncompleteResult
	}
	contexts := make([]identityDN, len(root.NamingContexts))
	for i, name := range root.NamingContexts {
		parsed, err := parseIdentityDN(name)
		if err != nil {
			return 0, nil, ErrInvalidResult
		}
		contexts[i] = parsed
	}
	var dn identityDN
	if identity.form == IdentityFormDN {
		var err error
		dn, err = parseIdentityDN(identity.value)
		if err != nil {
			return 0, nil, err
		}
	}
	if explicit == "" && dn == nil {
		if root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" {
			return 0, nil, ErrNoDefaultPartition
		}
		explicit = *root.DefaultNamingContext
	}
	selected := -1
	if explicit != "" {
		parsed, err := parseIdentityDN(explicit)
		if err != nil {
			return 0, nil, err
		}
		for i := range contexts {
			if sameIdentityDN(parsed, contexts[i]) {
				selected = i
				break
			}
		}
	} else {
		selected = identityNamingContext(dn, contexts)
	}
	if selected == -1 || (dn != nil && identityNamingContext(dn, contexts) != selected) {
		return 0, nil, ErrIdentityScope
	}
	return selected, contexts, nil
}

func identitySearch(identity Identity, partition string, options ResolveIdentityOptions) SearchOptions {
	query := SearchOptions{Base: partition, Scope: ScopeSubtree, Properties: options.Properties, PageSize: 2, ResultLimit: 2}
	switch identity.form {
	case IdentityFormDN:
		query.Base, query.Scope, query.Filter = identity.value, ScopeBase, "(objectClass=*)"
	case IdentityFormGUID:
		query.Filter = "(objectGUID=" + identityBinaryLiteral(identity.binary) + ")"
	case IdentityFormSID:
		query.Filter = "(objectSid=" + identityBinaryLiteral(identity.binary) + ")"
	case IdentityFormAccountName:
		query.Filter = "(sAMAccountName=" + ldapLiteral(identity.value) + ")"
	}
	if options.Target == IdentityTargetAccount {
		query.Filter = "(&(objectSid=*)" + query.Filter + ")"
	}
	return query
}

func identityBinaryLiteral(value []byte) string {
	var output strings.Builder
	for _, octet := range value {
		fmt.Fprintf(&output, "\\%02x", octet)
	}
	return output.String()
}
