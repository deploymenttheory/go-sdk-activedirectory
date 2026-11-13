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
func (i Identity) String() string     { return i.value }
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
	if searchErr != nil {
		return result, searchErr
	}
	if !search.Complete {
		return result, ErrIncompleteResult
	}
	if len(result.Candidates) == 0 {
		return result, ErrDirectoryObjectNotFound
	}
	result.Object = &result.Candidates[0]
	result.Complete = true
	return result, nil
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
