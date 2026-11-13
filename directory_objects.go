package activedirectory

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrInvalidObjectMutation    = errors.New("invalid directory object mutation")
	ErrObjectWritePermission    = errors.New("directory object access denied")
	ErrObjectWriteTarget        = errors.New("directory object writes require a writable LDAP endpoint")
	ErrObjectAlreadyExists      = errors.New("directory object already exists")
	ErrObjectNotLeaf            = errors.New("directory object has children; recursive deletion requires explicit intent")
	ErrObjectConcurrency        = errors.New("directory object version precondition failed")
	ErrObjectControlUnsupported = errors.New("server cannot enforce the requested object write control")
	ErrObjectWriteUncertain     = errors.New("directory object write outcome is unknown; reconcile before another write")
	ErrObjectReadback           = errors.New("write accepted but subsequent object observation is incomplete")
	ErrObjectVerification       = errors.New("write accepted but requested effects could not be verified from returned values")
)

// ObjectWriteState records submission/reply status, independently of readback.
// Rejected recursive deletes may already have deleted descendants.
type ObjectWriteState uint8

const (
	ObjectWriteNotAttempted ObjectWriteState = iota
	ObjectWriteAccepted
	ObjectWriteRejected
	ObjectWriteUncertain
)

// ObjectVersion is an explicit compare-and-write precondition on one endpoint.
// USNChanged is the decimal uSNChanged observed with ObjectGUID on Source.
// USNs from another DC are not interchangeable. A critical RFC4528 assertion
// control is required; a preflight read alone never substitutes for that control.
type ObjectVersion struct {
	Source     Endpoint
	GUID       GUID
	USNChanged uint64
}

type ObjectMutationOptions struct {
	Partition       string
	ExpectedVersion *ObjectVersion
	// Properties adds attributes to the post-write observation. Changed
	// attributes, objectGUID and uSNChanged are always explicitly selected.
	Properties []string
}

type CreateObjectRequest struct {
	Parent Identity
	// Class is a schema ldapDisplayName. Its inherited rDNAttID determines
	// the naming attribute; Name is a literal value, never a DN fragment.
	Class      string
	Name       string
	Attributes map[string][]RawValue
	Options    ObjectMutationOptions
}

type AttributeChangeKind uint8

const (
	AttributeSet AttributeChangeKind = iota + 1
	AttributeClear
	AttributeAddValues
	AttributeRemoveValues
)

// AttributeChange describes one explicit change. Omit an attribute by leaving
// it out of Changes. Set/Add/Remove require values; Clear requires none. An
// empty RawValue is one zero-length value, not a request to clear an attribute.
// Attribute names are LDAP display names without options or numeric aliases.
// One disjoint RemoveValues/AddValues pair for the same attribute is allowed
// and is submitted remove-first. All other repeated/conflicting changes fail.
type AttributeChange struct {
	Attribute string
	Kind      AttributeChangeKind
	Values    []RawValue
}

type UpdateObjectRequest struct {
	Identity Identity
	Changes  []AttributeChange
	Options  ObjectMutationOptions
}

// RenameObjectRequest changes the RDN's value in its current parent; it does
// not move the object or change its naming attribute. The old RDN is removed.
type RenameObjectRequest struct {
	Identity Identity
	Name     string
	Options  ObjectMutationOptions
}

type DeleteObjectRequest struct {
	Identity  Identity
	Recursive bool
	Options   ObjectMutationOptions
}

// ObjectMutationResult retains observations even when err is non-nil. Accepted
// means the server acknowledged this request, not that a subsequent observation
// is atomic with it. After may reflect concurrent writes; an absent attribute
// can be hidden by ACLs. Creation readback is by DN (the add reply has no GUID).
// An error never authorizes automatic retry, including after cleanup failure.
type ObjectMutationResult struct {
	Source     Endpoint
	Partition  string
	TargetDN   string
	TargetGUID *GUID
	State      ObjectWriteState
	Before     *Object
	After      *Object
	// Candidates retain raw resolution rows even on ambiguity, incomplete
	// retrieval, cancellation or cleanup failure. They are not verified
	// identities. Creation's preflight candidates describe its parent.
	PreflightCandidates []Object
	ReadbackCandidates  []Object
	ReadbackComplete    bool
	// Verified compares requested effects with complete returned values using
	// exact bytes. Schema normalization, hidden/ranged values, or concurrent
	// writes may prevent verification. A Clear cannot be proved by omission.
	Verified bool
	// AbsentAfter means a successful post-delete search found no visible
	// live object with this GUID. It makes no claim about tombstones.
	AbsentAfter bool
	// PartialEffectsPossible is conservative for a submitted tree delete,
	// including rejected requests (for example adminLimitExceeded).
	PartialEffectsPossible bool
}

// CreateObject creates one schema-class instance under an explicitly resolved
// parent. Required/allowed attributes and security are validated by the server.
// ExpectedVersion is unsupported for creation: an assertion on the new entry
// cannot atomically guard its parent. The parent path is a preflight observation.
func (c *Client) CreateObject(ctx context.Context, request CreateObjectRequest) (ObjectMutationResult, error) {
	return c.createObjectWithReadback(ctx, request, nil)
}

// Specialized linked-attribute workflows can verify bounded range reads under
// the same gate. The public generic operation retains its ordinary projection.
func (c *Client) createObjectWithReadback(ctx context.Context, request CreateObjectRequest, readback func(context.Context, ldapWriteSession, RootDSE, *ObjectMutationResult, []ldapAttributeModification) error) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Parent, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	if request.Options.ExpectedVersion != nil {
		return ObjectMutationResult{}, ErrObjectControlUnsupported
	}
	if !objectAttributeName(request.Class) || request.Name == "" || !validDirectoryText(request.Name) {
		return ObjectMutationResult{}, ErrInvalidObjectMutation
	}
	mods, err := createObjectAttributes(request.Attributes)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	return c.objectMutation(ctx, request.Parent, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, resolved IdentityResult, result *ObjectMutationResult) error {
		naming, err := objectClassNamingAttribute(ctx, session, root, request.Class)
		if err != nil {
			return err
		}
		for _, mod := range mods {
			if strings.EqualFold(mod.attribute, naming) {
				return fmt.Errorf("%w: naming attribute is supplied by Name", ErrInvalidObjectMutation)
			}
		}
		result.Before = nil // The resolved entry is the parent, not the new object.
		result.TargetGUID = nil
		result.TargetDN = naming + "=" + escapeObjectName(request.Name) + "," + resolved.Object.DistinguishedName
		mods = append(mods, ldapAttributeModification{operation: 0, attribute: "objectClass", values: [][]byte{[]byte(request.Class)}}, ldapAttributeModification{operation: 0, attribute: naming, values: [][]byte{[]byte(request.Name)}})
		write := ldapWriteRequest{operation: ldapWriteAdd, dn: result.TargetDN, modifications: mods}
		if err := submitObjectWrite(ctx, session, write, false, result); err != nil {
			return err
		}
		if readback != nil {
			return readback(ctx, session, root, result, mods)
		}
		identity, err := IdentityByDN(result.TargetDN)
		if err != nil {
			return errors.Join(ErrObjectReadback, err)
		}
		if err := observeObjectWrite(ctx, session, c.config, root, identity, result, objectWriteProperties(request.Options, mods), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, mods, request.Name)
	})
}

// UpdateObject submits one atomic LDAP Modify request. No permissive-modify
// control is used: adding an existing value or deleting a missing value retains
// the server's error. Clear deletes the entire attribute, including when that
// causes the server to report noSuchAttribute. No implicit read/merge/write.
func (c *Client) UpdateObject(ctx context.Context, request UpdateObjectRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	mods, err := objectChanges(request.Changes)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	return c.objectMutation(ctx, request.Identity, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, _ IdentityResult, result *ObjectMutationResult) error {
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		write := ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: mods, controls: controls}
		if err := submitObjectWrite(ctx, session, write, false, result); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(request.Options, mods), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, mods, "")
	})
}

func (c *Client) RenameObject(ctx context.Context, request RenameObjectRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	if request.Name == "" || !validDirectoryText(request.Name) {
		return ObjectMutationResult{}, ErrInvalidObjectMutation
	}
	return c.objectMutation(ctx, request.Identity, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, _ IdentityResult, result *ObjectMutationResult) error {
		dn, err := parseIdentityDN(result.TargetDN)
		if err != nil || len(dn[0]) != 1 || dn[0][0].binary {
			return ErrInvalidObjectMutation
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		write := ldapWriteRequest{operation: ldapWriteRename, dn: objectGUIDTarget(*result.TargetGUID), newRDN: dn[0][0].attribute + "=" + escapeObjectName(request.Name), deleteOldRDN: true, controls: controls}
		if err := submitObjectWrite(ctx, session, write, false, result); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(request.Options, nil), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, nil, request.Name)
	})
}

// DeleteObject defaults to leaf deletion. Recursive explicitly requests one
// critical AD tree-delete operation, which is not atomic across descendants.
// A server may delete only part of a large tree and report adminLimitExceeded;
// this method never repeats that request. Reconcile before further deletion.
func (c *Client) DeleteObject(ctx context.Context, request DeleteObjectRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	return c.objectMutation(ctx, request.Identity, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, _ IdentityResult, result *ObjectMutationResult) error {
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, request.Recursive)
		if err != nil {
			return err
		}
		write := ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}
		if err := submitObjectWrite(ctx, session, write, request.Recursive, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
}

type objectMutationWorkflow func(context.Context, ldapWriteSession, RootDSE, IdentityResult, *ObjectMutationResult) error

func (c *Client) objectMutation(ctx context.Context, identity Identity, options ObjectMutationOptions, workflow objectMutationWorkflow) (ObjectMutationResult, error) {
	return c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{}, workflow)
}

// Typed workflows select their identity forms and preflight properties while
// retaining the common session gate, GUID addressing and outcome handling.
func (c *Client) objectMutationIdentity(ctx context.Context, identity Identity, options ObjectMutationOptions, resolve ResolveIdentityOptions, workflow objectMutationWorkflow) (ObjectMutationResult, error) {
	resolve.Partition = options.Partition
	resolve.Properties = append(slices.Clone(resolve.Properties), "objectGUID", "uSNChanged", "objectClass")
	result := ObjectMutationResult{}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	result.Source = c.config.Endpoint
	err := c.read(ctx, func(ctx context.Context) error {
		session, ok := c.session.(ldapWriteSession)
		if !ok {
			return ErrUnsupported
		}
		root, err := readIdentityRoot(ctx, session)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == DirectoryADDS && (c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269) {
			return ErrObjectWriteTarget
		}
		resolved, err := resolveIdentitySession(ctx, session, c.config, root, identity, resolve)
		result.Partition = resolved.Partition
		result.PreflightCandidates = resolved.Candidates
		if err != nil {
			return err
		}
		result.Before = resolved.Object
		result.TargetDN = resolved.Object.DistinguishedName
		value, err := resolved.Object.Values("objectGUID").Single()
		if err != nil {
			return errors.Join(ErrInvalidResult, err)
		}
		guid, err := value.GUID()
		if err != nil {
			return errors.Join(ErrInvalidResult, err)
		}
		result.TargetGUID = &guid
		return workflow(ctx, session, root, resolved, &result)
	})
	return result, classifyObjectWriteError(err)
}

func submitObjectWrite(ctx context.Context, session ldapWriteSession, request ldapWriteRequest, recursive bool, result *ObjectMutationResult) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	attempt := session.ldapWrite(ctx, request)
	switch attempt.State {
	case ldapWriteAccepted:
		result.State = ObjectWriteAccepted
	case ldapWriteRejected:
		result.State = ObjectWriteRejected
	case ldapWriteUncertain:
		result.State = ObjectWriteUncertain
	default:
		result.State = ObjectWriteNotAttempted
	}
	result.PartialEffectsPossible = recursive && result.State != ObjectWriteNotAttempted
	if result.State == ObjectWriteUncertain {
		return errors.Join(ErrObjectWriteUncertain, attempt.Err)
	}
	if attempt.Err != nil {
		return attempt.Err
	}
	if result.State != ObjectWriteAccepted {
		return ErrInvalidResult
	}
	return nil
}

func observeObjectWrite(ctx context.Context, session directorySession, config Config, root RootDSE, identity Identity, result *ObjectMutationResult, properties []string, deleted bool) error {
	observed, err := resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: result.Partition, Properties: properties})
	result.ReadbackCandidates = observed.Candidates
	if deleted && errors.Is(err, ErrDirectoryObjectNotFound) {
		result.ReadbackComplete, result.AbsentAfter = true, true
		result.Verified = true
		return nil
	}
	result.After = observed.Object
	if err != nil {
		return errors.Join(ErrObjectReadback, err)
	}
	if deleted {
		return ErrObjectReadback
	}
	value, err := observed.Object.Values("objectGUID").Single()
	if err != nil {
		return errors.Join(ErrObjectReadback, ErrInvalidResult, err)
	}
	guid, err := value.GUID()
	if err != nil || (result.TargetGUID != nil && guid != *result.TargetGUID) {
		return errors.Join(ErrObjectReadback, ErrInvalidResult, err)
	}
	result.TargetGUID = &guid
	result.ReadbackComplete = observed.Complete
	return nil
}

func classifyObjectWriteError(err error) error {
	if errors.Is(err, errLDAPWriteUncertain) {
		err = errors.Join(ErrObjectWriteUncertain, err)
	}
	var native *LDAPError
	if errors.As(err, &native) {
		switch native.Code {
		case 50:
			return errors.Join(ErrObjectWritePermission, err)
		case 68:
			return errors.Join(ErrObjectAlreadyExists, err)
		case 66:
			return errors.Join(ErrObjectNotLeaf, err)
		case 122:
			return errors.Join(ErrObjectConcurrency, err)
		case 12:
			return errors.Join(ErrObjectControlUnsupported, err)
		}
	}
	return err
}

func objectGUIDTarget(guid GUID) string { return "<GUID=" + hex.EncodeToString(guid.Bytes()) + ">" }
func objectGUIDIdentity(guid GUID) Identity {
	return Identity{form: IdentityFormGUID, value: guid.String(), binary: guid.Bytes()}
}

func objectWriteProperties(options ObjectMutationOptions, mods []ldapAttributeModification) []string {
	properties := slices.Clone(options.Properties)
	properties = append(properties, "objectGUID", "uSNChanged", "name", "objectClass")
	for _, mod := range mods {
		properties = append(properties, mod.attribute)
	}
	return properties
}
