package model

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
)

var (
	ErrInvalidObjectMutation = errors.New("invalid directory object mutation")
	ErrObjectWritePermission = errors.New("directory object access denied")
	ErrObjectWriteTarget     = errors.New(
		"directory object writes require a writable LDAP endpoint",
	)
	ErrObjectAlreadyExists = errors.New("directory object already exists")
	ErrObjectNotLeaf       = errors.New(
		"directory object has children; recursive deletion requires explicit intent",
	)
	ErrObjectConcurrency        = errors.New("directory object version precondition failed")
	ErrObjectControlUnsupported = errors.New(
		"server cannot enforce the requested object write control",
	)
	ErrObjectWriteUncertain = errors.New(
		"directory object write outcome is unknown; reconcile before another write",
	)
	ErrObjectReadback = errors.New(
		"write accepted but subsequent object observation is incomplete",
	)
	// ErrObjectDeletionIncomplete preserves possible descendant effects after
	// a failed submitted tree delete, even when the root request was rejected.
	ErrObjectDeletionIncomplete = errors.New(
		"submitted tree deletion failed with possible partial effects; reconcile descendants before another write",
	)
	ErrObjectVerification = errors.New(
		"write accepted but requested effects could not be verified from returned values",
	)
	// ErrObjectUnverifiable is a write the server accepted whose effect no
	// readback could settle, as distinct from one a readback contradicted.
	// Clearing an attribute is the ordinary case: an absent attribute is what
	// success looks like and is equally what denied visibility looks like, so
	// the SDK will not claim to have confirmed it either way.
	ErrObjectUnverifiable = errors.New(
		"directory object write accepted but its effect cannot be proved by a readback",
	)
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
	Source    Endpoint
	Partition string
	// TargetDN is the directory's own distinguished name for the object once a
	// creation readback has been verified, so it can be stored and written
	// back into DN-valued attributes unchanged. Otherwise it is the name the
	// write was asked to produce, which addresses the same entry but may spell
	// the naming attribute as the schema does rather than as the directory
	// returns it.
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
	// DeletionReadback retains the separate critical deleted-object search,
	// including partial rows and completion state. Nil means it was not entered.
	// Ordinary empty readback cannot replace a positive same-GUID isDeleted
	// observation. After remains the ordinary live-object observation.
	DeletionReadback *SearchResult
	// Verified compares requested effects with complete returned values using
	// exact bytes, or confirms deletion through a positive same-GUID isDeleted
	// observation. Schema normalization, hidden/ranged values, or concurrent
	// writes may prevent verification. A Clear cannot be proved by omission.
	Verified bool
	// AbsentAfter means the ordinary post-delete search found no visible live
	// object with this GUID. It alone is not deletion proof. Verified deletion
	// additionally requires a validated positive DeletionReadback observation.
	AbsentAfter bool
	// PartialEffectsPossible is conservative for a submitted tree delete,
	// including rejected requests (for example adminLimitExceeded).
	PartialEffectsPossible bool
}

// observedDistinguishedName prefers the directory's own distinguishedName
// attribute over the name on the search entry, because the entry name of a
// base-scoped search can be the name the request supplied rather than the one
// the directory holds. Falls back to the entry name when the attribute was not
// returned, which is all there is to go on.
func InternalObservedDistinguishedName(object *Object) string {
	if object == nil {
		return ""
	}
	if value, err := object.Values("distinguishedName").Single(); err == nil {
		if text := string(value.Bytes()); text != "" {
			return text
		}
	}
	return object.DistinguishedName
}

type InternalObjectMutationWorkflow func(context.Context, InternalLdapWriteSession, RootDSE, IdentityResult, *ObjectMutationResult) error

func InternalSubmitObjectWrite(
	ctx context.Context,
	session InternalLdapWriteSession,
	request InternalLdapWriteRequest,
	recursive bool,
	result *ObjectMutationResult,
) error {
	if err := context.Cause(ctx); err != nil {
		return fmt.Errorf("object write not submitted: %w", err)
	}
	attempt := session.InternalLdapWrite(ctx, request)
	switch attempt.State {
	case InternalLdapWriteAccepted:
		result.State = ObjectWriteAccepted
	case InternalLdapWriteRejected:
		result.State = ObjectWriteRejected
	case InternalLdapWriteUncertain:
		result.State = ObjectWriteUncertain
	default:
		result.State = ObjectWriteNotAttempted
	}
	result.PartialEffectsPossible = recursive && result.State != ObjectWriteNotAttempted
	err := attempt.Err
	if result.State == ObjectWriteUncertain {
		err = errors.Join(ErrObjectWriteUncertain, err)
	} else if result.State != ObjectWriteAccepted && err == nil {
		err = ErrInvalidResult
	}
	if err != nil && result.PartialEffectsPossible {
		return errors.Join(ErrObjectDeletionIncomplete, err)
	}
	return err
}

func InternalObserveObjectWrite(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
	identity Identity,
	result *ObjectMutationResult,
	properties []string,
	deleted bool,
) error {
	observed, err := InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		identity,
		ResolveIdentityOptions{Partition: result.Partition, Properties: properties},
	)
	result.ReadbackCandidates = observed.Candidates
	// Only the resolver's complete empty result enters deletion proof. A
	// failed search carries SearchError even if its cause also means not found.
	var searchFailure *SearchError
	if deleted && errors.Is(err, ErrDirectoryObjectNotFound) && !errors.As(err, &searchFailure) {
		result.ReadbackComplete, result.AbsentAfter = true, true
		result.After = nil
		// A successful empty search can hide a still-live object. Retain that
		// visibility observation without claiming it proves the deletion.
		return internalObserveDeletedObjectProof(ctx, session, root, result)
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

func InternalClassifyObjectWriteError(err error) error {
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

func InternalObjectGUIDTarget(guid GUID) string {
	return "<GUID=" + hex.EncodeToString(guid.Bytes()) + ">"
}

func InternalObjectGUIDIdentity(guid GUID) Identity {
	return Identity{form: IdentityFormGUID, value: guid.String(), binary: guid.Bytes()}
}

func InternalObjectWriteProperties(
	options ObjectMutationOptions,
	mods []InternalLdapAttributeModification,
) []string {
	properties := slices.Clone(options.Properties)
	properties = append(properties, "objectGUID", "uSNChanged", "name", "objectClass")
	for _, mod := range mods {
		properties = append(properties, mod.InternalAttribute)
	}
	return properties
}

// creationIncomplete joins a stage-incomplete sentinel only when the first
// write actually got somewhere. A multi-stage create reports partial
// completion so a caller knows an object may exist in an unfinished shape, and
// those sentinels classify as uncertain for that reason.
//
// But the first stage failing cleanly is not partial completion. A duplicate
// name is rejected with nothing written, and joining the sentinel there made
// the whole call report as uncertain — so a caller could never see that the
// object already exists and adopt it instead. Observed live: a duplicate name
// classified as already-exists through the group, organizational-unit and
// generic-object paths, and as uncertain through the user and computer paths,
// for the identical condition.
//
// Accepted and uncertain both mean an effect may be in the directory, so both
// still report partial completion.
func InternalCreationIncomplete(sentinel error, creation ObjectMutationResult, err error) error {
	if err == nil {
		return nil
	}
	if creation.State == ObjectWriteAccepted || creation.State == ObjectWriteUncertain {
		return errors.Join(sentinel, err)
	}
	return err
}
