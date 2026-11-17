// Package shared provides the shared SDK interface.
package shared

import (
	time "time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ADFilterBinary is the SDK's ADFilterBinary.
const ADFilterBinary = admodel.ADFilterBinary

// ADFilterBoolean is the SDK's ADFilterBoolean.
const ADFilterBoolean = admodel.ADFilterBoolean

// ADFilterComputer is the SDK's ADFilterComputer.
const ADFilterComputer = admodel.ADFilterComputer

// ADFilterError locates a rejected expression without echoing assertion values.
// Offset is a zero-based UTF-8 byte offset; Line and Column are one-based, with
// Column counting Unicode code points. Cause supports errors.Is/errors.As.
type ADFilterError = admodel.ADFilterError

// ADFilterFileTime is the SDK's ADFilterFileTime.
const ADFilterFileTime = admodel.ADFilterFileTime

// ADFilterGUID is the SDK's ADFilterGUID.
const ADFilterGUID = admodel.ADFilterGUID

// ADFilterGeneralizedTime is the SDK's ADFilterGeneralizedTime.
const ADFilterGeneralizedTime = admodel.ADFilterGeneralizedTime

// ADFilterGroup is the SDK's ADFilterGroup.
const ADFilterGroup = admodel.ADFilterGroup

// ADFilterInteger is the SDK's ADFilterInteger.
const ADFilterInteger = admodel.ADFilterInteger

// ADFilterObject is the SDK's ADFilterObject.
const ADFilterObject = admodel.ADFilterObject

// ADFilterOptions is the SDK's ADFilterOptions.
type ADFilterOptions = admodel.ADFilterOptions

// ADFilterProfile selects property aliases, not search base, object class, or
// scope. Account/user/computer/group profiles are specifically AD DS mappings.
// AD LDS callers use common object aliases and explicit schema descriptors.
type ADFilterProfile = admodel.ADFilterProfile

// ADFilterProperty maps an expression property to a known LDAP attribute and
// syntax. Descriptors are caller-supplied schema facts, not directory discovery.
type ADFilterProperty = admodel.ADFilterProperty

// ADFilterSID is the SDK's ADFilterSID.
const ADFilterSID = admodel.ADFilterSID

// ADFilterScalar is the SDK's ADFilterScalar.
const ADFilterScalar = admodel.ADFilterScalar

// ADFilterString is the SDK's ADFilterString.
const ADFilterString = admodel.ADFilterString

// ADFilterSyntax is the SDK's ADFilterSyntax.
type ADFilterSyntax = admodel.ADFilterSyntax

// ADFilterUser is the SDK's ADFilterUser.
const ADFilterUser = admodel.ADFilterUser

// AttributeAbsent is the SDK's AttributeAbsent.
const AttributeAbsent = admodel.AttributeAbsent

// AttributeAddValues is the SDK's AttributeAddValues.
const AttributeAddValues = admodel.AttributeAddValues

// AttributeChange describes one explicit change. Omit an attribute by leaving
// it out of Changes. Set/Add/Remove require values; Clear requires none. An
// empty RawValue is one zero-length value, not a request to clear an attribute.
// Attribute names are LDAP display names without options or numeric aliases.
// One disjoint RemoveValues/AddValues pair for the same attribute is allowed
// and is submitted remove-first. All other repeated/conflicting changes fail.
type AttributeChange = admodel.AttributeChange

// AttributeChangeKind is the SDK's AttributeChangeKind.
type AttributeChangeKind = admodel.AttributeChangeKind

// AttributeClear is the SDK's AttributeClear.
const AttributeClear = admodel.AttributeClear

// AttributePartial is the SDK's AttributePartial.
const AttributePartial = admodel.AttributePartial

// AttributePresent is the SDK's AttributePresent.
const AttributePresent = admodel.AttributePresent

// AttributeRemoveValues is the SDK's AttributeRemoveValues.
const AttributeRemoveValues = admodel.AttributeRemoveValues

// AttributeSet is the SDK's AttributeSet.
const AttributeSet = admodel.AttributeSet

// AttributeState distinguishes not requested, requested but not returned, a
// complete returned value set, and a server-returned range requiring more reads.
type AttributeState = admodel.AttributeState

// AttributeUnloaded is the SDK's AttributeUnloaded.
const AttributeUnloaded = admodel.AttributeUnloaded

// AttributeValues retains retrieval state and every value in its original
// order, including duplicates. Ranges are retained separately; no incomplete
// range is silently presented as a complete multi-value attribute.
type AttributeValues = admodel.AttributeValues

// CapabilityADLDS is the SDK's CapabilityADLDS.
const CapabilityADLDS = admodel.CapabilityADLDS

// CapabilityActiveDirectory is the SDK's CapabilityActiveDirectory.
const CapabilityActiveDirectory = admodel.CapabilityActiveDirectory

// ClassAlreadyExists means the object the caller asked to create is
// already there. A caller that wants convergence should adopt the
// existing object rather than treat this as a failure.
const ClassAlreadyExists = admodel.ClassAlreadyExists

// ClassConflict means the request was well formed and permitted, but the
// directory's observed state is not the state the operation required —
// a failed version precondition, or an object that changed underneath a
// multi-step read. Re-reading and retrying is the remedy, and unlike
// ClassUncertain nothing was written.
const ClassConflict = admodel.ClassConflict

// ClassDenied means the authenticated identity is not permitted to do
// this. Retrying changes nothing; the remedy is outside the program.
const ClassDenied = admodel.ClassDenied

// ClassIncomplete means a read returned less than was asked for, or a
// value could not be determined. Nothing was written and what did come
// back is usable, but it is not the whole answer, so a caller must not
// treat absence in the result as absence in the directory.
const ClassIncomplete = admodel.ClassIncomplete

// ClassInvalidRequest means the request is malformed, internally
// inconsistent, or names an object of the wrong kind. The remedy is in
// the request, so retrying it unchanged is pointless. Nothing was
// written.
const ClassInvalidRequest = admodel.ClassInvalidRequest

// ClassNotFound means no object matched. For a caller tracking state
// this is the signal that a tracked object is gone — but see the note on
// precedence: it must not be inferred from an error that is also denied.
const ClassNotFound = admodel.ClassNotFound

// ClassTransport means the session or connection failed, or the client
// was closed. A read may be safely retried on a new session; a write
// that may already have been submitted is ClassUncertain instead, and
// that class wins.
const ClassTransport = admodel.ClassTransport

// ClassUncertain means a write was attempted and its outcome is not
// known, or is only partly known. The directory may hold the change, all
// of it or some of it. A caller must neither record the change as applied
// nor record it as absent, and must not repeat the operation until it has
// re-read the target: repeating a write whose first attempt may have
// landed is how a reconcilable state becomes an unreconcilable one.
const ClassUncertain = admodel.ClassUncertain

// ClassUnclassified is the zero value, and the class of a nil error. It
// also covers an error this package did not produce. It never asserts
// that a condition is benign: a caller that cannot classify an error must
// treat it as a failure it does not understand.
const ClassUnclassified = admodel.ClassUnclassified

// ClassUnsupported means this platform, endpoint or directory type cannot
// perform the operation at all. Distinct from ClassDenied: no credential
// makes it succeed here.
const ClassUnsupported = admodel.ClassUnsupported

// ClassUnverified means a write was accepted and its effect cannot be
// proved from a subsequent read — not because the read disagreed, but
// because no read could settle it. Clearing an attribute is the ordinary
// case: an absent attribute is what success looks like and is equally what
// denied visibility looks like.
//
// Distinct from ClassUncertain, and the distinction is the point. The
// server accepted the change, so a caller may record it as applied; what it
// may not do is claim this SDK confirmed it. Without this class, every
// successful attribute clear reported as uncertain, so the one predicate a
// caller cannot afford to ignore fired on the happy path.
const ClassUnverified = admodel.ClassUnverified

// Classify reduces an error to the one decision a caller has to make about it.
//
// A nil error is ClassUnclassified, as is an error this package did not
// produce: Classify never claims that an unrecognised failure is harmless.
//
// Errors here are joined freely, so one error commonly carries several
// classes. Classify returns the most dominant present, ordered by the
// consequence of acting on the wrong one — see classPrecedence. In particular
// an error that is both uncertain and anything else is ClassUncertain, and an
// error that is both denied and not-found is ClassDenied.
//
// The sentinel is unaffected and remains the right tool for everything a class
// deliberately discards. Classify answers "what may I do next"; errors.Is
// against a sentinel answers "what exactly happened".
func Classify(err error) admodel.ErrorClass { return admodel.Classify(err) }

// CreateObjectRequest is the SDK's CreateObjectRequest.
type CreateObjectRequest = admodel.CreateObjectRequest

// DeleteObjectRequest is the SDK's DeleteObjectRequest.
type DeleteObjectRequest = admodel.DeleteObjectRequest

// DirectoryADDS is the SDK's DirectoryADDS.
const DirectoryADDS = admodel.DirectoryADDS

// DirectoryADLDS is the SDK's DirectoryADLDS.
const DirectoryADLDS = admodel.DirectoryADLDS

// DirectoryCapabilities retains all advertised OIDs, including unknown ones.
// Advertisements do not prove access rights or negotiated authentication.
type DirectoryCapabilities = admodel.DirectoryCapabilities

// DirectoryCapabilityError explains a directory-type prerequisite failure.
// It does not imply that an operation is implemented or that permission exists.
type DirectoryCapabilityError = admodel.DirectoryCapabilityError

// DirectoryObservation records the raw inputs to a projection. Complete means
// all planned reads and conversions finished, not that every attribute exists
// or was visible to this identity. Sequential reads are not an atomic snapshot.
// Absent, unloaded and ranged values remain distinguishable through Object.Attribute.
type DirectoryObservation = admodel.DirectoryObservation

// DirectoryReadError preserves partial, native, capability, and context errors.
type DirectoryReadError = admodel.DirectoryReadError

// DirectoryService reads topology through the client's authenticated endpoint.
// It never discovers another endpoint, rebinds, or retains credentials.
type DirectoryService = adengine.DirectoryService

// DirectoryType describes the server's advertised directory service.
type DirectoryType = admodel.DirectoryType

// DirectoryUnknown is the SDK's DirectoryUnknown.
const DirectoryUnknown = admodel.DirectoryUnknown

// ErrADFilterConversion is the SDK's ErrADFilterConversion.
var ErrADFilterConversion = admodel.ErrADFilterConversion

// ErrADFilterProperty is the SDK's ErrADFilterProperty.
var ErrADFilterProperty = admodel.ErrADFilterProperty

// ErrADFilterSyntax is the SDK's ErrADFilterSyntax.
var ErrADFilterSyntax = admodel.ErrADFilterSyntax

// ErrADFilterVariable is the SDK's ErrADFilterVariable.
var ErrADFilterVariable = admodel.ErrADFilterVariable

// ErrAmbiguousIdentity is the SDK's ErrAmbiguousIdentity.
var ErrAmbiguousIdentity = admodel.ErrAmbiguousIdentity

// ErrAttributeUnavailable is the SDK's ErrAttributeUnavailable.
var ErrAttributeUnavailable = admodel.ErrAttributeUnavailable

// ErrClosed is the SDK's ErrClosed.
var ErrClosed = admodel.ErrClosed

// ErrConflictingFilters is the SDK's ErrConflictingFilters.
var ErrConflictingFilters = admodel.ErrConflictingFilters

// ErrDirectoryObjectNotFound is the SDK's ErrDirectoryObjectNotFound.
var ErrDirectoryObjectNotFound = admodel.ErrDirectoryObjectNotFound

// ErrFilterLimit is the SDK's ErrFilterLimit.
var ErrFilterLimit = admodel.ErrFilterLimit

// ErrIdentityScope is the SDK's ErrIdentityScope.
var ErrIdentityScope = admodel.ErrIdentityScope

// ErrIncompleteResult is the SDK's ErrIncompleteResult.
var ErrIncompleteResult = admodel.ErrIncompleteResult

// ErrInvalidDNValue is the SDK's ErrInvalidDNValue.
var ErrInvalidDNValue = admodel.ErrInvalidDNValue

// ErrInvalidDirectoryQuery is the SDK's ErrInvalidDirectoryQuery.
var ErrInvalidDirectoryQuery = admodel.ErrInvalidDirectoryQuery

// ErrInvalidFilter is the SDK's ErrInvalidFilter.
var ErrInvalidFilter = admodel.ErrInvalidFilter

// ErrInvalidIdentity is the SDK's ErrInvalidIdentity.
var ErrInvalidIdentity = admodel.ErrInvalidIdentity

// ErrInvalidObjectMove is the SDK's ErrInvalidObjectMove.
var ErrInvalidObjectMove = admodel.ErrInvalidObjectMove

// ErrInvalidObjectMutation is the SDK's ErrInvalidObjectMutation.
var ErrInvalidObjectMutation = admodel.ErrInvalidObjectMutation

// ErrInvalidObjectSync is the SDK's ErrInvalidObjectSync.
var ErrInvalidObjectSync = admodel.ErrInvalidObjectSync

// ErrInvalidProperty is the SDK's ErrInvalidProperty.
var ErrInvalidProperty = admodel.ErrInvalidProperty

// ErrInvalidResult is the SDK's ErrInvalidResult.
var ErrInvalidResult = admodel.ErrInvalidResult

// ErrInvalidSearch is the SDK's ErrInvalidSearch.
var ErrInvalidSearch = admodel.ErrInvalidSearch

// ErrInvalidValue is the SDK's ErrInvalidValue.
var ErrInvalidValue = admodel.ErrInvalidValue

// ErrMoveDelegation is the SDK's ErrMoveDelegation.
var ErrMoveDelegation = admodel.ErrMoveDelegation

// ErrMoveForest is the SDK's ErrMoveForest.
var ErrMoveForest = admodel.ErrMoveForest

// ErrMoveRIDMaster is the SDK's ErrMoveRIDMaster.
var ErrMoveRIDMaster = admodel.ErrMoveRIDMaster

// ErrNoDefaultPartition is the SDK's ErrNoDefaultPartition.
var ErrNoDefaultPartition = admodel.ErrNoDefaultPartition

// ErrNotNamingContext is the SDK's ErrNotNamingContext.
var ErrNotNamingContext = admodel.ErrNotNamingContext

// ErrObjectAlreadyExists is the SDK's ErrObjectAlreadyExists.
var ErrObjectAlreadyExists = admodel.ErrObjectAlreadyExists

// ErrObjectConcurrency is the SDK's ErrObjectConcurrency.
var ErrObjectConcurrency = admodel.ErrObjectConcurrency

// ErrObjectControlUnsupported is the SDK's ErrObjectControlUnsupported.
var ErrObjectControlUnsupported = admodel.ErrObjectControlUnsupported

// ErrObjectMoveForbidden is the SDK's ErrObjectMoveForbidden.
var ErrObjectMoveForbidden = admodel.ErrObjectMoveForbidden

// ErrObjectNotLeaf is the SDK's ErrObjectNotLeaf.
var ErrObjectNotLeaf = admodel.ErrObjectNotLeaf

// ErrObjectReadback is the SDK's ErrObjectReadback.
var ErrObjectReadback = admodel.ErrObjectReadback

// ErrObjectSyncCapability is the SDK's ErrObjectSyncCapability.
var ErrObjectSyncCapability = admodel.ErrObjectSyncCapability

// ErrObjectSyncIdentity is the SDK's ErrObjectSyncIdentity.
var ErrObjectSyncIdentity = admodel.ErrObjectSyncIdentity

// ErrObjectSyncPasswordPolicy is the SDK's ErrObjectSyncPasswordPolicy.
var ErrObjectSyncPasswordPolicy = admodel.ErrObjectSyncPasswordPolicy

// ErrObjectSyncPermission is the SDK's ErrObjectSyncPermission.
var ErrObjectSyncPermission = admodel.ErrObjectSyncPermission

// ErrObjectSyncReadback is the SDK's ErrObjectSyncReadback.
var ErrObjectSyncReadback = admodel.ErrObjectSyncReadback

// ErrObjectSyncUncertain is the SDK's ErrObjectSyncUncertain.
var ErrObjectSyncUncertain = admodel.ErrObjectSyncUncertain

// ErrObjectUnverifiable is a write the server accepted whose effect no
// readback could settle, as distinct from one a readback contradicted.
// Clearing an attribute is the ordinary case: an absent attribute is what
// success looks like and is equally what denied visibility looks like, so
// the SDK will not claim to have confirmed it either way.
var ErrObjectUnverifiable = admodel.ErrObjectUnverifiable

// ErrObjectVerification is the SDK's ErrObjectVerification.
var ErrObjectVerification = admodel.ErrObjectVerification

// ErrObjectWritePermission is the SDK's ErrObjectWritePermission.
var ErrObjectWritePermission = admodel.ErrObjectWritePermission

// ErrObjectWriteTarget is the SDK's ErrObjectWriteTarget.
var ErrObjectWriteTarget = admodel.ErrObjectWriteTarget

// ErrObjectWriteUncertain is the SDK's ErrObjectWriteUncertain.
var ErrObjectWriteUncertain = admodel.ErrObjectWriteUncertain

// ErrPolicyIntervalRange is the SDK's ErrPolicyIntervalRange.
var ErrPolicyIntervalRange = admodel.ErrPolicyIntervalRange

// ErrSearchReferences is the SDK's ErrSearchReferences.
var ErrSearchReferences = admodel.ErrSearchReferences

// ErrTLSNegotiation is the SDK's ErrTLSNegotiation.
var ErrTLSNegotiation = admodel.ErrTLSNegotiation

// ErrUnsupported is the SDK's ErrUnsupported.
var ErrUnsupported = admodel.ErrUnsupported

// ErrUnsupportedDirectory is the SDK's ErrUnsupportedDirectory.
var ErrUnsupportedDirectory = admodel.ErrUnsupportedDirectory

// ErrUnsupportedFilterValue is the SDK's ErrUnsupportedFilterValue.
var ErrUnsupportedFilterValue = admodel.ErrUnsupportedFilterValue

// ErrUnsupportedIdentity is the SDK's ErrUnsupportedIdentity.
var ErrUnsupportedIdentity = admodel.ErrUnsupportedIdentity

// ErrValuePrecision is the SDK's ErrValuePrecision.
var ErrValuePrecision = admodel.ErrValuePrecision

// ErrValueRange is the SDK's ErrValueRange.
var ErrValueRange = admodel.ErrValueRange

// ErrValueSentinel is the SDK's ErrValueSentinel.
var ErrValueSentinel = admodel.ErrValueSentinel

// ErrorClass names the single decision a caller has to make about an error.
//
// This package exports well over a hundred sentinels, each naming a precise
// condition in one area. That precision is the point: a caller reporting a
// failure should be able to say exactly what the directory refused. But a
// caller *acting* on a failure has far fewer choices than it has sentinels,
// and enumerating the sentinels to find them means a sentinel added later is
// silently unrecognised. The suffix families (Err…Uncertain, Err…Permission,
// Err…Readback) look like they supply the grouping, but a name is not a
// contract. ErrorClass is.
//
// A class answers "what may I do next", not "what went wrong". Two errors from
// unrelated areas share a class when they permit the same next action, and the
// sentinel remains available through errors.Is for everything else.
type ErrorClass = admodel.ErrorClass

// EscapeDNValue escapes one textual RDN attribute value under RFC 4514. It is
// deliberately separate from filter escaping: do not pass a whole DN here.
// When using a formed DN in a filter, pass it through FilterText afterward.
func EscapeDNValue(value string) (string, error) { return admodel.EscapeDNValue(value) }

// ExtensibleFilter follows RFC 4515. Attribute may be omitted only when Rule
// is specified; Rule may be omitted only when Attribute is specified.
// DNAttributes includes DN attributes in matching when the server supports it.
// AD rule/schema prerequisites and access restrictions remain server-enforced.
type ExtensibleFilter = admodel.ExtensibleFilter

// FileTime preserves all 64 bits of the 100ns count since 1601-01-01 UTC,
// including 0, MaxInt64 and all-ones sentinels. Their meaning depends on the
// attribute (for example, accountExpires uses both 0 and MaxInt64 for never).
type FileTime = admodel.FileTime

// FileTimeFromTime is the SDK's FileTimeFromTime.
func FileTimeFromTime(value time.Time) (admodel.FileTime, error) {
	return admodel.FileTimeFromTime(value)
}

// Filter is an immutable, safely composed RFC 4515 expression. Constructors
// retain validation errors; LDAP or SearchOptions.Validate reports them before
// native execution. Values can never introduce filter syntax. A zero Filter is
// unset in SearchOptions and invalid when composed or encoded on its own.
type Filter = admodel.Filter

// FilterAnd/FilterOr require at least one nonzero child; empty conjunctions
// are not silently replaced with match-all or match-none searches.
func FilterAnd(filters ...admodel.Filter) admodel.Filter { return admodel.FilterAnd(filters...) }

// FilterApprox encodes LDAP's ~= operator. Approximate matching semantics are
// server/schema-defined; this constructor does not implement fuzzy matching.
func FilterApprox(attribute string, value admodel.FilterValue) admodel.Filter {
	return admodel.FilterApprox(attribute, value)
}

// FilterBitAnd matches when every mask bit is set; FilterBitOr matches when
// any mask bit is set. The integer attribute's supported width is schema-defined.
func FilterBitAnd(attribute string, mask uint64) admodel.Filter {
	return admodel.FilterBitAnd(attribute, mask)
}

// FilterBitOr is the SDK's FilterBitOr.
func FilterBitOr(attribute string, mask uint64) admodel.Filter {
	return admodel.FilterBitOr(attribute, mask)
}

// FilterBytes copies arbitrary assertion octets, including GUID/SID encodings.
// Every octet is hexadecimal-escaped. Nil/empty bytes are valid empty values.
// GUIDs use LDAP's Windows GUID byte order; SIDs use their binary SID layout.
func FilterBytes(value []byte) admodel.FilterValue { return admodel.FilterBytes(value) }

// FilterEqual is the SDK's FilterEqual.
func FilterEqual(attribute string, value admodel.FilterValue) admodel.Filter {
	return admodel.FilterEqual(attribute, value)
}

// FilterExtensible is the SDK's FilterExtensible.
func FilterExtensible(match admodel.ExtensibleFilter) admodel.Filter {
	return admodel.FilterExtensible(match)
}

// FilterGreaterOrEqual is the SDK's FilterGreaterOrEqual.
func FilterGreaterOrEqual(attribute string, value admodel.FilterValue) admodel.Filter {
	return admodel.FilterGreaterOrEqual(attribute, value)
}

// FilterInChain traverses an AD link attribute (for example member/memberOf).
// dn is an already formed DN, then escaped as a filter assertion value. This
// does not DN-escape the complete DN or alter its components.
func FilterInChain(
	attribute, dn string,
) admodel.Filter {
	return admodel.FilterInChain(attribute, dn)
}

// FilterInteger encodes an exact signed decimal integer without float conversion.
func FilterInteger(value int64) admodel.FilterValue { return admodel.FilterInteger(value) }

// FilterLessOrEqual is the SDK's FilterLessOrEqual.
func FilterLessOrEqual(attribute string, value admodel.FilterValue) admodel.Filter {
	return admodel.FilterLessOrEqual(attribute, value)
}

// FilterNot is the SDK's FilterNot.
func FilterNot(filter admodel.Filter) admodel.Filter { return admodel.FilterNot(filter) }

// FilterOr is the SDK's FilterOr.
func FilterOr(filters ...admodel.Filter) admodel.Filter { return admodel.FilterOr(filters...) }

// FilterPresent is the SDK's FilterPresent.
func FilterPresent(attribute string) admodel.Filter { return admodel.FilterPresent(attribute) }

// FilterSubstrings is the SDK's FilterSubstrings.
func FilterSubstrings(attribute string, parts admodel.SubstringFilter) admodel.Filter {
	return admodel.FilterSubstrings(attribute, parts)
}

// FilterText selects literal UTF-8 text. NUL and filter metacharacters are
// escaped, including '*' (which never becomes a wildcard). Invalid UTF-8 is
// rejected when the value is composed; use FilterBytes for arbitrary octets.
func FilterText(value string) admodel.FilterValue { return admodel.FilterText(value) }

// FilterValue holds assertion octets, not executable LDAP or DN syntax.
// Its zero value is invalid, except as an omitted Initial/Final substring.
type FilterValue = admodel.FilterValue

// Flags32 preserves all bits, including unknown bits and signed LDAP Integer
// representations such as groupType. LDAPString emits signed 32-bit decimal.
type Flags32 = admodel.Flags32

// GUID stores exactly the 16 AD/Windows binary bytes: the first three fields
// are little-endian, and the final eight bytes retain their order.
type GUID = admodel.GUID

// GUIDFromBytes is the SDK's GUIDFromBytes.
func GUIDFromBytes(value []byte) (admodel.GUID, error) { return admodel.GUIDFromBytes(value) }

// GeneralizedTime preserves the exact RFC4517 representation, including time
// zone, hour/minute/second precision, arbitrary fractions and leap seconds.
// Time refuses values Go cannot represent exactly. Input is bounded to 4096 bytes.
type GeneralizedTime = admodel.GeneralizedTime

// Identity has an explicit form; the SDK never guesses whether text is a DN,
// GUID, SID, account name or filter. Its zero value is invalid.
type Identity = admodel.Identity

// IdentityByAccountName selects a literal unqualified sAMAccountName. UPN and
// DOMAIN\name are not aliases for it. No wildcard expansion is performed.
func IdentityByAccountName(value string) (admodel.Identity, error) {
	return admodel.IdentityByAccountName(value)
}

// IdentityByDN is the SDK's IdentityByDN.
func IdentityByDN(value string) (admodel.Identity, error) { return admodel.IdentityByDN(value) }

// IdentityByGUID is the SDK's IdentityByGUID.
func IdentityByGUID(value string) (admodel.Identity, error) { return admodel.IdentityByGUID(value) }

// IdentityBySID is the SDK's IdentityBySID.
func IdentityBySID(value string) (admodel.Identity, error) { return admodel.IdentityBySID(value) }

// IdentityForm is the SDK's IdentityForm.
type IdentityForm = admodel.IdentityForm

// IdentityFormAccountName is the SDK's IdentityFormAccountName.
const IdentityFormAccountName = admodel.IdentityFormAccountName

// IdentityFormDN is the SDK's IdentityFormDN.
const IdentityFormDN = admodel.IdentityFormDN

// IdentityFormGUID is the SDK's IdentityFormGUID.
const IdentityFormGUID = admodel.IdentityFormGUID

// IdentityFormSID is the SDK's IdentityFormSID.
const IdentityFormSID = admodel.IdentityFormSID

// IdentityResult retains up to two raw candidates even on ambiguity or search
// failure. Object is set only after complete, unique, in-scope resolution.
// Complete does not assert every selected attribute was visible or returned.
type IdentityResult = admodel.IdentityResult

// IdentityTarget defines this operation's allowed forms. Generic object reads
// accept DN/GUID; AD DS account reads additionally accept SID/sAMAccountName and
// require objectSid to be present. Future operations must choose their own rule.
type IdentityTarget = admodel.IdentityTarget

// IdentityTargetAccount is the SDK's IdentityTargetAccount.
const IdentityTargetAccount = admodel.IdentityTargetAccount

// IdentityTargetObject is the SDK's IdentityTargetObject.
const IdentityTargetObject = admodel.IdentityTargetObject

// Interval100ns preserves a signed LDAP interval without assuming an attribute's
// sign convention. MinInt64 is retained as the common infinite-interval sentinel.
// This is a wire value, distinct from the policy API's nonnegative PolicyInterval.
type Interval100ns = admodel.Interval100ns

// Interval100nsFromDuration is the SDK's Interval100nsFromDuration.
func Interval100nsFromDuration(value time.Duration) (admodel.Interval100ns, error) {
	return admodel.Interval100nsFromDuration(value)
}

// IsAlreadyExists reports whether the object a caller asked to create is
// already present.
func IsAlreadyExists(err error) bool { return admodel.IsAlreadyExists(err) }

// IsConflict reports whether the directory's observed state was not the state
// the operation required. Nothing was written; re-reading and retrying is the
// remedy.
func IsConflict(err error) bool { return admodel.IsConflict(err) }

// IsDenied reports whether the bound identity is not permitted to do this.
// Retrying with the same credential cannot succeed.
func IsDenied(err error) bool { return admodel.IsDenied(err) }

// IsIncomplete reports whether a read returned less than was asked for.
// Nothing was written and the partial answer is usable, but absence from it
// does not establish absence in the directory.
func IsIncomplete(err error) bool { return admodel.IsIncomplete(err) }

// IsInvalidRequest reports whether the remedy is in the request rather than in
// the directory. Nothing was written, and retrying the call unchanged cannot
// succeed.
func IsInvalidRequest(err error) bool { return admodel.IsInvalidRequest(err) }

// IsNotFound reports whether no object matched.
//
// It is false for an error that is also denied, because an Active Directory
// search omits objects the bound identity cannot read, so a permissions
// failure can otherwise look like a deletion.
func IsNotFound(err error) bool { return admodel.IsNotFound(err) }

// IsTransport reports whether the session or connection failed. A read may be
// retried on a new session; a write that may already have been submitted
// classifies as uncertain instead.
func IsTransport(err error) bool { return admodel.IsTransport(err) }

// IsUncertain reports whether a write was attempted and its outcome is not
// known. A caller must not record the change as applied or as absent, and must
// re-read the target before repeating the operation.
//
// This is the one predicate here a caller cannot safely omit. Every other
// class says the directory's state is known.
func IsUncertain(err error) bool { return admodel.IsUncertain(err) }

// IsUnsupported reports whether this platform, endpoint or directory type
// cannot perform the operation at all. No credential changes that here.
func IsUnsupported(err error) bool { return admodel.IsUnsupported(err) }

// IsUnverified reports whether a write was accepted and this SDK cannot prove
// its effect from a readback. A caller may record the change as applied; it
// cannot claim the SDK confirmed it. Clearing an attribute always reports this
// way, because an absence cannot distinguish success from denied visibility.
func IsUnverified(err error) bool { return admodel.IsUnverified(err) }

// LDAPError preserves LDAP status separately from Windows system error codes.
// Diagnostic and MatchedDN may contain directory information; Error deliberately
// omits them so ordinary error logging does not disclose server diagnostics.
type LDAPError = admodel.LDAPError

// MatchingRule identifies a numeric OID. Custom OIDs are syntax-checked, not
// advertised as supported. AD exposes no matching-rule capability list.
type MatchingRule = admodel.MatchingRule

// MatchingRuleBitAnd is the SDK's MatchingRuleBitAnd.
const MatchingRuleBitAnd = admodel.MatchingRuleBitAnd

// MatchingRuleBitOr is the SDK's MatchingRuleBitOr.
const MatchingRuleBitOr = admodel.MatchingRuleBitOr

// MatchingRuleDNWithData is the SDK's MatchingRuleDNWithData.
const MatchingRuleDNWithData = admodel.MatchingRuleDNWithData

// MatchingRuleInChain is the SDK's MatchingRuleInChain.
const MatchingRuleInChain = admodel.MatchingRuleInChain

// MaxFilterBytes is the SDK's MaxFilterBytes.
const MaxFilterBytes = admodel.MaxFilterBytes

// MaxFilterDepth is the SDK's MaxFilterDepth.
const MaxFilterDepth = admodel.MaxFilterDepth

// MoveObjectRequest preserves the RDN and GUID using one native ModifyDN.
// TargetParent accepts DN or GUID. Nil Destination means a same-partition move
// on this Client (AD DS or AD LDS). A distinct authenticated Destination opts
// into a cross-domain AD DS move; its credentials are never forwarded.
type MoveObjectRequest = adengine.MoveObjectRequest

// MoveSecurity describes the actual source LDAP SSPI context. Complete means
// the delegated Kerberos and mutual-authentication checks succeeded. It never
// contains credentials, security handles, tickets or secret key material.
type MoveSecurity = admodel.MoveSecurity

// NewRawValue is the SDK's NewRawValue.
func NewRawValue(value []byte) admodel.RawValue { return admodel.NewRawValue(value) }

// Object owns copied raw LDAP values. Keys are lowercase attribute descriptions;
// binary bytes and ranged descriptions are preserved without schema conversion.
// RequestedProperties records explicit selection. Absent does not prove an
// attribute is unset: access controls and server policy can hide values.
type Object = admodel.Object

// ObjectMoveResult keeps Mutation.Source/Partition on the write endpoint.
// Mutation.After and its uSNChanged are observed on Destination in
// DestinationPartition; cross-domain USNs cannot become source preconditions.
type ObjectMoveResult = admodel.ObjectMoveResult

// ObjectMutationOptions is the SDK's ObjectMutationOptions.
type ObjectMutationOptions = admodel.ObjectMutationOptions

// ObjectMutationResult retains observations even when err is non-nil. Accepted
// means the server acknowledged this request, not that a subsequent observation
// is atomic with it. After may reflect concurrent writes; an absent attribute
// can be hidden by ACLs. Creation readback is by DN (the add reply has no GUID).
// An error never authorizes automatic retry, including after cleanup failure.
type ObjectMutationResult = admodel.ObjectMutationResult

// ObjectSyncAccepted is the SDK's ObjectSyncAccepted.
const ObjectSyncAccepted = admodel.ObjectSyncAccepted

// ObjectSyncNotAttempted is the SDK's ObjectSyncNotAttempted.
const ObjectSyncNotAttempted = admodel.ObjectSyncNotAttempted

// ObjectSyncRejected is the SDK's ObjectSyncRejected.
const ObjectSyncRejected = admodel.ObjectSyncRejected

// ObjectSyncUncertain is the SDK's ObjectSyncUncertain.
const ObjectSyncUncertain = admodel.ObjectSyncUncertain

// ObjectSyncWriteState is the SDK's ObjectSyncWriteState.
type ObjectSyncWriteState = admodel.ObjectSyncWriteState

// ObjectVersion is an explicit compare-and-write precondition on one endpoint.
// USNChanged is the decimal uSNChanged observed with ObjectGUID on Source.
// USNs from another DC are not interchangeable. A critical RFC4528 assertion
// control is required; a preflight read alone never substitutes for that control.
type ObjectVersion = admodel.ObjectVersion

// ObjectWriteAccepted is the SDK's ObjectWriteAccepted.
const ObjectWriteAccepted = admodel.ObjectWriteAccepted

// ObjectWriteNotAttempted is the SDK's ObjectWriteNotAttempted.
const ObjectWriteNotAttempted = admodel.ObjectWriteNotAttempted

// ObjectWriteRejected is the SDK's ObjectWriteRejected.
const ObjectWriteRejected = admodel.ObjectWriteRejected

// ObjectWriteState records submission/reply status, independently of readback.
// Rejected recursive deletes may already have deleted descendants.
type ObjectWriteState = admodel.ObjectWriteState

// ObjectWriteUncertain is the SDK's ObjectWriteUncertain.
const ObjectWriteUncertain = admodel.ObjectWriteUncertain

// ParseADFilter parses the AD expression language and returns a typed LDAP
// filter. It never evaluates PowerShell, commands, interpolation, property or
// method access. Go variables are bound as values, never textually substituted.
// Pass the result to SearchOptions.TypedFilter. Parentheses and one optional
// outer brace pair are grouping syntax only; a standalone '*' means match all.
func ParseADFilter(expression string, options admodel.ADFilterOptions) (admodel.Filter, error) {
	return admodel.ParseADFilter(expression, options)
}

// ParseFileTime is the SDK's ParseFileTime.
func ParseFileTime(value string) (admodel.FileTime, error) { return admodel.ParseFileTime(value) }

// ParseGUID is the SDK's ParseGUID.
func ParseGUID(value string) (admodel.GUID, error) { return admodel.ParseGUID(value) }

// ParseGeneralizedTime is the SDK's ParseGeneralizedTime.
func ParseGeneralizedTime(value string) (admodel.GeneralizedTime, error) {
	return admodel.ParseGeneralizedTime(value)
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
func ParseIdentity(value string) (admodel.Identity, error) { return admodel.ParseIdentity(value) }

// ParseSID is the SDK's ParseSID.
func ParseSID(value string) (admodel.SID, error) { return admodel.ParseSID(value) }

// Partition is the naming-context root returned by the configured server.
// Attributes owns copied raw values. On error the result may be partial.
type Partition = admodel.Partition

// PolicyInterval is a nonnegative count of 100-nanosecond ticks. It preserves
// the full LDAP signed delta-time range, which exceeds time.Duration's range.
// Values through PolicyNever are valid. The LDAP representation is negative.
type PolicyInterval = admodel.PolicyInterval

// PolicyIntervalFromDuration rejects negative or sub-100ns values rather than
// silently rounding them. Use PolicyInterval(ticks) for longer finite values.
func PolicyIntervalFromDuration(duration time.Duration) (admodel.PolicyInterval, error) {
	return admodel.PolicyIntervalFromDuration(duration)
}

// PolicyNever is the SDK's PolicyNever.
const PolicyNever = admodel.PolicyNever

// RawValue owns one LDAP value. Conversions are explicit, never inferred from
// an attribute name. Bytes returns a copy, including unknown binary syntaxes.
type RawValue = admodel.RawValue

// RenameObjectRequest changes the RDN's value in its current parent; it does
// not move the object or change its naming attribute. The old RDN is removed.
type RenameObjectRequest = admodel.RenameObjectRequest

// ResolveIdentityOptions is the SDK's ResolveIdentityOptions.
type ResolveIdentityOptions = admodel.ResolveIdentityOptions

// RootDSE preserves optional scalar values with pointers: absent is distinct
// from zero, false, or empty. Functional levels are raw numeric levels, not OS
// versions or schema versions. Advertised capabilities do not prove permission
// or that an authentication mechanism was negotiated by this connection.
type RootDSE = admodel.RootDSE

// RootDSEOptions adds attribute names to the stable default projection. Use
// "*" to also request server-returned user attributes. Operational attributes
// may require explicit names even with "*"; it does not promise every property.
type RootDSEOptions = admodel.RootDSEOptions

// SID is an immutable revision-1 Windows SID, including arbitrary 48-bit
// identifier authorities and up to 15 subauthorities. Its zero value is invalid.
type SID = admodel.SID

// SIDFromBytes is the SDK's SIDFromBytes.
func SIDFromBytes(value []byte) (admodel.SID, error) { return admodel.SIDFromBytes(value) }

// ScopeBase is the SDK's ScopeBase.
const ScopeBase = admodel.ScopeBase

// ScopeOneLevel is the SDK's ScopeOneLevel.
const ScopeOneLevel = admodel.ScopeOneLevel

// ScopeSubtree is the SDK's ScopeSubtree.
const ScopeSubtree = admodel.ScopeSubtree

// SearchError explicitly identifies an incomplete search, including zero-entry
// failures. Unwrap preserves cancellation, LDAP diagnostics and cleanup errors.
type SearchError = admodel.SearchError

// SearchOptions describes an LDAP search. Filter accepts explicit raw LDAP,
// not PowerShell expressions. TypedFilter composes escaped literal values.
// They are mutually exclusive; both unset means (objectClass=*).
type SearchOptions = admodel.SearchOptions

// SearchResult reports why retrieval stopped. Complete means the server ended
// the entire search successfully. LimitReached means the caller's bound stopped
// retrieval; it does not prove that additional matches exist. Always check err.
type SearchResult = admodel.SearchResult

// SearchScope selects which entries relative to Base are searched. The zero
// value searches Base itself; no domain or naming context is inferred.
type SearchScope = admodel.SearchScope

// SubstringFilter specifies literal segments separated by wildcards. A zero
// Initial or Final omits that anchor. Any segments remain in caller order.
// At least one segment is required and each supplied segment must be nonempty.
// Use FilterPresent for a lone wildcard, FilterEqual for a literal '*'.
type SubstringFilter = admodel.SubstringFilter

// SyncObjectIdentity selects exactly one object on Source. ObjectGUID contains
// the 16 LDAP objectGUID octets (Windows GUID byte order), not UTF-8 text.
type SyncObjectIdentity = admodel.SyncObjectIdentity

// SyncObjectRequest requests one object from Source on the destination Client.
// Partition is mandatory and must be the object's containing NC on both DCs.
// Source credentials authenticate SDK preflight reads; DC-to-DC replication
// uses the destination DC's replication identity, not forwarded credentials.
type SyncObjectRequest = admodel.SyncObjectRequest

// SyncObjectResult preserves acknowledgement separately from verification.
// Accepted means the synchronous LDAP operation returned success. A rejected
// response is not a guarantee that every server-side step had no effect.
// Verified describes only Properties, or the unicodePwd cache marker for
// PasswordOnly. It never asserts forest-wide convergence or secret equality.
type SyncObjectResult = admodel.SyncObjectResult

// UpdateObjectRequest is the SDK's UpdateObjectRequest.
type UpdateObjectRequest = admodel.UpdateObjectRequest
