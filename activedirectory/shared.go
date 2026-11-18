package activedirectory

import (
	time "time"

	config "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	shared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

const ADFilterBinary = shared.ADFilterBinary

const ADFilterBoolean = shared.ADFilterBoolean

const ADFilterComputer = shared.ADFilterComputer

type ADFilterError = shared.ADFilterError

const ADFilterFileTime = shared.ADFilterFileTime

const ADFilterGUID = shared.ADFilterGUID

const ADFilterGeneralizedTime = shared.ADFilterGeneralizedTime

const ADFilterGroup = shared.ADFilterGroup

const ADFilterInteger = shared.ADFilterInteger

const ADFilterObject = shared.ADFilterObject

type ADFilterOptions = shared.ADFilterOptions

type ADFilterProfile = shared.ADFilterProfile

type ADFilterProperty = shared.ADFilterProperty

const ADFilterSID = shared.ADFilterSID

const ADFilterScalar = shared.ADFilterScalar

const ADFilterString = shared.ADFilterString

type ADFilterSyntax = shared.ADFilterSyntax

const ADFilterUser = shared.ADFilterUser

const AttributeAbsent = shared.AttributeAbsent

const AttributeAddValues = shared.AttributeAddValues

type AttributeChange = shared.AttributeChange

type AttributeChangeKind = shared.AttributeChangeKind

const AttributeClear = shared.AttributeClear

const AttributePartial = shared.AttributePartial

const AttributePresent = shared.AttributePresent

const AttributeRemoveValues = shared.AttributeRemoveValues

const AttributeSet = shared.AttributeSet

type AttributeState = shared.AttributeState

const AttributeUnloaded = shared.AttributeUnloaded

type AttributeValues = shared.AttributeValues

type AuthenticationMethod = config.AuthenticationMethod

const AuthenticationNegotiate = config.AuthenticationNegotiate

const AuthenticationSimple = config.AuthenticationSimple

const CapabilityADLDS = shared.CapabilityADLDS

const CapabilityActiveDirectory = shared.CapabilityActiveDirectory

const ClassAlreadyExists = shared.ClassAlreadyExists

const ClassConflict = shared.ClassConflict

const ClassDenied = shared.ClassDenied

const ClassIncomplete = shared.ClassIncomplete

const ClassInvalidRequest = shared.ClassInvalidRequest

const ClassNotFound = shared.ClassNotFound

const ClassTransport = shared.ClassTransport

const ClassUncertain = shared.ClassUncertain

const ClassUnclassified = shared.ClassUnclassified

const ClassUnsupported = shared.ClassUnsupported

const ClassUnverified = shared.ClassUnverified

func Classify(err error) ErrorClass { return shared.Classify(err) }

type Config = config.Config

type CreateObjectRequest = shared.CreateObjectRequest

type Credentials = config.Credentials

type DeleteObjectRequest = shared.DeleteObjectRequest

const DirectoryADDS = shared.DirectoryADDS

const DirectoryADLDS = shared.DirectoryADLDS

type DirectoryCapabilities = shared.DirectoryCapabilities

type DirectoryCapabilityError = shared.DirectoryCapabilityError

type DirectoryObservation = shared.DirectoryObservation

type DirectoryReadError = shared.DirectoryReadError

type DirectoryService = shared.DirectoryService

type DirectoryType = shared.DirectoryType

const DirectoryUnknown = shared.DirectoryUnknown

type Endpoint = config.Endpoint

var ErrADFilterConversion = shared.ErrADFilterConversion

var ErrADFilterProperty = shared.ErrADFilterProperty

var ErrADFilterSyntax = shared.ErrADFilterSyntax

var ErrADFilterVariable = shared.ErrADFilterVariable

var ErrAmbiguousIdentity = shared.ErrAmbiguousIdentity

var ErrAttributeUnavailable = shared.ErrAttributeUnavailable

var ErrClosed = shared.ErrClosed

var ErrConflictingFilters = shared.ErrConflictingFilters

var ErrDirectoryObjectNotFound = shared.ErrDirectoryObjectNotFound

var ErrFilterLimit = shared.ErrFilterLimit

var ErrIdentityScope = shared.ErrIdentityScope

var ErrIncompleteResult = shared.ErrIncompleteResult

var ErrInvalidConfig = config.ErrInvalidConfig

var ErrInvalidDNValue = shared.ErrInvalidDNValue

var ErrInvalidDirectoryQuery = shared.ErrInvalidDirectoryQuery

var ErrInvalidFilter = shared.ErrInvalidFilter

var ErrInvalidIdentity = shared.ErrInvalidIdentity

var ErrInvalidObjectMove = shared.ErrInvalidObjectMove

var ErrInvalidObjectMutation = shared.ErrInvalidObjectMutation

var ErrInvalidObjectSync = shared.ErrInvalidObjectSync

var ErrInvalidProperty = shared.ErrInvalidProperty

var ErrInvalidResult = shared.ErrInvalidResult

var ErrInvalidSearch = shared.ErrInvalidSearch

var ErrInvalidValue = shared.ErrInvalidValue

var ErrMoveDelegation = shared.ErrMoveDelegation

var ErrMoveForest = shared.ErrMoveForest

var ErrMoveRIDMaster = shared.ErrMoveRIDMaster

var ErrNoDefaultPartition = shared.ErrNoDefaultPartition

var ErrNotNamingContext = shared.ErrNotNamingContext

var ErrObjectAlreadyExists = shared.ErrObjectAlreadyExists

var ErrObjectConcurrency = shared.ErrObjectConcurrency

var ErrObjectControlUnsupported = shared.ErrObjectControlUnsupported

var ErrObjectMoveForbidden = shared.ErrObjectMoveForbidden

var ErrObjectNotLeaf = shared.ErrObjectNotLeaf

var ErrObjectReadback = shared.ErrObjectReadback

var ErrObjectSyncCapability = shared.ErrObjectSyncCapability

var ErrObjectSyncIdentity = shared.ErrObjectSyncIdentity

var ErrObjectSyncPasswordPolicy = shared.ErrObjectSyncPasswordPolicy

var ErrObjectSyncPermission = shared.ErrObjectSyncPermission

var ErrObjectSyncReadback = shared.ErrObjectSyncReadback

var ErrObjectSyncUncertain = shared.ErrObjectSyncUncertain

var ErrObjectUnverifiable = shared.ErrObjectUnverifiable

var ErrObjectVerification = shared.ErrObjectVerification

var ErrObjectWritePermission = shared.ErrObjectWritePermission

var ErrObjectWriteTarget = shared.ErrObjectWriteTarget

var ErrObjectWriteUncertain = shared.ErrObjectWriteUncertain

var ErrPolicyIntervalRange = shared.ErrPolicyIntervalRange

var ErrSearchReferences = shared.ErrSearchReferences

var ErrTLSNegotiation = shared.ErrTLSNegotiation

// ErrUnsupported is the legacy umbrella; check ErrUnsupportedDirectory first
// to distinguish a directory-type refusal from unsupported backend operations.
var ErrUnsupported = shared.ErrUnsupported

var ErrUnsupportedDirectory = shared.ErrUnsupportedDirectory

var ErrUnsupportedFilterValue = shared.ErrUnsupportedFilterValue

var ErrUnsupportedIdentity = shared.ErrUnsupportedIdentity

var ErrValuePrecision = shared.ErrValuePrecision

var ErrValueRange = shared.ErrValueRange

var ErrValueSentinel = shared.ErrValueSentinel

type ErrorClass = shared.ErrorClass

func EscapeDNValue(value string) (string, error) { return shared.EscapeDNValue(value) }

type ExtensibleFilter = shared.ExtensibleFilter

type FileTime = shared.FileTime

func FileTimeFromTime(value time.Time) (FileTime, error) { return shared.FileTimeFromTime(value) }

type Filter = shared.Filter

func FilterAnd(filters ...Filter) Filter { return shared.FilterAnd(filters...) }

func FilterApprox(attribute string, value FilterValue) Filter {
	return shared.FilterApprox(attribute, value)
}

func FilterBitAnd(
	attribute string,
	mask uint64,
) Filter {
	return shared.FilterBitAnd(attribute, mask)
}

func FilterBitOr(
	attribute string,
	mask uint64,
) Filter {
	return shared.FilterBitOr(attribute, mask)
}

func FilterBytes(value []byte) FilterValue { return shared.FilterBytes(value) }

func FilterEqual(attribute string, value FilterValue) Filter {
	return shared.FilterEqual(attribute, value)
}

func FilterExtensible(match ExtensibleFilter) Filter { return shared.FilterExtensible(match) }

func FilterGreaterOrEqual(attribute string, value FilterValue) Filter {
	return shared.FilterGreaterOrEqual(attribute, value)
}

func FilterInChain(attribute, dn string) Filter { return shared.FilterInChain(attribute, dn) }

func FilterInteger(value int64) FilterValue { return shared.FilterInteger(value) }

func FilterLessOrEqual(attribute string, value FilterValue) Filter {
	return shared.FilterLessOrEqual(attribute, value)
}

func FilterNot(filter Filter) Filter { return shared.FilterNot(filter) }

func FilterOr(filters ...Filter) Filter { return shared.FilterOr(filters...) }

func FilterPresent(attribute string) Filter { return shared.FilterPresent(attribute) }

func FilterSubstrings(attribute string, parts SubstringFilter) Filter {
	return shared.FilterSubstrings(attribute, parts)
}

func FilterText(value string) FilterValue { return shared.FilterText(value) }

type FilterValue = shared.FilterValue

type Flags32 = shared.Flags32

type GUID = shared.GUID

func GUIDFromBytes(value []byte) (GUID, error) { return shared.GUIDFromBytes(value) }

type GeneralizedTime = shared.GeneralizedTime

type Identity = shared.Identity

func IdentityByAccountName(value string) (Identity, error) {
	return shared.IdentityByAccountName(value)
}

func IdentityByDN(value string) (Identity, error) { return shared.IdentityByDN(value) }

func IdentityByGUID(value string) (Identity, error) { return shared.IdentityByGUID(value) }

func IdentityBySID(value string) (Identity, error) { return shared.IdentityBySID(value) }

type IdentityForm = shared.IdentityForm

const IdentityFormAccountName = shared.IdentityFormAccountName

const IdentityFormDN = shared.IdentityFormDN

const IdentityFormGUID = shared.IdentityFormGUID

const IdentityFormSID = shared.IdentityFormSID

type IdentityResult = shared.IdentityResult

type IdentityTarget = shared.IdentityTarget

const IdentityTargetAccount = shared.IdentityTargetAccount

const IdentityTargetObject = shared.IdentityTargetObject

type Interval100ns = shared.Interval100ns

func Interval100nsFromDuration(value time.Duration) (Interval100ns, error) {
	return shared.Interval100nsFromDuration(value)
}

func IsAlreadyExists(err error) bool { return shared.IsAlreadyExists(err) }

func IsConflict(err error) bool { return shared.IsConflict(err) }

func IsDenied(err error) bool { return shared.IsDenied(err) }

func IsIncomplete(err error) bool { return shared.IsIncomplete(err) }

func IsInvalidRequest(err error) bool { return shared.IsInvalidRequest(err) }

func IsNotFound(err error) bool { return shared.IsNotFound(err) }

func IsTransport(err error) bool { return shared.IsTransport(err) }

func IsUncertain(err error) bool { return shared.IsUncertain(err) }

func IsUnsupported(err error) bool { return shared.IsUnsupported(err) }

func IsUnverified(err error) bool { return shared.IsUnverified(err) }

type LDAPError = shared.LDAPError

type MatchingRule = shared.MatchingRule

const MatchingRuleBitAnd = shared.MatchingRuleBitAnd

const MatchingRuleBitOr = shared.MatchingRuleBitOr

const MatchingRuleDNWithData = shared.MatchingRuleDNWithData

const MatchingRuleInChain = shared.MatchingRuleInChain

const MaxFilterBytes = shared.MaxFilterBytes

const MaxFilterDepth = shared.MaxFilterDepth

type MoveObjectRequest = shared.MoveObjectRequest

type MoveSecurity = shared.MoveSecurity

func NewRawValue(value []byte) RawValue { return shared.NewRawValue(value) }

type Object = shared.Object

type ObjectMoveResult = shared.ObjectMoveResult

type ObjectMutationOptions = shared.ObjectMutationOptions

type ObjectMutationResult = shared.ObjectMutationResult

const ObjectSyncAccepted = shared.ObjectSyncAccepted

const ObjectSyncNotAttempted = shared.ObjectSyncNotAttempted

const ObjectSyncRejected = shared.ObjectSyncRejected

const ObjectSyncUncertain = shared.ObjectSyncUncertain

type ObjectSyncWriteState = shared.ObjectSyncWriteState

type ObjectVersion = shared.ObjectVersion

const ObjectWriteAccepted = shared.ObjectWriteAccepted

const ObjectWriteNotAttempted = shared.ObjectWriteNotAttempted

const ObjectWriteRejected = shared.ObjectWriteRejected

type ObjectWriteState = shared.ObjectWriteState

const ObjectWriteUncertain = shared.ObjectWriteUncertain

func ParseADFilter(expression string, options ADFilterOptions) (Filter, error) {
	return shared.ParseADFilter(expression, options)
}

func ParseFileTime(value string) (FileTime, error) { return shared.ParseFileTime(value) }

func ParseGUID(value string) (GUID, error) { return shared.ParseGUID(value) }

func ParseGeneralizedTime(value string) (GeneralizedTime, error) {
	return shared.ParseGeneralizedTime(value)
}

func ParseIdentity(value string) (Identity, error) { return shared.ParseIdentity(value) }

func ParseSID(value string) (SID, error) { return shared.ParseSID(value) }

type Partition = shared.Partition

type PolicyInterval = shared.PolicyInterval

func PolicyIntervalFromDuration(duration time.Duration) (PolicyInterval, error) {
	return shared.PolicyIntervalFromDuration(duration)
}

const PolicyNever = shared.PolicyNever

type RawValue = shared.RawValue

type RenameObjectRequest = shared.RenameObjectRequest

type ResolveIdentityOptions = shared.ResolveIdentityOptions

type RootDSE = shared.RootDSE

type RootDSEOptions = shared.RootDSEOptions

type SID = shared.SID

func SIDFromBytes(value []byte) (SID, error) { return shared.SIDFromBytes(value) }

const ScopeBase = shared.ScopeBase

const ScopeOneLevel = shared.ScopeOneLevel

const ScopeSubtree = shared.ScopeSubtree

type SearchError = shared.SearchError

type SearchOptions = shared.SearchOptions

type SearchResult = shared.SearchResult

type SearchScope = shared.SearchScope

type SubstringFilter = shared.SubstringFilter

type SyncObjectIdentity = shared.SyncObjectIdentity

type SyncObjectRequest = shared.SyncObjectRequest

type SyncObjectResult = shared.SyncObjectResult

type Transport = config.Transport

const TransportLDAP = config.TransportLDAP

const TransportLDAPS = config.TransportLDAPS

const TransportStartTLS = config.TransportStartTLS

type UpdateObjectRequest = shared.UpdateObjectRequest
