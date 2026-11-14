package activedirectory

import "errors"

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
type ErrorClass uint8

const (
	// ClassUnclassified is the zero value, and the class of a nil error. It
	// also covers an error this package did not produce. It never asserts
	// that a condition is benign: a caller that cannot classify an error must
	// treat it as a failure it does not understand.
	ClassUnclassified ErrorClass = iota

	// ClassUncertain means a write was attempted and its outcome is not
	// known, or is only partly known. The directory may hold the change, all
	// of it or some of it. A caller must neither record the change as applied
	// nor record it as absent, and must not repeat the operation until it has
	// re-read the target: repeating a write whose first attempt may have
	// landed is how a reconcilable state becomes an unreconcilable one.
	ClassUncertain

	// ClassDenied means the authenticated identity is not permitted to do
	// this. Retrying changes nothing; the remedy is outside the program.
	ClassDenied

	// ClassConflict means the request was well formed and permitted, but the
	// directory's observed state is not the state the operation required —
	// a failed version precondition, or an object that changed underneath a
	// multi-step read. Re-reading and retrying is the remedy, and unlike
	// ClassUncertain nothing was written.
	ClassConflict

	// ClassAlreadyExists means the object the caller asked to create is
	// already there. A caller that wants convergence should adopt the
	// existing object rather than treat this as a failure.
	ClassAlreadyExists

	// ClassNotFound means no object matched. For a caller tracking state
	// this is the signal that a tracked object is gone — but see the note on
	// precedence: it must not be inferred from an error that is also denied.
	ClassNotFound

	// ClassUnsupported means this platform, endpoint or directory type cannot
	// perform the operation at all. Distinct from ClassDenied: no credential
	// makes it succeed here.
	ClassUnsupported

	// ClassInvalidRequest means the request is malformed, internally
	// inconsistent, or names an object of the wrong kind. The remedy is in
	// the request, so retrying it unchanged is pointless. Nothing was
	// written.
	ClassInvalidRequest

	// ClassTransport means the session or connection failed, or the client
	// was closed. A read may be safely retried on a new session; a write
	// that may already have been submitted is ClassUncertain instead, and
	// that class wins.
	ClassTransport

	// ClassIncomplete means a read returned less than was asked for, or a
	// value could not be determined. Nothing was written and what did come
	// back is usable, but it is not the whole answer, so a caller must not
	// treat absence in the result as absence in the directory.
	ClassIncomplete
)

func (c ErrorClass) String() string {
	switch c {
	case ClassUncertain:
		return "uncertain"
	case ClassDenied:
		return "denied"
	case ClassConflict:
		return "conflict"
	case ClassAlreadyExists:
		return "already-exists"
	case ClassNotFound:
		return "not-found"
	case ClassUnsupported:
		return "unsupported"
	case ClassInvalidRequest:
		return "invalid-request"
	case ClassTransport:
		return "transport"
	case ClassIncomplete:
		return "incomplete"
	}
	return "unclassified"
}

// classPrecedence orders the classes from most to least dominant. Errors in
// this package are routinely joined, so a single error commonly carries more
// than one class and the order decides which one a caller sees. It is ordered
// by consequence of being wrong, not by specificity:
//
//   - ClassUncertain first, because every other class tells a caller that the
//     directory's state is known, and acting on that belief after an uncertain
//     write is the one mistake this package cannot help a caller recover from.
//
//   - ClassDenied above ClassConflict, so a caller does not retry in a loop
//     something no retry will be permitted to do.
//
//   - ClassDenied above ClassNotFound, because an Active Directory search
//     silently omits objects the bound identity cannot read. A denied read can
//     therefore present as an absence, and a caller that treats absence as
//     deletion would discard state over a permissions change. Being wrong in
//     this direction costs nothing: a genuinely absent object reports
//     not-found without a denial joined to it.
//
//   - ClassTransport above ClassIncomplete, because a dead session explains
//     the short read rather than the other way round.
var classPrecedence = [...]ErrorClass{
	ClassUncertain,
	ClassDenied,
	ClassConflict,
	ClassAlreadyExists,
	ClassNotFound,
	ClassUnsupported,
	ClassInvalidRequest,
	ClassTransport,
	ClassIncomplete,
}

// sentinelClasses assigns every sentinel this package exports. It is
// exhaustive by test: errors_classification_test.go parses this package's own
// source, collects every package-level Err… variable, and fails if one is
// absent here. That test is the mechanism being added — without it a new
// sentinel would classify as ClassUnclassified and callers would quietly stop
// recognising a condition they used to handle.
var sentinelClasses = map[error]ErrorClass{
	// A write was attempted and the result is not known. The Err…Uncertain
	// family says so outright. The Err…Readback and verification sentinels
	// belong here for the same reason: the server accepted the write and the
	// SDK could not confirm what it did, which leaves the caller in exactly
	// the same position. The three creation-incomplete sentinels report a
	// write that partly succeeded, so the object exists in an unknown shape.
	ErrObjectWriteUncertain:             ClassUncertain,
	ErrObjectSyncUncertain:              ClassUncertain,
	ErrOperationMasterUncertain:         ClassUncertain,
	ErrOptionalFeatureUncertain:         ClassUncertain,
	ErrPasswordUncertain:                ClassUncertain,
	ErrServiceAccountLocalUncertain:     ClassUncertain,
	ErrObjectReadback:                   ClassUncertain,
	ErrObjectVerification:               ClassUncertain,
	ErrObjectSyncReadback:               ClassUncertain,
	ErrOperationMasterReadback:          ClassUncertain,
	ErrOptionalFeatureReadback:          ClassUncertain,
	ErrServiceAccountLocalObservation:   ClassUncertain,
	ErrOUProtection:                     ClassUncertain,
	ErrAuthenticationSiloGrant:          ClassUncertain,
	ErrUserCreationIncomplete:           ClassUncertain,
	ErrComputerCreationIncomplete:       ClassUncertain,
	ErrServiceAccountCreationIncomplete: ClassUncertain,
	ErrServiceAccountMigrationPartial:   ClassUncertain,

	// Access refused to the bound identity. ErrPasswordCredential is a
	// rejected credential rather than a rejected permission, but the caller's
	// options are the same. ErrObjectSyncPasswordPolicy and
	// ErrObjectMoveForbidden are refusals by directory policy rather than by
	// an ACL, which likewise no retry overcomes.
	ErrObjectWritePermission:         ClassDenied,
	ErrObjectSyncPermission:          ClassDenied,
	ErrOperationMasterPermission:     ClassDenied,
	ErrOptionalFeaturePermission:     ClassDenied,
	ErrRODCPasswordPolicyPermission:  ClassDenied,
	ErrServiceAccountLocalPermission: ClassDenied,
	ErrPasswordAccess:                ClassDenied,
	ErrPasswordCredential:            ClassDenied,
	ErrObjectSyncPasswordPolicy:      ClassDenied,
	ErrObjectMoveForbidden:           ClassDenied,
	ErrMoveDelegation:                ClassDenied,

	// The observed state is not what the operation required, and re-reading
	// is the remedy. The Err…Changed family is a multi-step read whose
	// subject moved underneath it. ErrReplicationSiteNotEmpty and
	// ErrServiceAccountMigrationState are preconditions on directory state,
	// not on the request: the caller changes the directory, not the call.
	ErrObjectConcurrency:             ClassConflict,
	ErrAuthenticationSiloChanged:     ClassConflict,
	ErrFineGrainedPolicyChanged:      ClassConflict,
	ErrGroupMembershipChanged:        ClassConflict,
	ErrOperationMasterChanged:        ClassConflict,
	ErrReplicationReferenceChanged:   ClassConflict,
	ErrReplicationSiteNotEmpty:       ClassConflict,
	ErrServiceAccountMigrationState:  ClassConflict,
	ErrServiceAccountMigrationPaired: ClassConflict,
	ErrClaimTypeReferenced:           ClassConflict,

	ErrObjectAlreadyExists: ClassAlreadyExists,

	ErrDirectoryObjectNotFound:    ClassNotFound,
	ErrServiceAccountNotInstalled: ClassNotFound,

	// Nothing the caller can supply makes this work on this endpoint. Three
	// shapes share the class: the platform or directory type cannot do it,
	// the server does not advertise the feature, and the endpoint is the
	// wrong kind of replica. A caller's response to all three is the same —
	// stop, and report what the directory would need to be.
	ErrUnsupported:                      ClassUnsupported,
	ErrUnsupportedDirectory:             ClassUnsupported,
	ErrUnsupportedFilterValue:           ClassUnsupported,
	ErrUnsupportedIdentity:              ClassUnsupported,
	ErrUserCapability:                   ClassUnsupported,
	ErrAccountControlUnsupported:        ClassUnsupported,
	ErrObjectControlUnsupported:         ClassUnsupported,
	ErrGroupMembershipTTLUnsupported:    ClassUnsupported,
	ErrObjectSyncCapability:             ClassUnsupported,
	ErrOperationMasterCapability:        ClassUnsupported,
	ErrRODCPasswordPolicyCapability:     ClassUnsupported,
	ErrObjectRestoreFeature:             ClassUnsupported,
	ErrObjectNotRestorable:              ClassUnsupported,
	ErrOptionalFeatureScope:             ClassUnsupported,
	ErrOptionalFeatureIrreversible:      ClassUnsupported,
	ErrAuthenticationPolicyPrerequisite: ClassUnsupported,
	ErrFunctionalLevelPrerequisite:      ClassUnsupported,
	ErrOptionalFeaturePrerequisite:      ClassUnsupported,
	ErrServiceAccountPrerequisite:       ClassUnsupported,
	ErrClaimTypeSchema:                  ClassUnsupported,
	ErrObjectWriteTarget:                ClassUnsupported,
	ErrPasswordTarget:                   ClassUnsupported,
	ErrPasswordProtection:               ClassUnsupported,
	ErrAccountStateTarget:               ClassUnsupported,
	ErrGroupMembershipTarget:            ClassUnsupported,
	ErrDirectorySettingsTarget:          ClassUnsupported,
	ErrRODCPasswordPolicyTarget:         ClassUnsupported,
	ErrFineGrainedPolicyTarget:          ClassUnsupported,
	ErrMembershipGC:                     ClassUnsupported,
	ErrMembershipContext:                ClassUnsupported,
	ErrNoDefaultPartition:               ClassUnsupported,
	ErrNoCurrentDomain:                  ClassUnsupported,
	ErrServiceAccountHost:               ClassUnsupported,
	ErrFunctionalLevelRoleOwner:         ClassUnsupported,
	ErrOptionalFeatureRole:              ClassUnsupported,
	ErrMoveRIDMaster:                    ClassUnsupported,
	ErrMoveForest:                       ClassUnsupported,

	// The remedy is in the request. This covers malformed input, internally
	// inconsistent options, a value that cannot be represented, a limit the
	// request exceeded, and an identity that resolved to an object of the
	// wrong class. They differ enormously in cause and not at all in what a
	// caller does about them: correct the call, do not retry it as it stands.
	ErrInvalidConfig:                  ClassInvalidRequest,
	ErrInvalidSearch:                  ClassInvalidRequest,
	ErrInvalidResult:                  ClassInvalidRequest,
	ErrInvalidNativeResult:            ClassInvalidRequest,
	ErrInvalidProperty:                ClassInvalidRequest,
	ErrInvalidValue:                   ClassInvalidRequest,
	ErrInvalidDNValue:                 ClassInvalidRequest,
	ErrInvalidIdentity:                ClassInvalidRequest,
	ErrIdentityScope:                  ClassInvalidRequest,
	ErrAmbiguousIdentity:              ClassInvalidRequest,
	ErrInvalidFilter:                  ClassInvalidRequest,
	ErrConflictingFilters:             ClassInvalidRequest,
	ErrFilterLimit:                    ClassInvalidRequest,
	ErrADFilterSyntax:                 ClassInvalidRequest,
	ErrADFilterProperty:               ClassInvalidRequest,
	ErrADFilterVariable:               ClassInvalidRequest,
	ErrADFilterConversion:             ClassInvalidRequest,
	ErrInvalidDirectoryQuery:          ClassInvalidRequest,
	ErrInvalidDiscovery:               ClassInvalidRequest,
	ErrInvalidUser:                    ClassInvalidRequest,
	ErrInvalidGroup:                   ClassInvalidRequest,
	ErrInvalidComputer:                ClassInvalidRequest,
	ErrInvalidMembership:              ClassInvalidRequest,
	ErrInvalidGroupMembership:         ClassInvalidRequest,
	ErrInvalidObjectMutation:          ClassInvalidRequest,
	ErrInvalidObjectMove:              ClassInvalidRequest,
	ErrInvalidObjectRestore:           ClassInvalidRequest,
	ErrInvalidObjectSync:              ClassInvalidRequest,
	ErrInvalidAccountControl:          ClassInvalidRequest,
	ErrInvalidAccountExpiration:       ClassInvalidRequest,
	ErrInvalidAccountStateSearch:      ClassInvalidRequest,
	ErrInvalidPasswordRequest:         ClassInvalidRequest,
	ErrInvalidAuthenticationPolicy:    ClassInvalidRequest,
	ErrInvalidAuthenticationSilo:      ClassInvalidRequest,
	ErrInvalidDirectorySettings:       ClassInvalidRequest,
	ErrInvalidFineGrainedPolicy:       ClassInvalidRequest,
	ErrInvalidFunctionalLevel:         ClassInvalidRequest,
	ErrInvalidOperationMasterRequest:  ClassInvalidRequest,
	ErrInvalidOptionalFeature:         ClassInvalidRequest,
	ErrInvalidRODCPasswordPolicy:      ClassInvalidRequest,
	ErrInvalidReplicationQuery:        ClassInvalidRequest,
	ErrInvalidReplicationSchedule:     ClassInvalidRequest,
	ErrInvalidReplicationSubnet:       ClassInvalidRequest,
	ErrInvalidServiceAccount:          ClassInvalidRequest,
	ErrInvalidServiceAccountInstall:   ClassInvalidRequest,
	ErrCentralAccess:                  ClassInvalidRequest,
	ErrClaimType:                      ClassInvalidRequest,
	ErrClaimTransformPolicy:           ClassInvalidRequest,
	ErrClaimTransformLink:             ClassInvalidRequest,
	ErrClaimTransformRule:             ClassInvalidRequest,
	ErrResourceProperty:               ClassInvalidRequest,
	ErrResourcePropertyMember:         ClassInvalidRequest,
	ErrReplicationTopology:            ClassInvalidRequest,
	ErrServiceAccountMigration:        ClassInvalidRequest,
	ErrServiceAccountOtherHost:        ClassInvalidRequest,
	ErrFunctionalLevelLowering:        ClassInvalidRequest,
	ErrObjectNotLeaf:                  ClassInvalidRequest,
	ErrPasswordConstraint:             ClassInvalidRequest,
	ErrFineGrainedPolicySubject:       ClassInvalidRequest,
	ErrAuthenticationPolicyDescriptor: ClassInvalidRequest,
	ErrObjectSyncIdentity:             ClassInvalidRequest,
	ErrValueRange:                     ClassInvalidRequest,
	ErrValuePrecision:                 ClassInvalidRequest,
	ErrValueSentinel:                  ClassInvalidRequest,
	ErrPolicyIntervalRange:            ClassInvalidRequest,
	ErrNotUser:                        ClassInvalidRequest,
	ErrNotGroup:                       ClassInvalidRequest,
	ErrNotComputer:                    ClassInvalidRequest,
	ErrNotOrganizationalUnit:          ClassInvalidRequest,
	ErrNotServiceAccount:              ClassInvalidRequest,
	ErrNotAuthenticationPolicy:        ClassInvalidRequest,
	ErrNotAuthenticationSilo:          ClassInvalidRequest,
	ErrNotNamingContext:               ClassInvalidRequest,
	ErrAccountControlTarget:           ClassInvalidRequest,
	ErrAccountCreationParent:          ClassInvalidRequest,
	ErrOperationMasterRIDPool:         ClassInvalidRequest,

	ErrClosed:         ClassTransport,
	ErrTLSNegotiation: ClassTransport,

	// A read that did not return everything, or a value that could not be
	// determined. Nothing was written, and what came back is usable — but
	// absence in the result does not establish absence in the directory,
	// which is the mistake this class exists to prevent. The limit sentinels
	// sit here rather than in ClassInvalidRequest because a reached
	// collection bound truncates an answer rather than rejecting a call.
	ErrIncompleteResult:               ClassIncomplete,
	ErrSearchReferences:               ClassIncomplete,
	ErrAttributeUnavailable:           ClassIncomplete,
	ErrAccountStateUnreadable:         ClassIncomplete,
	ErrAccountPasswordPermission:      ClassIncomplete,
	ErrAuthorizationGroupsUnavailable: ClassIncomplete,
	ErrServiceAccountReadiness:        ClassIncomplete,
	ErrDeletedObjectUnavailable:       ClassIncomplete,
	ErrCentralAccessReferences:        ClassIncomplete,
	ErrMembershipForeign:              ClassIncomplete,
	ErrMembershipLimit:                ClassIncomplete,
	ErrGroupMembershipLimit:           ClassIncomplete,
	ErrCentralAccessMemberLimit:       ClassIncomplete,
	ErrFineGrainedPolicyLimit:         ClassIncomplete,
	ErrReplicationReferenceLimit:      ClassIncomplete,
	ErrServiceAccountAssociationLimit: ClassIncomplete,
}

// ldapStatusClasses maps the LDAP result codes the SDK already acts on to
// classes, so a caller gets the same answer whether a refusal arrived as a
// sentinel or as a bare server status. The codes are the ones this package
// already tests by number — 50 in object_sync.go, operation_master.go,
// optional_features_change.go and rodc_password_policy.go, and 1/52/53 in
// operation_master.go — plus the two a caller cannot do without: 32 for an
// absent object and 68 for one that already exists.
//
// It is deliberately not a full table of RFC 4511 codes. A code absent here
// contributes no class rather than a guessed one, and the sentinel joined
// alongside it decides.
var ldapStatusClasses = map[uint32]ErrorClass{
	1:  ClassUnsupported,    // operationsError
	32: ClassNotFound,       // noSuchObject
	50: ClassDenied,         // insufficientAccessRights
	52: ClassUnsupported,    // unavailable
	53: ClassUnsupported,    // unwillingToPerform
	68: ClassAlreadyExists,  // entryAlreadyExists
	19: ClassInvalidRequest, // constraintViolation
	21: ClassInvalidRequest, // invalidAttributeSyntax
	64: ClassInvalidRequest, // namingViolation
	65: ClassInvalidRequest, // objectClassViolation
	66: ClassConflict,       // notAllowedOnNonLeaf
	49: ClassDenied,         // invalidCredentials
}

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
func Classify(err error) ErrorClass {
	if err == nil {
		return ClassUnclassified
	}
	var present [len(classPrecedence) + 1]bool
	// errors.Is per sentinel rather than one walk of the error tree, because
	// at least one error type here classifies itself through a custom Is
	// method (LocalServiceAccountNativeError maps two NTSTATUS values onto a
	// permission sentinel) and a tree walk would not see it. This runs only
	// on a failure path.
	for sentinel, class := range sentinelClasses {
		if errors.Is(err, sentinel) {
			present[class] = true
		}
	}
	var ldapErr *LDAPError
	if errors.As(err, &ldapErr) {
		if class, ok := ldapStatusClasses[ldapErr.Code]; ok {
			present[class] = true
		}
	}
	for _, class := range classPrecedence {
		if present[class] {
			return class
		}
	}
	return ClassUnclassified
}

// IsUncertain reports whether a write was attempted and its outcome is not
// known. A caller must not record the change as applied or as absent, and must
// re-read the target before repeating the operation.
//
// This is the one predicate here a caller cannot safely omit. Every other
// class says the directory's state is known.
func IsUncertain(err error) bool { return Classify(err) == ClassUncertain }

// IsDenied reports whether the bound identity is not permitted to do this.
// Retrying with the same credential cannot succeed.
func IsDenied(err error) bool { return Classify(err) == ClassDenied }

// IsConflict reports whether the directory's observed state was not the state
// the operation required. Nothing was written; re-reading and retrying is the
// remedy.
func IsConflict(err error) bool { return Classify(err) == ClassConflict }

// IsAlreadyExists reports whether the object a caller asked to create is
// already present.
func IsAlreadyExists(err error) bool { return Classify(err) == ClassAlreadyExists }

// IsNotFound reports whether no object matched.
//
// It is false for an error that is also denied, because an Active Directory
// search omits objects the bound identity cannot read, so a permissions
// failure can otherwise look like a deletion.
func IsNotFound(err error) bool { return Classify(err) == ClassNotFound }

// IsUnsupported reports whether this platform, endpoint or directory type
// cannot perform the operation at all. No credential changes that here.
func IsUnsupported(err error) bool { return Classify(err) == ClassUnsupported }

// IsInvalidRequest reports whether the remedy is in the request rather than in
// the directory. Nothing was written, and retrying the call unchanged cannot
// succeed.
func IsInvalidRequest(err error) bool { return Classify(err) == ClassInvalidRequest }

// IsTransport reports whether the session or connection failed. A read may be
// retried on a new session; a write that may already have been submitted
// classifies as uncertain instead.
func IsTransport(err error) bool { return Classify(err) == ClassTransport }

// IsIncomplete reports whether a read returned less than was asked for.
// Nothing was written and the partial answer is usable, but absence from it
// does not establish absence in the directory.
func IsIncomplete(err error) bool { return Classify(err) == ClassIncomplete }
