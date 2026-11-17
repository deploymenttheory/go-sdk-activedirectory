// Package object_restoration provides the object_restoration SDK interface.
package object_restoration

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// DeletedObject describes an observation, not a promise that restoration will
// succeed. Omitted metadata is distinct from false. Recycled objects cannot be
// restored through Recycle Bin. An absent object cannot be distinguished from
// expired/garbage-collected, invisible, or never-existing by this LDAP view.
type DeletedObject = admodel.DeletedObject

// DeletedObjectQuery is the SDK's DeletedObjectQuery.
type DeletedObjectQuery = admodel.DeletedObjectQuery

// DeletedObjectState is the SDK's DeletedObjectState.
type DeletedObjectState = admodel.DeletedObjectState

// DeletedObjectsResult is the SDK's DeletedObjectsResult.
type DeletedObjectsResult = admodel.DeletedObjectsResult

// DeletedStateDeleted is the SDK's DeletedStateDeleted.
const DeletedStateDeleted = admodel.DeletedStateDeleted

// DeletedStateProtected is the SDK's DeletedStateProtected.
const DeletedStateProtected = admodel.DeletedStateProtected

// DeletedStateRecycled is the SDK's DeletedStateRecycled.
const DeletedStateRecycled = admodel.DeletedStateRecycled

// DeletedStateTombstone is the SDK's DeletedStateTombstone.
const DeletedStateTombstone = admodel.DeletedStateTombstone

// DeletedStateUnknown is the SDK's DeletedStateUnknown.
const DeletedStateUnknown = admodel.DeletedStateUnknown

// ErrDeletedObjectUnavailable is the SDK's ErrDeletedObjectUnavailable.
var ErrDeletedObjectUnavailable = admodel.ErrDeletedObjectUnavailable

// ErrInvalidObjectRestore is the SDK's ErrInvalidObjectRestore.
var ErrInvalidObjectRestore = admodel.ErrInvalidObjectRestore

// ErrObjectNotRestorable is the SDK's ErrObjectNotRestorable.
var ErrObjectNotRestorable = admodel.ErrObjectNotRestorable

// ErrObjectRestoreFeature is the SDK's ErrObjectRestoreFeature.
var ErrObjectRestoreFeature = admodel.ErrObjectRestoreFeature

// ObjectRestorationCapabilities retains the connected DSA's forward feature
// links and resolved feature objects. Nil means unknown, including omitted or
// ranged links; false is used only for a complete returned list with no match.
type ObjectRestorationCapabilities = admodel.ObjectRestorationCapabilities

// ObjectRestorationResult is the SDK's ObjectRestorationResult.
type ObjectRestorationResult = admodel.ObjectRestorationResult

// ObjectRestoreMode is the SDK's ObjectRestoreMode.
type ObjectRestoreMode = admodel.ObjectRestoreMode

// RestoreLegacyTombstone explicitly permits reanimation without feature
// proof. Stripped attributes/links cannot be recovered by this operation.
const RestoreLegacyTombstone = admodel.RestoreLegacyTombstone

// RestoreObjectRequest restores one object, never a subtree. Identity accepts
// the current deleted DN or GUID. NewName is a literal RDN value; nil selects
// msDS-LastKnownRDN. Zero TargetParent selects lastKnownParent. The selected
// parent must exist in the same naming context. Default mode requires Recycle
// Bin. Legacy mode permits lossy reanimation and explicit replacement Attributes
// for stripped mandatory values. No mode enables directory features.
type RestoreObjectRequest = admodel.RestoreObjectRequest

// RestoreWithRecycleBin requires positively observed feature enablement.
const RestoreWithRecycleBin = admodel.RestoreWithRecycleBin
