// Package groups provides the groups SDK interface.
package groups

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// CreateGroupRequest requires category and scope; omitted Parent selects the
// configured Users container (the Roles container on applicable AD LDS). The
// server enforces schema, uniqueness, naming and directory-specific constraints.
// An omitted SAMAccountName is left to the server; Name is never rewritten.
type CreateGroupRequest = admodel.CreateGroupRequest

// DeleteGroupRequest performs a leaf delete. Deleting a group does not delete
// its members. Tree deletion is available only through explicit DeleteObject.
type DeleteGroupRequest = admodel.DeleteGroupRequest

// ErrInvalidGroup is the SDK's ErrInvalidGroup.
var ErrInvalidGroup = admodel.ErrInvalidGroup

// ErrNotGroup is the SDK's ErrNotGroup.
var ErrNotGroup = admodel.ErrNotGroup

// Group preserves the original object, including unknown flags and ranged
// values. Nil fields were not returned. ScopeUnknown denotes returned flags
// with no recognized unambiguous scope. Members are not implicitly loaded.
type Group = admodel.Group

// GroupCategory is the SDK's GroupCategory.
type GroupCategory = admodel.GroupCategory

// GroupCategoryUnknown is the SDK's GroupCategoryUnknown.
const GroupCategoryUnknown = admodel.GroupCategoryUnknown

// GroupDistribution is the SDK's GroupDistribution.
const GroupDistribution = admodel.GroupDistribution

// GroupDomainLocal is the SDK's GroupDomainLocal.
const GroupDomainLocal = admodel.GroupDomainLocal

// GroupGlobal is the SDK's GroupGlobal.
const GroupGlobal = admodel.GroupGlobal

// GroupMutationResult is the SDK's GroupMutationResult.
type GroupMutationResult = admodel.GroupMutationResult

// GroupResult is the SDK's GroupResult.
type GroupResult = admodel.GroupResult

// GroupScope is the SDK's GroupScope.
type GroupScope = admodel.GroupScope

// GroupScopeUnknown is the SDK's GroupScopeUnknown.
const GroupScopeUnknown = admodel.GroupScopeUnknown

// GroupSecurity is the SDK's GroupSecurity.
const GroupSecurity = admodel.GroupSecurity

// GroupUniversal is the SDK's GroupUniversal.
const GroupUniversal = admodel.GroupUniversal

// GroupsResult is the SDK's GroupsResult.
type GroupsResult = admodel.GroupsResult

// UpdateGroupRequest changes only supplied properties. Use Changes with
// AttributeClear to clear a text property; a non-nil string is a literal value.
// A typed property and a raw change for the same attribute are rejected.
// groupType must be changed through Category/Scope, preserving unrelated bits.
type UpdateGroupRequest = admodel.UpdateGroupRequest
