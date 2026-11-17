// Package resource_properties provides the resource_properties SDK interface.
package resource_properties

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// CreateResourcePropertyListRequest creates one property list.
type CreateResourcePropertyListRequest = admodel.CreateResourcePropertyListRequest

// CreateResourcePropertyRequest creates one resource property.
type CreateResourcePropertyRequest = admodel.CreateResourcePropertyRequest

// ErrResourceProperty is the SDK's ErrResourceProperty.
var ErrResourceProperty = admodel.ErrResourceProperty

// ErrResourcePropertyMember is the SDK's ErrResourcePropertyMember.
var ErrResourcePropertyMember = admodel.ErrResourcePropertyMember

// ResourcePropertiesResult is the SDK's ResourcePropertiesResult.
type ResourcePropertiesResult = admodel.ResourcePropertiesResult

// ResourceProperty is one msDS-ResourceProperty. Suggested values and the
// restricted value space mirror the claim-type representation because the
// directory stores them in the same attributes.
type ResourceProperty = admodel.ResourceProperty

// ResourcePropertyList is one msDS-ResourcePropertyList.
type ResourcePropertyList = admodel.ResourcePropertyList

// ResourcePropertyListMemberLimit is the SDK's ResourcePropertyListMemberLimit.
const ResourcePropertyListMemberLimit = admodel.ResourcePropertyListMemberLimit

// ResourcePropertyListMembersRequest adds or removes list members. Members are
// resource properties; each is resolved and verified before any write.
type ResourcePropertyListMembersRequest = admodel.ResourcePropertyListMembersRequest

// ResourcePropertyListMembersResult is the SDK's ResourcePropertyListMembersResult.
type ResourcePropertyListMembersResult = admodel.ResourcePropertyListMembersResult

// ResourcePropertyListMutationResult is the SDK's ResourcePropertyListMutationResult.
type ResourcePropertyListMutationResult = admodel.ResourcePropertyListMutationResult

// ResourcePropertyListResult is the SDK's ResourcePropertyListResult.
type ResourcePropertyListResult = admodel.ResourcePropertyListResult

// ResourcePropertyListsResult is the SDK's ResourcePropertyListsResult.
type ResourcePropertyListsResult = admodel.ResourcePropertyListsResult

// ResourcePropertyMutationResult is the SDK's ResourcePropertyMutationResult.
type ResourcePropertyMutationResult = admodel.ResourcePropertyMutationResult

// ResourcePropertyReadOptions is the SDK's ResourcePropertyReadOptions.
type ResourcePropertyReadOptions = admodel.ResourcePropertyReadOptions

// ResourcePropertyResult is the SDK's ResourcePropertyResult.
type ResourcePropertyResult = admodel.ResourcePropertyResult

// ResourceValueType is one read-only msDS-ValueType.
type ResourceValueType = admodel.ResourceValueType

// ResourceValueTypeResult is the SDK's ResourceValueTypeResult.
type ResourceValueTypeResult = admodel.ResourceValueTypeResult

// ResourceValueTypesResult is the SDK's ResourceValueTypesResult.
type ResourceValueTypesResult = admodel.ResourceValueTypesResult

// UpdateResourcePropertyListRequest changes one property list.
type UpdateResourcePropertyListRequest = admodel.UpdateResourcePropertyListRequest

// UpdateResourcePropertyRequest changes one resource property.
type UpdateResourcePropertyRequest = admodel.UpdateResourcePropertyRequest
