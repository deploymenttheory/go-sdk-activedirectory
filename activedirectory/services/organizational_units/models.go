// Package organizational_units provides the organizational_units SDK interface.
package organizational_units

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// CreateOrganizationalUnitRequest is the SDK's CreateOrganizationalUnitRequest.
type CreateOrganizationalUnitRequest = admodel.CreateOrganizationalUnitRequest

// DeleteOrganizationalUnitRequest is the SDK's DeleteOrganizationalUnitRequest.
type DeleteOrganizationalUnitRequest = admodel.DeleteOrganizationalUnitRequest

// ErrNotOrganizationalUnit is the SDK's ErrNotOrganizationalUnit.
var ErrNotOrganizationalUnit = admodel.ErrNotOrganizationalUnit

// ErrOUProtection is the SDK's ErrOUProtection.
var ErrOUProtection = admodel.ErrOUProtection

// OUProperties uses nil to omit a property; a pointer to an empty string is an
// explicit empty value. Use the common AttributeChange Clear operation to clear
// one. ManagedBy is an explicit DN, not an inferred account name.
type OUProperties = admodel.OUProperties

// OUProtectionResult is the SDK's OUProtectionResult.
type OUProtectionResult = admodel.OUProtectionResult

// OUProtectionStep records one object's ACL observation and write. Parent and
// OU changes are separate LDAP operations; an earlier accepted write survives
// later failure. Neither partial success nor uncertainty triggers rollback.
type OUProtectionStep = admodel.OUProtectionStep

// OrganizationalUnit retains raw LDAP values and unknown optional properties.
// Protection is an ACL observation, not a guarantee against every privileged
// operation or recursive deletion of an ancestor.
type OrganizationalUnit = admodel.OrganizationalUnit

// OrganizationalUnitMutationResult is the SDK's OrganizationalUnitMutationResult.
type OrganizationalUnitMutationResult = admodel.OrganizationalUnitMutationResult

// OrganizationalUnitResult is the SDK's OrganizationalUnitResult.
type OrganizationalUnitResult = admodel.OrganizationalUnitResult

// OrganizationalUnitsResult is the SDK's OrganizationalUnitsResult.
type OrganizationalUnitsResult = admodel.OrganizationalUnitsResult

// UpdateOrganizationalUnitRequest is the SDK's UpdateOrganizationalUnitRequest.
type UpdateOrganizationalUnitRequest = admodel.UpdateOrganizationalUnitRequest
