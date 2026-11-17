// Package directory_settings provides the directory_settings SDK interface.
package directory_settings

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ErrDirectorySettingsTarget is the SDK's ErrDirectorySettingsTarget.
var ErrDirectorySettingsTarget = admodel.ErrDirectorySettingsTarget

// ErrFunctionalLevelLowering is the SDK's ErrFunctionalLevelLowering.
var ErrFunctionalLevelLowering = admodel.ErrFunctionalLevelLowering

// ErrFunctionalLevelPrerequisite is the SDK's ErrFunctionalLevelPrerequisite.
var ErrFunctionalLevelPrerequisite = admodel.ErrFunctionalLevelPrerequisite

// ErrFunctionalLevelRoleOwner is the SDK's ErrFunctionalLevelRoleOwner.
var ErrFunctionalLevelRoleOwner = admodel.ErrFunctionalLevelRoleOwner

// ErrInvalidDirectorySettings is the SDK's ErrInvalidDirectorySettings.
var ErrInvalidDirectorySettings = admodel.ErrInvalidDirectorySettings

// ErrInvalidFunctionalLevel is the SDK's ErrInvalidFunctionalLevel.
var ErrInvalidFunctionalLevel = admodel.ErrInvalidFunctionalLevel

// ErrInvalidOptionalFeature is the SDK's ErrInvalidOptionalFeature.
var ErrInvalidOptionalFeature = admodel.ErrInvalidOptionalFeature

// ErrOptionalFeatureIrreversible is the SDK's ErrOptionalFeatureIrreversible.
var ErrOptionalFeatureIrreversible = admodel.ErrOptionalFeatureIrreversible

// ErrOptionalFeaturePermission is the SDK's ErrOptionalFeaturePermission.
var ErrOptionalFeaturePermission = admodel.ErrOptionalFeaturePermission

// ErrOptionalFeaturePrerequisite is the SDK's ErrOptionalFeaturePrerequisite.
var ErrOptionalFeaturePrerequisite = admodel.ErrOptionalFeaturePrerequisite

// ErrOptionalFeatureReadback is the SDK's ErrOptionalFeatureReadback.
var ErrOptionalFeatureReadback = admodel.ErrOptionalFeatureReadback

// ErrOptionalFeatureRole is the SDK's ErrOptionalFeatureRole.
var ErrOptionalFeatureRole = admodel.ErrOptionalFeatureRole

// ErrOptionalFeatureScope is the SDK's ErrOptionalFeatureScope.
var ErrOptionalFeatureScope = admodel.ErrOptionalFeatureScope

// ErrOptionalFeatureUncertain is the SDK's ErrOptionalFeatureUncertain.
var ErrOptionalFeatureUncertain = admodel.ErrOptionalFeatureUncertain

// FunctionalLevel is msDS-Behavior-Version, not a schema or OS version. There
// are no distinct Windows Server 2019/2022 levels; those releases use 2016.
type FunctionalLevel = admodel.FunctionalLevel

// FunctionalLevelTransitionRequest identifies the domain NC root (domain
// operation) or CN=Partitions in the configuration NC (forest operation), by
// DN or GUID. A forest GUID needs Options.Partition set to the configuration NC.
// AllowLowering is intent, not an override of compatibility or feature guards.
type FunctionalLevelTransitionRequest = admodel.FunctionalLevelTransitionRequest

// FunctionalLevelTransitionResult retains local raw prerequisite observations
// on failure. PreflightComplete means these checks completed, not that the
// forest is healthy, fully replicated, or every object/attribute was visible.
// The server enforces the transition at write time. No DC is contacted except
// Source, and the SDK never performs ADPrep, replication, or feature changes.
type FunctionalLevelTransitionResult = admodel.FunctionalLevelTransitionResult

// FunctionalLevelWindows2000 is the SDK's FunctionalLevelWindows2000.
const FunctionalLevelWindows2000 = admodel.FunctionalLevelWindows2000

// FunctionalLevelWindows2003 is the SDK's FunctionalLevelWindows2003.
const FunctionalLevelWindows2003 = admodel.FunctionalLevelWindows2003

// FunctionalLevelWindows2003Interim is the SDK's FunctionalLevelWindows2003Interim.
const FunctionalLevelWindows2003Interim = admodel.FunctionalLevelWindows2003Interim

// FunctionalLevelWindows2008 is the SDK's FunctionalLevelWindows2008.
const FunctionalLevelWindows2008 = admodel.FunctionalLevelWindows2008

// FunctionalLevelWindows2008R2 is the SDK's FunctionalLevelWindows2008R2.
const FunctionalLevelWindows2008R2 = admodel.FunctionalLevelWindows2008R2

// FunctionalLevelWindows2012 is the SDK's FunctionalLevelWindows2012.
const FunctionalLevelWindows2012 = admodel.FunctionalLevelWindows2012

// FunctionalLevelWindows2012R2 is the SDK's FunctionalLevelWindows2012R2.
const FunctionalLevelWindows2012R2 = admodel.FunctionalLevelWindows2012R2

// FunctionalLevelWindows2016 is the SDK's FunctionalLevelWindows2016.
const FunctionalLevelWindows2016 = admodel.FunctionalLevelWindows2016

// FunctionalLevelWindows2025 is the SDK's FunctionalLevelWindows2025.
const FunctionalLevelWindows2025 = admodel.FunctionalLevelWindows2025

// OptionalFeature preserves unknown flags and missing properties. EnabledScopes
// are observations, not proof that an omitted backlink is empty. Raw retains
// metadata; EnabledScopeObjects retains unmerged backlink range responses.
type OptionalFeature = admodel.OptionalFeature

// OptionalFeatureChangeRequest identifies the exact feature and scope object.
// Forest/configuration-set scope uses CN=Partitions,<configuration NC>; domain
// scope uses this AD DS server's default domain NC; server scope uses its DSA.
// The connection must already target the naming master for forest scope.
type OptionalFeatureChangeRequest = admodel.OptionalFeatureChangeRequest

// OptionalFeatureChangeResult retains an acknowledged write even if subsequent
// readback fails. Verified describes this server's local scope link, not forest
// convergence. Nil enabled values mean unobserved/hidden, not false.
type OptionalFeatureChangeResult = admodel.OptionalFeatureChangeResult

// OptionalFeatureDatabase32KPagesGUID is the SDK's OptionalFeatureDatabase32KPagesGUID.
const OptionalFeatureDatabase32KPagesGUID = admodel.OptionalFeatureDatabase32KPagesGUID

// OptionalFeatureDisablableFlag is the SDK's OptionalFeatureDisablableFlag.
const OptionalFeatureDisablableFlag = admodel.OptionalFeatureDisablableFlag

// OptionalFeatureDomain is the SDK's OptionalFeatureDomain.
const OptionalFeatureDomain = admodel.OptionalFeatureDomain

// OptionalFeatureDomainFlag is the SDK's OptionalFeatureDomainFlag.
const OptionalFeatureDomainFlag = admodel.OptionalFeatureDomainFlag

// OptionalFeatureFlags is the SDK's OptionalFeatureFlags.
type OptionalFeatureFlags = admodel.OptionalFeatureFlags

// OptionalFeatureForest is the SDK's OptionalFeatureForest.
const OptionalFeatureForest = admodel.OptionalFeatureForest

// OptionalFeatureForestFlag is the SDK's OptionalFeatureForestFlag.
const OptionalFeatureForestFlag = admodel.OptionalFeatureForestFlag

// OptionalFeaturePAMGUID is the SDK's OptionalFeaturePAMGUID.
const OptionalFeaturePAMGUID = admodel.OptionalFeaturePAMGUID

// OptionalFeatureQuery selects at most one identity/filter; zero selects all.
// GUID selectors use binary LDAP equality. LDAPFilter uses LDAP syntax, not
// PowerShell expressions. ResultLimit is explicit and never means completion.
type OptionalFeatureQuery = admodel.OptionalFeatureQuery

// OptionalFeatureRecycleBinGUID is the SDK's OptionalFeatureRecycleBinGUID.
const OptionalFeatureRecycleBinGUID = admodel.OptionalFeatureRecycleBinGUID

// OptionalFeatureScope is the SDK's OptionalFeatureScope.
type OptionalFeatureScope = admodel.OptionalFeatureScope

// OptionalFeatureServer is the SDK's OptionalFeatureServer.
const OptionalFeatureServer = admodel.OptionalFeatureServer

// OptionalFeatureServerFlag is the SDK's OptionalFeatureServerFlag.
const OptionalFeatureServerFlag = admodel.OptionalFeatureServerFlag

// OptionalFeatureWriteAccepted is the SDK's OptionalFeatureWriteAccepted.
const OptionalFeatureWriteAccepted = admodel.OptionalFeatureWriteAccepted

// OptionalFeatureWriteNotAttempted is the SDK's OptionalFeatureWriteNotAttempted.
const OptionalFeatureWriteNotAttempted = admodel.OptionalFeatureWriteNotAttempted

// OptionalFeatureWriteRejected is the SDK's OptionalFeatureWriteRejected.
const OptionalFeatureWriteRejected = admodel.OptionalFeatureWriteRejected

// OptionalFeatureWriteState is the SDK's OptionalFeatureWriteState.
type OptionalFeatureWriteState = admodel.OptionalFeatureWriteState

// OptionalFeatureWriteUncertain is the SDK's OptionalFeatureWriteUncertain.
const OptionalFeatureWriteUncertain = admodel.OptionalFeatureWriteUncertain

// OptionalFeaturesResult is the SDK's OptionalFeaturesResult.
type OptionalFeaturesResult = admodel.OptionalFeaturesResult

// UpdateDomainRequest identifies the connected DC's domain NC root by DN or
// GUID. Nil typed fields are omitted. A non-nil empty suffix slice clears that
// attribute; Changes supplies exact add/remove/clear and raw binary operations.
// Typed and raw changes for the same attribute conflict. Raw changes cannot
// alter functional levels, role ownership, or object identity through this API.
type UpdateDomainRequest = admodel.UpdateDomainRequest

// UpdateForestRequest identifies CN=Partitions in this connection's
// configuration NC by DN or GUID. GUID identities need the configuration NC
// in Options.Partition. The suffix fields replace their entire value set;
// use Changes for exact add/remove, and omit nil fields to preserve values.
type UpdateForestRequest = admodel.UpdateForestRequest
