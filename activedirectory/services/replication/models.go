// Package replication provides the replication SDK interface.
package replication

import (
	context "context"

	adconfig "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// CreateReplicationSiteLinkBridgeRequest is the SDK's CreateReplicationSiteLinkBridgeRequest.
type CreateReplicationSiteLinkBridgeRequest = admodel.CreateReplicationSiteLinkBridgeRequest

// CreateReplicationSiteLinkRequest is the SDK's CreateReplicationSiteLinkRequest.
type CreateReplicationSiteLinkRequest = admodel.CreateReplicationSiteLinkRequest

// CreateReplicationSiteRequest is the SDK's CreateReplicationSiteRequest.
type CreateReplicationSiteRequest = admodel.CreateReplicationSiteRequest

// CreateReplicationSubnetRequest is the SDK's CreateReplicationSubnetRequest.
type CreateReplicationSubnetRequest = admodel.CreateReplicationSubnetRequest

// ErrInvalidReplicationQuery is the SDK's ErrInvalidReplicationQuery.
var ErrInvalidReplicationQuery = admodel.ErrInvalidReplicationQuery

// ErrReplicationPermission identifies an authenticated replication RPC access refusal.
var ErrReplicationPermission = admodel.ErrReplicationPermission

// ErrInvalidReplicationSchedule is the SDK's ErrInvalidReplicationSchedule.
var ErrInvalidReplicationSchedule = admodel.ErrInvalidReplicationSchedule

// ErrInvalidReplicationSubnet is the SDK's ErrInvalidReplicationSubnet.
var ErrInvalidReplicationSubnet = admodel.ErrInvalidReplicationSubnet

// ErrReplicationReferenceChanged is the SDK's ErrReplicationReferenceChanged.
var ErrReplicationReferenceChanged = admodel.ErrReplicationReferenceChanged

// ErrReplicationReferenceLimit is the SDK's ErrReplicationReferenceLimit.
var ErrReplicationReferenceLimit = admodel.ErrReplicationReferenceLimit

// ErrReplicationSiteNotEmpty is the SDK's ErrReplicationSiteNotEmpty.
var ErrReplicationSiteNotEmpty = admodel.ErrReplicationSiteNotEmpty

// ErrReplicationTopology is the SDK's ErrReplicationTopology.
var ErrReplicationTopology = admodel.ErrReplicationTopology

// ErrReplicationTopologyIncomplete reports that a site change stopped
// after at least one of its object writes had already been accepted, so
// the directory holds part of the change. It mirrors the creation-incomplete
// sentinels the user, computer and service-account paths return, and exists
// because the underlying failure alone does not say that anything landed:
// a refused third write reports only the refusal, which reads as though the
// whole change was rejected.
var ErrReplicationTopologyIncomplete = admodel.ErrReplicationTopologyIncomplete

// MoveDirectoryServerRequest is the SDK's MoveDirectoryServerRequest.
type MoveDirectoryServerRequest = admodel.MoveDirectoryServerRequest

// MoveDirectoryServerResult is the SDK's MoveDirectoryServerResult.
type MoveDirectoryServerResult = admodel.MoveDirectoryServerResult

// ReadReplicationFailures preserves connection and link failures separately.
// A successful zero-count native response is a confirmed empty collection;
// failed reads retain their native error and any other successful categories.
//
// Related cmdlet: Get-ADReplicationFailure.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationfailure?view=windowsserver2025-ps
func ReadReplicationFailures(
	ctx context.Context,
	config adconfig.Config,
	query ReplicationFailureQuery,
) (result ReplicationFailuresResult, err error) {
	return adengine.ReadReplicationFailures(ctx, config, query)
}

// ReadReplicationPartners reads inbound synchronization and/or outbound
// notification metadata from every selected server. LDAP omission is returned
// as incomplete, not as proof of no outbound partners. RPC and LDAP reads are
// sequential observations, not an atomic snapshot. See docs/replication.md.
//
// Related cmdlet: Get-ADReplicationPartnerMetadata.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationpartnermetadata?view=windowsserver2025-ps
func ReadReplicationPartners(
	ctx context.Context,
	config adconfig.Config,
	query ReplicationPartnerQuery,
) (ReplicationPartnersResult, error) {
	return adengine.ReadReplicationPartners(ctx, config, query)
}

// ReadReplicationQueue preserves native queue order (the first pending item
// is executing) and the native container's current-operation start time.
//
// Related cmdlet: Get-ADReplicationQueueOperation.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationqueueoperation?view=windowsserver2025-ps
func ReadReplicationQueue(
	ctx context.Context,
	config adconfig.Config,
	query ReplicationQueueQuery,
) (result ReplicationQueueResult, err error) {
	return adengine.ReadReplicationQueue(ctx, config, query)
}

// ReplicationBoth is the SDK's ReplicationBoth.
const ReplicationBoth = admodel.ReplicationBoth

// ReplicationConnection is the SDK's ReplicationConnection.
type ReplicationConnection = admodel.ReplicationConnection

// ReplicationConnectionDisableCompression is the SDK's ReplicationConnectionDisableCompression.
const ReplicationConnectionDisableCompression = admodel.ReplicationConnectionDisableCompression

// ReplicationConnectionFailure is the SDK's ReplicationConnectionFailure.
const ReplicationConnectionFailure = admodel.ReplicationConnectionFailure

// ReplicationConnectionGenerated is the SDK's ReplicationConnectionGenerated.
const ReplicationConnectionGenerated = admodel.ReplicationConnectionGenerated

// ReplicationConnectionIgnoreSchedule is the SDK's ReplicationConnectionIgnoreSchedule.
const ReplicationConnectionIgnoreSchedule = admodel.ReplicationConnectionIgnoreSchedule

// ReplicationConnectionMutationResult is the SDK's ReplicationConnectionMutationResult.
type ReplicationConnectionMutationResult = admodel.ReplicationConnectionMutationResult

// ReplicationConnectionOptions is the SDK's ReplicationConnectionOptions.
type ReplicationConnectionOptions = admodel.ReplicationConnectionOptions

// ReplicationConnectionOverrideNotifyDefault is the SDK's ReplicationConnectionOverrideNotifyDefault.
const ReplicationConnectionOverrideNotifyDefault = admodel.ReplicationConnectionOverrideNotifyDefault

// ReplicationConnectionRODCTopology is the SDK's ReplicationConnectionRODCTopology.
const ReplicationConnectionRODCTopology = admodel.ReplicationConnectionRODCTopology

// ReplicationConnectionResult is the SDK's ReplicationConnectionResult.
type ReplicationConnectionResult = admodel.ReplicationConnectionResult

// ReplicationConnectionTwoWaySync is the SDK's ReplicationConnectionTwoWaySync.
const ReplicationConnectionTwoWaySync = admodel.ReplicationConnectionTwoWaySync

// ReplicationConnectionUseNotify is the SDK's ReplicationConnectionUseNotify.
const ReplicationConnectionUseNotify = admodel.ReplicationConnectionUseNotify

// ReplicationConnectionUserOwnedSchedule is the SDK's ReplicationConnectionUserOwnedSchedule.
const ReplicationConnectionUserOwnedSchedule = admodel.ReplicationConnectionUserOwnedSchedule

// ReplicationConnectionsResult is the SDK's ReplicationConnectionsResult.
type ReplicationConnectionsResult = admodel.ReplicationConnectionsResult

// ReplicationDirection is the SDK's ReplicationDirection.
type ReplicationDirection = admodel.ReplicationDirection

// ReplicationFailure.Time is first failure for a connection failure and last
// successful replication for a link failure. LastResult zero means that the
// specific failure code was unavailable; the record still describes a failure.
type ReplicationFailure = admodel.ReplicationFailure

// ReplicationFailureKind is the SDK's ReplicationFailureKind.
type ReplicationFailureKind = admodel.ReplicationFailureKind

// ReplicationFailureQuery is the SDK's ReplicationFailureQuery.
type ReplicationFailureQuery = admodel.ReplicationFailureQuery

// ReplicationFailureServer is the SDK's ReplicationFailureServer.
type ReplicationFailureServer = admodel.ReplicationFailureServer

// ReplicationFailuresResult is the SDK's ReplicationFailuresResult.
type ReplicationFailuresResult = admodel.ReplicationFailuresResult

// ReplicationInbound is the SDK's ReplicationInbound.
const ReplicationInbound = admodel.ReplicationInbound

// ReplicationLinkFailure is the SDK's ReplicationLinkFailure.
const ReplicationLinkFailure = admodel.ReplicationLinkFailure

// ReplicationLinkMutationResult is the SDK's ReplicationLinkMutationResult.
type ReplicationLinkMutationResult = admodel.ReplicationLinkMutationResult

// ReplicationLinkReadOptions is the SDK's ReplicationLinkReadOptions.
type ReplicationLinkReadOptions = admodel.ReplicationLinkReadOptions

// ReplicationOperationAdd is the SDK's ReplicationOperationAdd.
const ReplicationOperationAdd = admodel.ReplicationOperationAdd

// ReplicationOperationDelete is the SDK's ReplicationOperationDelete.
const ReplicationOperationDelete = admodel.ReplicationOperationDelete

// ReplicationOperationModify is the SDK's ReplicationOperationModify.
const ReplicationOperationModify = admodel.ReplicationOperationModify

// ReplicationOperationSync is the SDK's ReplicationOperationSync.
const ReplicationOperationSync = admodel.ReplicationOperationSync

// ReplicationOperationType retains unknown native operation numbers.
type ReplicationOperationType = admodel.ReplicationOperationType

// ReplicationOperationUpdateReferences is the SDK's ReplicationOperationUpdateReferences.
const ReplicationOperationUpdateReferences = admodel.ReplicationOperationUpdateReferences

// ReplicationOutbound is the SDK's ReplicationOutbound.
const ReplicationOutbound = admodel.ReplicationOutbound

// ReplicationPartner preserves reported values, including zero GUIDs, unknown
// flag bits and status codes. Nil fields are unreported, not zero. Outbound
// attempt/success/status describe notification delivery; they must not be
// substituted with an inbound partner's synchronization measurements.
type ReplicationPartner = admodel.ReplicationPartner

// ReplicationPartnerQuery is the SDK's ReplicationPartnerQuery.
type ReplicationPartnerQuery = admodel.ReplicationPartnerQuery

// ReplicationPartnerServer is the SDK's ReplicationPartnerServer.
type ReplicationPartnerServer = admodel.ReplicationPartnerServer

// ReplicationPartnersResult is the SDK's ReplicationPartnersResult.
type ReplicationPartnersResult = admodel.ReplicationPartnersResult

// ReplicationQueryState distinguishes a successful empty native result from a
// failed query or omitted information. An omitted LDAP attribute is not proof
// that the collection is empty: access checks can hide its values.
type ReplicationQueryState = admodel.ReplicationQueryState

// ReplicationQueueOperation is the SDK's ReplicationQueueOperation.
type ReplicationQueueOperation = admodel.ReplicationQueueOperation

// ReplicationQueueQuery is the SDK's ReplicationQueueQuery.
type ReplicationQueueQuery = admodel.ReplicationQueueQuery

// ReplicationQueueResult is the SDK's ReplicationQueueResult.
type ReplicationQueueResult = admodel.ReplicationQueueResult

// ReplicationQueueServer is the SDK's ReplicationQueueServer.
type ReplicationQueueServer = admodel.ReplicationQueueServer

// ReplicationReadError retains the affected server and native/context cause.
// Other servers' successful results remain in the returned result.
type ReplicationReadError = admodel.ReplicationReadError

// ReplicationReference is the SDK's ReplicationReference.
type ReplicationReference = admodel.ReplicationReference

// ReplicationReferenceChanges applies either an explicit replacement (a non-nil
// slice, including empty) or disjoint Add/Remove values in one LDAP Modify.
type ReplicationReferenceChanges = admodel.ReplicationReferenceChanges

// ReplicationReferenceInput is the SDK's ReplicationReferenceInput.
type ReplicationReferenceInput = admodel.ReplicationReferenceInput

// ReplicationReferenceLimits is the SDK's ReplicationReferenceLimits.
type ReplicationReferenceLimits = admodel.ReplicationReferenceLimits

// ReplicationReferenceRange is the SDK's ReplicationReferenceRange.
type ReplicationReferenceRange = admodel.ReplicationReferenceRange

// Complete describes contiguous retrieval at one observed GUID/USN, not ACL
// visibility. AttributeReturned distinguishes omission from a returned empty set.
type ReplicationReferencesResult = admodel.ReplicationReferencesResult

// ReplicationSchedule is a UTC week, Sunday first, with four 15-minute slots
// per hour. Zero means no slots enabled. It never applies local timezone/DST.
type ReplicationSchedule = admodel.ReplicationSchedule

// ReplicationScheduleFromBytes rejects malformed/unsupported headers and
// reserved bits. Callers retain the original raw attribute alongside failures.
func ReplicationScheduleFromBytes(data []byte) (ReplicationSchedule, error) {
	return admodel.ReplicationScheduleFromBytes(data)
}

// ReplicationScope determines which servers are selected before any per-server
// replication query. Domain, forest and site scopes require AD DS topology.
type ReplicationScope = admodel.ReplicationScope

// ReplicationScopeDomain is the SDK's ReplicationScopeDomain.
const ReplicationScopeDomain = admodel.ReplicationScopeDomain

// ReplicationScopeForest is the SDK's ReplicationScopeForest.
const ReplicationScopeForest = admodel.ReplicationScopeForest

// ReplicationScopeServer is the SDK's ReplicationScopeServer.
const ReplicationScopeServer = admodel.ReplicationScopeServer

// ReplicationScopeSite is the SDK's ReplicationScopeSite.
const ReplicationScopeSite = admodel.ReplicationScopeSite

// ReplicationSelection resolves targets through Config.Endpoint. Server scope
// uses Servers, or the configured endpoint when Servers is empty. DomainDNS and
// ForestDNS select or verify a domain/forest in the anchor's authenticated
// topology. Empty names select that topology's current domain or forest.
// SiteName names a site in that forest. No trust or referral is followed.
type ReplicationSelection = admodel.ReplicationSelection

// ReplicationServicePrincipals pins the LDAP, endpoint-map and DRS service
// identities separately for one selected DNS host. See ReplicationSelection.
type ReplicationServicePrincipals = admodel.ReplicationServicePrincipals

// ReplicationRPCProtection reports actual keyless protection facts for one
// endpoint-map or DRS stage, independently of the diagnostic query outcome.
type ReplicationRPCProtection = admodel.ReplicationRPCProtection

// ReplicationServerObservation is the SDK's ReplicationServerObservation.
type ReplicationServerObservation = admodel.ReplicationServerObservation

// ReplicationSite is the SDK's ReplicationSite.
type ReplicationSite = admodel.ReplicationSite

// ReplicationSiteLink is the SDK's ReplicationSiteLink.
type ReplicationSiteLink = admodel.ReplicationSiteLink

// ReplicationSiteLinkBridge is the SDK's ReplicationSiteLinkBridge.
type ReplicationSiteLinkBridge = admodel.ReplicationSiteLinkBridge

// ReplicationSiteLinkBridgeResult is the SDK's ReplicationSiteLinkBridgeResult.
type ReplicationSiteLinkBridgeResult = admodel.ReplicationSiteLinkBridgeResult

// ReplicationSiteLinkBridgesResult is the SDK's ReplicationSiteLinkBridgesResult.
type ReplicationSiteLinkBridgesResult = admodel.ReplicationSiteLinkBridgesResult

// ReplicationSiteLinkDisableCompression is the SDK's ReplicationSiteLinkDisableCompression.
const ReplicationSiteLinkDisableCompression = admodel.ReplicationSiteLinkDisableCompression

// ReplicationSiteLinkOptions is the SDK's ReplicationSiteLinkOptions.
type ReplicationSiteLinkOptions = admodel.ReplicationSiteLinkOptions

// ReplicationSiteLinkResult is the SDK's ReplicationSiteLinkResult.
type ReplicationSiteLinkResult = admodel.ReplicationSiteLinkResult

// ReplicationSiteLinkTwoWaySync is the SDK's ReplicationSiteLinkTwoWaySync.
const ReplicationSiteLinkTwoWaySync = admodel.ReplicationSiteLinkTwoWaySync

// ReplicationSiteLinkUseNotify is the SDK's ReplicationSiteLinkUseNotify.
const ReplicationSiteLinkUseNotify = admodel.ReplicationSiteLinkUseNotify

// ReplicationSiteLinksResult is the SDK's ReplicationSiteLinksResult.
type ReplicationSiteLinksResult = admodel.ReplicationSiteLinksResult

// Stages are ordered, independent native writes. Complete never means atomic
// across objects; accepted earlier stages survive a later failure without rollback.
type ReplicationSiteMutationResult = admodel.ReplicationSiteMutationResult

// ReplicationSiteOptions is the SDK's ReplicationSiteOptions.
type ReplicationSiteOptions = admodel.ReplicationSiteOptions

// ReplicationSiteResult is the SDK's ReplicationSiteResult.
type ReplicationSiteResult = admodel.ReplicationSiteResult

// ReplicationSiteSettings is the SDK's ReplicationSiteSettings.
type ReplicationSiteSettings = admodel.ReplicationSiteSettings

// SetOptions/ClearOptions change only selected documented bits, preserving
// unrecognized bits. Schedule is UTC; ClearSchedule explicitly requests removal.
type ReplicationSiteSettingsPatch = admodel.ReplicationSiteSettingsPatch

// ReplicationSitesResult is the SDK's ReplicationSitesResult.
type ReplicationSitesResult = admodel.ReplicationSitesResult

// ReplicationSubnet is the SDK's ReplicationSubnet.
type ReplicationSubnet = admodel.ReplicationSubnet

// ReplicationSubnetMutationResult is the SDK's ReplicationSubnetMutationResult.
type ReplicationSubnetMutationResult = admodel.ReplicationSubnetMutationResult

// ReplicationSubnetResult is the SDK's ReplicationSubnetResult.
type ReplicationSubnetResult = admodel.ReplicationSubnetResult

// ReplicationSubnetsResult is the SDK's ReplicationSubnetsResult.
type ReplicationSubnetsResult = admodel.ReplicationSubnetsResult

// ReplicationTargets retains target discovery independently of server health.
// A partial discovery can still yield servers whose results are useful.
type ReplicationTargets = admodel.ReplicationTargets

// ReplicationTimestamp preserves native 100ns FILETIME precision. Nil Ticks
// means the source did not report this field. Reported zero ticks are retained,
// with nil UTC, rather than being presented as a successful event in 1601.
type ReplicationTimestamp = admodel.ReplicationTimestamp

// ReplicationTopologyStep is the SDK's ReplicationTopologyStep.
type ReplicationTopologyStep = admodel.ReplicationTopologyStep

// ReplicationTransport selects the interSiteTransport container. IP is the
// default. AD LDS does not support SMTP replication.
type ReplicationTransport = admodel.ReplicationTransport

// ReplicationTransportIP is the SDK's ReplicationTransportIP.
const ReplicationTransportIP = admodel.ReplicationTransportIP

// ReplicationTransportSMTP is the SDK's ReplicationTransportSMTP.
const ReplicationTransportSMTP = admodel.ReplicationTransportSMTP

// ResolveReplicationTargets expands a server/domain/forest/site selection using
// the configured authenticated LDAP endpoint. Resolution is independent of the
// targets' replication health and never follows a trust or LDAP referral.
func ResolveReplicationTargets(
	ctx context.Context,
	config adconfig.Config,
	selection ReplicationSelection,
) (ReplicationTargets, error) {
	return adengine.ResolveReplicationTargets(ctx, config, selection)
}

// SiteDisableAutomaticIntersiteTopology is the SDK's SiteDisableAutomaticIntersiteTopology.
const SiteDisableAutomaticIntersiteTopology = admodel.SiteDisableAutomaticIntersiteTopology

// SiteDisableAutomaticTopology is the SDK's SiteDisableAutomaticTopology.
const SiteDisableAutomaticTopology = admodel.SiteDisableAutomaticTopology

// SiteDisableMinimumHops is the SDK's SiteDisableMinimumHops.
const SiteDisableMinimumHops = admodel.SiteDisableMinimumHops

// SiteDisableRandomBridgeheadSelection is the SDK's SiteDisableRandomBridgeheadSelection.
const SiteDisableRandomBridgeheadSelection = admodel.SiteDisableRandomBridgeheadSelection

// SiteDisableStaleDetection is the SDK's SiteDisableStaleDetection.
const SiteDisableStaleDetection = admodel.SiteDisableStaleDetection

// SiteDisableTopologyCleanup is the SDK's SiteDisableTopologyCleanup.
const SiteDisableTopologyCleanup = admodel.SiteDisableTopologyCleanup

// SiteEnableRedundantServerTopology is the SDK's SiteEnableRedundantServerTopology.
const SiteEnableRedundantServerTopology = admodel.SiteEnableRedundantServerTopology

// SiteEnableScheduleHashing is the SDK's SiteEnableScheduleHashing.
const SiteEnableScheduleHashing = admodel.SiteEnableScheduleHashing

// SiteEnableUniversalGroupCaching is the SDK's SiteEnableUniversalGroupCaching.
const SiteEnableUniversalGroupCaching = admodel.SiteEnableUniversalGroupCaching

// SiteForceWindows2000ISTGElection is the SDK's SiteForceWindows2000ISTGElection.
const SiteForceWindows2000ISTGElection = admodel.SiteForceWindows2000ISTGElection

// SiteForceWindows2003KCCBehavior is the SDK's SiteForceWindows2003KCCBehavior.
const SiteForceWindows2003KCCBehavior = admodel.SiteForceWindows2003KCCBehavior

// SiteWindows2003BridgesRequired is the SDK's SiteWindows2003BridgesRequired.
const SiteWindows2003BridgesRequired = admodel.SiteWindows2003BridgesRequired

// SiteWindows2003IgnoreSchedules is the SDK's SiteWindows2003IgnoreSchedules.
const SiteWindows2003IgnoreSchedules = admodel.SiteWindows2003IgnoreSchedules

// UpdateReplicationConnectionRequest is the SDK's UpdateReplicationConnectionRequest.
type UpdateReplicationConnectionRequest = admodel.UpdateReplicationConnectionRequest

// UpdateReplicationSiteLinkBridgeRequest is the SDK's UpdateReplicationSiteLinkBridgeRequest.
type UpdateReplicationSiteLinkBridgeRequest = admodel.UpdateReplicationSiteLinkBridgeRequest

// UpdateReplicationSiteLinkRequest is the SDK's UpdateReplicationSiteLinkRequest.
type UpdateReplicationSiteLinkRequest = admodel.UpdateReplicationSiteLinkRequest

// UpdateReplicationSiteRequest is the SDK's UpdateReplicationSiteRequest.
type UpdateReplicationSiteRequest = admodel.UpdateReplicationSiteRequest

// UpdateReplicationSubnetRequest is the SDK's UpdateReplicationSubnetRequest.
type UpdateReplicationSubnetRequest = admodel.UpdateReplicationSubnetRequest
