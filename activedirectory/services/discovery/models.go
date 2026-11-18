// Package discovery provides the discovery SDK interface.
package discovery

import (
	context "context"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ControllerAddressIP is the SDK's ControllerAddressIP.
const ControllerAddressIP = admodel.ControllerAddressIP

// ControllerAddressNetBIOS is the SDK's ControllerAddressNetBIOS.
const ControllerAddressNetBIOS = admodel.ControllerAddressNetBIOS

// ControllerAddressType identifies the native address representation. Unknown
// values are preserved. The IP form still carries the native leading slashes.
type ControllerAddressType = admodel.ControllerAddressType

// ControllerReplica separates configured GC state from the live endpoint's GC
// readiness. ReadOnly is nil when the category cannot be determined.
type ControllerReplica = admodel.ControllerReplica

// CrossReference retains flags and enabled state without guessing the intent of
// disabled or external references. Linked names are distinguished names.
type CrossReference = admodel.CrossReference

// CurrentDomain returns a name from local-computer join status or the calling
// thread's security identity. It does not authenticate or return domain metadata.
// A caller using thread impersonation must keep its goroutine on that OS thread.
// Explicit LDAP credentials do not affect this operation. Native calls are
// synchronous; cancellation is observed between calls, not by interrupting them.
//
// Related cmdlet: Get-ADDomain.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2025-ps
func CurrentDomain(ctx context.Context, mode CurrentMode) (DomainName, error) {
	return admodel.CurrentDomain(ctx, mode)
}

// CurrentLocalComputer is the SDK's CurrentLocalComputer.
const CurrentLocalComputer = admodel.CurrentLocalComputer

// CurrentLoggedOnUser is the SDK's CurrentLoggedOnUser.
const CurrentLoggedOnUser = admodel.CurrentLoggedOnUser

// CurrentMode explicitly selects the source of the current domain name.
type CurrentMode = admodel.CurrentMode

// DCServices is a set of required or advertised domain-controller services.
type DCServices = admodel.DCServices

// DirectoryServiceVersion selects a minimum DC service generation. It is not
// a domain/forest functional level or a schema version.
type DirectoryServiceVersion = admodel.DirectoryServiceVersion

// DirectoryServiceWindows2000 is the SDK's DirectoryServiceWindows2000.
const DirectoryServiceWindows2000 = admodel.DirectoryServiceWindows2000

// DirectoryServiceWindows2008 is the SDK's DirectoryServiceWindows2008.
const DirectoryServiceWindows2008 = admodel.DirectoryServiceWindows2008

// DirectoryServiceWindows2012 is the SDK's DirectoryServiceWindows2012.
const DirectoryServiceWindows2012 = admodel.DirectoryServiceWindows2012

// DirectoryServiceWindows2012R2 is the SDK's DirectoryServiceWindows2012R2.
const DirectoryServiceWindows2012R2 = admodel.DirectoryServiceWindows2012R2

// DirectoryServiceWindows2016 is the SDK's DirectoryServiceWindows2016.
const DirectoryServiceWindows2016 = admodel.DirectoryServiceWindows2016

// DiscoverDomainController invokes the local DC Locator. Cached results are
// allowed unless ForceDiscover is set. A returned candidate must be explicitly
// authenticated before use. Cancellation is checked between native calls: the
// synchronous locator itself has no interrupt or timeout parameter and may
// delay return. Data may be returned with a cleanup/cancellation error.
//
// Related cmdlet: Get-ADDomainController.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomaincontroller?view=windowsserver2025-ps
func DiscoverDomainController(
	ctx context.Context,
	options DiscoveryOptions,
) (DiscoveredController, error) {
	return admodel.DiscoverDomainController(ctx, options)
}

// DiscoveredController owns copied locator data. It is an advertised candidate,
// not an authenticated LDAP result or a complete DomainController projection.
// Native names/addresses retain their leading backslashes. Optional strings
// distinguish native NULL from an empty string; unknown native flags survive.
type DiscoveredController = admodel.DiscoveredController

// DiscoveryOptions selects one candidate using the local Windows DC Locator.
// Nil Domain uses the local computer's domain (its forest for GC discovery).
// For ServiceGlobalCatalog, an explicit Domain must identify the forest root.
// Discovery does not authenticate or bind, and has no explicit credentials.
type DiscoveryOptions = admodel.DiscoveryOptions

// Domain is the SDK's Domain.
type Domain = admodel.Domain

// DomainController is the SDK's DomainController.
type DomainController = admodel.DomainController

// DomainControllerOptions selects a server object's DN. Empty selects the
// authenticated endpoint's serverName. Host/IP/GUID/computer/DSA identities need
// the shared identity resolver and are deliberately not guessed from strings.
type DomainControllerOptions = admodel.DomainControllerOptions

// DomainControllerResult is the SDK's DomainControllerResult.
type DomainControllerResult = admodel.DomainControllerResult

// DomainControllersQuery offers explicit joined criteria. It is not the
// PowerShell Filter language. General expressions will use the shared compiler.
// DomainDN defaults to the configured/default NC; Sites spans a forest, so the
// query always constrains msDS-HasDomainNCs as well as any site selection.
type DomainControllersQuery = admodel.DomainControllersQuery

// DomainControllersResult is the SDK's DomainControllersResult.
type DomainControllersResult = admodel.DomainControllersResult

// DomainName is a name used for domain selection, not an authenticated identity.
type DomainName = admodel.DomainName

// DomainNameDNS is the SDK's DomainNameDNS.
const DomainNameDNS = admodel.DomainNameDNS

// DomainNameFormat distinguishes DNS names from NetBIOS domain names. A short
// DNS name and a NetBIOS name are not interchangeable on all Windows policies.
type DomainNameFormat = admodel.DomainNameFormat

// DomainNameNetBIOS is the SDK's DomainNameNetBIOS.
const DomainNameNetBIOS = admodel.DomainNameNetBIOS

// DomainOptions selects an explicit domain NC or the configured/default NC.
// Other identity forms will use the shared identity resolver when available.
type DomainOptions = admodel.DomainOptions

// ErrInvalidDiscovery is the SDK's ErrInvalidDiscovery.
var ErrInvalidDiscovery = admodel.ErrInvalidDiscovery

// ErrInvalidNativeResult is the SDK's ErrInvalidNativeResult.
var ErrInvalidNativeResult = admodel.ErrInvalidNativeResult

// ErrNoCurrentDomain is the SDK's ErrNoCurrentDomain.
var ErrNoCurrentDomain = admodel.ErrNoCurrentDomain

// FSMORole is the SDK's FSMORole.
type FSMORole = admodel.FSMORole

// Forest classifies cross-references by their raw systemFlags. Disabled entries
// remain visible with Enabled state; these lists are directory observations,
// not a promise that every naming context is online or reachable.
type Forest = admodel.Forest

// ForestSite is the SDK's ForestSite.
type ForestSite = admodel.ForestSite

// NativeStatusError preserves a Windows status independently of LDAP status.
// Operation identifies the native API; Code is its returned Win32 status.
type NativeStatusError = admodel.NativeStatusError

// ReplicaKind is the SDK's ReplicaKind.
type ReplicaKind = admodel.ReplicaKind

// ReplicaNamingContext is the SDK's ReplicaNamingContext.
type ReplicaNamingContext = admodel.ReplicaNamingContext

// ReplicaPartial is the SDK's ReplicaPartial.
const ReplicaPartial = admodel.ReplicaPartial

// ReplicaReadOnlyFull is the SDK's ReplicaReadOnlyFull.
const ReplicaReadOnlyFull = admodel.ReplicaReadOnlyFull

// ReplicaWritable is the SDK's ReplicaWritable.
const ReplicaWritable = admodel.ReplicaWritable

// RoleDomainNamingMaster is the SDK's RoleDomainNamingMaster.
const RoleDomainNamingMaster = admodel.RoleDomainNamingMaster

// RoleInfrastructureMaster is the SDK's RoleInfrastructureMaster.
const RoleInfrastructureMaster = admodel.RoleInfrastructureMaster

// RoleOwner preserves the role's DSA identity even when its host read fails.
// Holding a role does not establish availability of that server.
type RoleOwner = admodel.RoleOwner

// RolePDCEmulator is the SDK's RolePDCEmulator.
const RolePDCEmulator = admodel.RolePDCEmulator

// RoleRIDMaster is the SDK's RoleRIDMaster.
const RoleRIDMaster = admodel.RoleRIDMaster

// RoleSchemaMaster is the SDK's RoleSchemaMaster.
const RoleSchemaMaster = admodel.RoleSchemaMaster

// ServiceADWS is the SDK's ServiceADWS.
const ServiceADWS = admodel.ServiceADWS

// ServiceGlobalCatalog is the SDK's ServiceGlobalCatalog.
const ServiceGlobalCatalog = admodel.ServiceGlobalCatalog

// ServiceKDC is the SDK's ServiceKDC.
const ServiceKDC = admodel.ServiceKDC

// ServicePrimaryDC is the SDK's ServicePrimaryDC.
const ServicePrimaryDC = admodel.ServicePrimaryDC

// ServiceTime is the SDK's ServiceTime.
const ServiceTime = admodel.ServiceTime

// Trust is a trustedDomain object observed from its source partition. Direction
// and type retain unknown numeric values; AttributesMask retains unknown bits.
// SecurityIdentifier identifies the partner domain and is not objectSid.
type Trust = admodel.Trust

// TrustOptions adds raw attributes to the stable projection. "*" is explicit;
// default properties never include trust authentication secrets. As elsewhere,
// caller-requested raw properties may be sensitive and must not be logged.
type TrustOptions = admodel.TrustOptions

// TrustQuery is explicitly a domain/partition query, not a forest-wide traversal.
// BaseDN selects a container directly (including an LDS application partition).
// Otherwise DomainDN or the configured/default NC supplies wellKnownObjects to
// locate System. BaseDN and DomainDN are mutually exclusive. LDAPFilter uses
// LDAP syntax; PowerShell expressions and InputObject require shared resolvers.
type TrustQuery = admodel.TrustQuery

// TrustResult is the SDK's TrustResult.
type TrustResult = admodel.TrustResult

// TrustsResult is the SDK's TrustsResult.
type TrustsResult = admodel.TrustsResult
