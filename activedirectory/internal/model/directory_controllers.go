package model

// ControllerReplica separates configured GC state from the live endpoint's GC
// readiness. ReadOnly is nil when the category cannot be determined.
type ControllerReplica struct {
	Settings        Object
	Server          Object
	HostName        *string
	DomainDN        *string
	IsReadOnly      *bool
	IsGlobalCatalog *bool
	Functionality   *uint32
}

type ReplicaKind uint8

const (
	ReplicaWritable ReplicaKind = iota + 1
	ReplicaReadOnlyFull
	ReplicaPartial
)

type ReplicaNamingContext struct {
	DistinguishedName string
	Kind              ReplicaKind
}

type FSMORole string

const (
	RolePDCEmulator          FSMORole = "PDCEmulator"
	RoleRIDMaster            FSMORole = "RIDMaster"
	RoleInfrastructureMaster FSMORole = "InfrastructureMaster"
	RoleSchemaMaster         FSMORole = "SchemaMaster"
	RoleDomainNamingMaster   FSMORole = "DomainNamingMaster"
)

type DomainController struct {
	ControllerReplica
	Computer                   Object
	Site                       Object
	SiteName                   *string
	ServerObjectGUID           []byte
	NTDSSettingsObjectGUID     []byte
	InvocationID               []byte
	ComputerObjectSID          []byte
	ComputerAccountName        *string
	Enabled                    *bool
	OperatingSystem            *string
	OperatingSystemVersion     *string
	OperatingSystemServicePack *string
	OperatingSystemHotfix      *string
	Options                    *uint32
	NamingContexts             []ReplicaNamingContext
	Partitions                 []string
	OperationMasterRoles       []FSMORole
	OperationMasterRolesKnown  bool
	// Only populated for the connected endpoint's own DSA.
	GlobalCatalogReady *bool
}

type DomainControllerResult struct {
	Observation DirectoryObservation
	Controller  DomainController
}
type DomainControllersResult struct {
	Observation  DirectoryObservation
	Controllers  []DomainController
	LimitReached bool
}

// DomainControllerOptions selects a server object's DN. Empty selects the
// authenticated endpoint's serverName. Host/IP/GUID/computer/DSA identities need
// the shared identity resolver and are deliberately not guessed from strings.
type DomainControllerOptions struct{ ServerDN string }

// DomainControllersQuery offers explicit joined criteria. It is not the
// PowerShell Filter language. General expressions will use the shared compiler.
// DomainDN defaults to the configured/default NC; Sites spans a forest, so the
// query always constrains msDS-HasDomainNCs as well as any site selection.
type DomainControllersQuery struct {
	DomainDN        string
	SiteDN          string
	IsGlobalCatalog *bool
	IsReadOnly      *bool
	PageSize        int
	ResultLimit     int
}

func InternalServerAttributes() []string {
	return []string{"objectGUID", "dnsHostName", "serverReference"}
}

func InternalDsaAttributes() []string {
	return []string{
		"objectGUID",
		"invocationId",
		"objectCategory",
		"options",
		"msDS-Behavior-Version",
		"msDS-HasDomainNCs",
		"msDS-hasMasterNCs",
		"msDS-hasFullReplicaNCs",
		"hasPartialReplicaNCs",
	}
}
