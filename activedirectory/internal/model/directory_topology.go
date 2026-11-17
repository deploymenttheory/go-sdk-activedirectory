package model

// DomainOptions selects an explicit domain NC or the configured/default NC.
// Other identity forms will use the shared identity resolver when available.
type DomainOptions struct{ DistinguishedName string }

// RoleOwner preserves the role's DSA identity even when its host read fails.
// Holding a role does not establish availability of that server.
type RoleOwner struct {
	NTDSSettingsDN string
	ServerDN       string
	HostName       *string
}

// CrossReference retains flags and enabled state without guessing the intent of
// disabled or external references. Linked names are distinguished names.
type CrossReference struct {
	Raw           Object
	NamingContext *string
	DNSRoot       *string
	NetBIOSName   *string
	SystemFlags   *uint32
	Enabled       *bool
	TrustParent   *string
	RootTrust     *string
}

type Domain struct {
	Observation                      DirectoryObservation
	Raw                              Object
	ObjectGUID                       []byte
	ObjectSID                        []byte
	Name                             *string
	DNSRoot                          *string
	NetBIOSName                      *string
	ForestDNSRoot                    *string
	FunctionalLevel                  *uint32
	AllowedDNSSuffixes               []string
	LogonTimeSyncInterval            *uint32
	ManagedBy                        *string
	PublicKeyRequiredPasswordRolling *bool
	GroupPolicyLinks                 *string
	SubordinateReferences            []string
	WellKnownContainers              map[string]string
	CrossReference                   *CrossReference
	Parent                           *CrossReference
	Children                         []CrossReference
	PDCEmulator                      *RoleOwner
	RIDMaster                        *RoleOwner
	InfrastructureMaster             *RoleOwner
	Replicas                         []ControllerReplica
}

func InternalDomainAttributes() []string {
	return []string{
		"objectGUID",
		"objectSid",
		"name",
		"msDS-Behavior-Version",
		"msDS-AllowedDNSSuffixes",
		"msDS-LogonTimeSyncInterval",
		"managedBy",
		"msDS-ExpirePasswordsOnSmartCardOnlyAccounts",
		"gpLink",
		"subRefs",
		"wellKnownObjects",
		"rIDManagerReference",
		"fSMORoleOwner",
	}
}

func InternalCrossReferenceAttributes() []string {
	return []string{
		"objectGUID",
		"nCName",
		"dnsRoot",
		"nETBIOSName",
		"systemFlags",
		"enabled",
		"trustParent",
		"rootTrust",
	}
}

type ForestSite struct {
	Raw  Object
	Name *string
}

// Forest classifies cross-references by their raw systemFlags. Disabled entries
// remain visible with Enabled state; these lists are directory observations,
// not a promise that every naming context is online or reachable.
type Forest struct {
	Observation           DirectoryObservation
	RootDomainDN          *string
	Name                  *string
	FunctionalLevel       *uint32
	UPNSuffixes           []string
	SPNSuffixes           []string
	CrossReferences       []CrossReference
	Domains               []CrossReference
	ApplicationPartitions []CrossReference
	ExternalReferences    []CrossReference
	Sites                 []ForestSite
	GlobalCatalogs        []ControllerReplica
	DomainNamingMaster    *RoleOwner
	SchemaMaster          *RoleOwner
}
