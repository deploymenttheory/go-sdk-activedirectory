package model

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrReplicationTopology     = errors.New("invalid replication topology object or relationship")
	ErrReplicationSiteNotEmpty = errors.New(
		"site has server, subnet or unrecognized child relationships; remove or relocate them explicitly",
	)
	ErrInvalidReplicationSubnet = errors.New(
		"subnet must be a canonical IPv4 or IPv6 network prefix without host bits or a zone",
	)
	// ErrReplicationTopologyIncomplete reports that a site change stopped
	// after at least one of its object writes had already been accepted, so
	// the directory holds part of the change. It mirrors the creation-incomplete
	// sentinels the user, computer and service-account paths return, and exists
	// because the underlying failure alone does not say that anything landed:
	// a refused third write reports only the refusal, which reads as though the
	// whole change was rejected.
	ErrReplicationTopologyIncomplete = errors.New(
		"replication site change did not complete all stages; inspect step results before further writes",
	)
)

type ReplicationSiteOptions uint32

const (
	SiteDisableAutomaticTopology          ReplicationSiteOptions = 1
	SiteDisableTopologyCleanup            ReplicationSiteOptions = 2
	SiteDisableMinimumHops                ReplicationSiteOptions = 4
	SiteDisableStaleDetection             ReplicationSiteOptions = 8
	SiteDisableAutomaticIntersiteTopology ReplicationSiteOptions = 16
	SiteEnableUniversalGroupCaching       ReplicationSiteOptions = 32
	SiteForceWindows2003KCCBehavior       ReplicationSiteOptions = 64
	SiteForceWindows2000ISTGElection      ReplicationSiteOptions = 128
	SiteDisableRandomBridgeheadSelection  ReplicationSiteOptions = 256
	SiteEnableScheduleHashing             ReplicationSiteOptions = 512
	SiteEnableRedundantServerTopology     ReplicationSiteOptions = 1024
	SiteWindows2003IgnoreSchedules        ReplicationSiteOptions = 2048
	SiteWindows2003BridgesRequired        ReplicationSiteOptions = 4096
)

type ReplicationSiteSettings struct {
	Raw                                                          Object
	Options                                                      *ReplicationSiteOptions
	Schedule                                                     *ReplicationSchedule
	InterSiteTopologyGenerator, UniversalGroupCachingRefreshSite *string
}
type ReplicationSite struct {
	ForestSite
	GUID                   *GUID
	Description, ManagedBy *string
	Settings               *ReplicationSiteSettings
}
type ReplicationSiteResult struct {
	Site                             *ReplicationSite
	Observation, SettingsObservation IdentityResult
	Servers, Subnets                 SearchResult
	Complete                         bool
}
type ReplicationSitesResult struct {
	Sites       []ReplicationSiteResult
	Observation SearchResult
}
type ReplicationTopologyStep struct {
	Name     string
	Mutation ObjectMutationResult
	Error    error
}

// Stages are ordered, independent native writes. Complete never means atomic
// across objects; accepted earlier stages survive a later failure without rollback.
type ReplicationSiteMutationResult struct {
	Steps                        []ReplicationTopologyStep
	Preflight, SettingsPreflight IdentityResult
	Children, LinkedSubnets      SearchResult
	After                        ReplicationSiteResult
	Complete                     bool
}

func InternalTopologyClass(object Object, class string) error {
	values, state := object.Attribute("objectClass")
	if state != AttributePresent {
		return errors.Join(ErrReplicationTopology, ErrAttributeUnavailable)
	}
	for _, value := range values {
		if strings.EqualFold(string(value), class) {
			return nil
		}
	}
	return ErrReplicationTopology
}

func InternalTopologyGUID(object Object) (GUID, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, err
	}
	return value.GUID()
}

func InternalTopologyConfiguration(root RootDSE, config Config, partition string) (string, error) {
	if root.Capabilities().Type != DirectoryADDS && root.Capabilities().Type != DirectoryADLDS {
		return "", ErrUnsupportedDirectory
	}
	if root.ConfigurationNamingContext == nil {
		return "", ErrIncompleteResult
	}
	if partition == "" {
		partition = *root.ConfigurationNamingContext
	}
	a, err := InternalParseIdentityDN(partition)
	b, e := InternalParseIdentityDN(*root.ConfigurationNamingContext)
	if err != nil || e != nil || !InternalSameIdentityDN(a, b) {
		return "", ErrReplicationTopology
	}
	if root.Capabilities().Type == DirectoryADDS &&
		(config.Endpoint.Port == 3268 || config.Endpoint.Port == 3269) {
		return "", ErrObjectWriteTarget
	}
	return *root.ConfigurationNamingContext, nil
}

func InternalTopologyIdentity(identity Identity, options ResolveIdentityOptions) error {
	if options.Target != IdentityTargetObject ||
		(identity.Form() != IdentityFormDN && identity.Form() != IdentityFormGUID) {
		return ErrUnsupportedIdentity
	}
	return InternalValidateIdentityOperation(identity, options)
}

func InternalTopologyDirectChild(object Object, parent, class string) error {
	if err := InternalTopologyClass(object, class); err != nil {
		return err
	}
	dn, err := InternalParseIdentityDN(object.DistinguishedName)
	container, e := InternalParseIdentityDN(parent)
	if err != nil || e != nil || len(dn) != len(container)+1 ||
		!InternalSameIdentityDN(dn[1:], container) {
		return ErrReplicationTopology
	}
	return nil
}

func InternalTopologySiteProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"description",
		"managedBy",
	)
}

func InternalTopologySettingsProperties() []string {
	return []string{
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"options",
		"schedule",
		"interSiteTopologyGenerator",
		"msDS-Preferred-GC-Site",
	}
}

func InternalDecodeReplicationSite(object Object) (ReplicationSite, error) {
	result := ReplicationSite{ForestSite: ForestSite{Raw: object}}
	if err := InternalTopologyClass(object, "site"); err != nil {
		return result, err
	}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.Name = d.InternalText("name")
	result.Description = d.InternalText("description")
	result.ManagedBy = d.InternalText("managedBy")
	guid, err := InternalTopologyGUID(object)
	if err == nil {
		result.GUID = &guid
	}
	return result, errors.Join(err, errors.Join(d.InternalErrors...))
}

func InternalDecodeReplicationSiteSettings(object Object) (ReplicationSiteSettings, error) {
	result := ReplicationSiteSettings{Raw: object}
	if err := InternalTopologyClass(object, "nTDSSiteSettings"); err != nil {
		return result, err
	}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	if flags := InternalDecodeScalar(&d, "options", InternalParseDirectoryMask); flags != nil {
		value := ReplicationSiteOptions(*flags)
		result.Options = &value
	}
	result.InterSiteTopologyGenerator = d.InternalText("interSiteTopologyGenerator")
	result.UniversalGroupCachingRefreshSite = d.InternalText("msDS-Preferred-GC-Site")
	if _, state := object.Attribute("schedule"); state == AttributePresent {
		value, err := object.Values("schedule").Single()
		if err == nil {
			schedule, e := ReplicationScheduleFromBytes(value.Bytes())
			err = e
			if err == nil {
				result.Schedule = &schedule
			}
		}
		d.InternalErrors = append(d.InternalErrors, err)
	}
	return result, errors.Join(d.InternalErrors...)
}

func InternalReadReplicationSite(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
	identity Identity,
	options ResolveIdentityOptions,
) (ReplicationSiteResult, error) {
	var result ReplicationSiteResult
	configuration, err := InternalTopologyConfiguration(root, config, options.Partition)
	if err != nil {
		return result, err
	}
	options.Partition = configuration
	options.Properties = InternalTopologySiteProperties(options.Properties)
	result.Observation, err = InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		identity,
		options,
	)
	if err != nil {
		return result, err
	}
	object := *result.Observation.Object
	if err := InternalTopologyDirectChild(object, "CN=Sites,"+configuration, "site"); err != nil {
		return result, err
	}
	site, err := InternalDecodeReplicationSite(object)
	result.Site = &site
	if err != nil {
		return result, err
	}
	settingsIdentity, _ := IdentityByDN("CN=NTDS Site Settings," + object.DistinguishedName)
	result.SettingsObservation, err = InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		settingsIdentity,
		ResolveIdentityOptions{
			Partition:  configuration,
			Properties: InternalTopologySettingsProperties(),
		},
	)
	if result.SettingsObservation.Object != nil {
		settings, e := InternalDecodeReplicationSiteSettings(*result.SettingsObservation.Object)
		result.Site.Settings = &settings
		err = errors.Join(err, e)
	}
	var e error
	if context.Cause(ctx) != nil {
		return result, errors.Join(err, context.Cause(ctx))
	}
	result.Servers, e = InternalSearchIdentitySession(
		ctx,
		session,
		SearchOptions{
			Base:   "CN=Servers," + object.DistinguishedName,
			Scope:  ScopeOneLevel,
			Filter: "(objectClass=server)",
			Properties: []string{
				"objectGUID",
				"objectClass",
				"name",
				"dnsHostName",
				"serverReference",
			},
		},
	)
	err = errors.Join(err, e)
	if context.Cause(ctx) != nil {
		return result, errors.Join(err, context.Cause(ctx))
	}
	result.Subnets, e = InternalSearchIdentitySession(
		ctx,
		session,
		SearchOptions{
			Base:  "CN=Subnets,CN=Sites," + configuration,
			Scope: ScopeOneLevel,
			TypedFilter: FilterAnd(
				FilterEqual("objectClass", FilterText("subnet")),
				FilterEqual("siteObject", FilterText(object.DistinguishedName)),
			),
			Properties: InternalTopologySubnetProperties(nil),
		},
	)
	err = errors.Join(err, e)
	result.Complete = err == nil
	return result, err
}

func InternalTopologySearch(options SearchOptions, parent, class string) (SearchOptions, error) {
	if err := options.Validate(); err != nil {
		return options, err
	}
	if options.Base != "" {
		a, e := InternalParseIdentityDN(options.Base)
		b, _ := InternalParseIdentityDN(parent)
		if e != nil || !InternalSameIdentityDN(a, b) {
			return options, ErrReplicationTopology
		}
	}
	options.Base, options.Scope = parent, ScopeOneLevel
	classFilter := FilterEqual("objectClass", FilterText(class))
	if !InternalFilterUnset(options.TypedFilter) {
		options.TypedFilter = FilterAnd(classFilter, options.TypedFilter)
	} else if options.Filter != "" {
		options.Filter = "(&(objectClass=" + class + ")" + options.Filter + ")"
	} else {
		options.TypedFilter = classFilter
	}
	return options, nil
}
