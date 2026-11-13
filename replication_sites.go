package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrReplicationTopology      = errors.New("invalid replication topology object or relationship")
	ErrReplicationSiteNotEmpty  = errors.New("site has server, subnet or unrecognized child relationships; remove or relocate them explicitly")
	ErrInvalidReplicationSubnet = errors.New("subnet must be a canonical IPv4 or IPv6 network prefix without host bits or a zone")
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

func topologyClass(object Object, class string) error {
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
func topologyGUID(object Object) (GUID, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, err
	}
	return value.GUID()
}
func topologyConfiguration(root RootDSE, config Config, partition string) (string, error) {
	if root.Capabilities().Type != DirectoryADDS && root.Capabilities().Type != DirectoryADLDS {
		return "", ErrUnsupportedDirectory
	}
	if root.ConfigurationNamingContext == nil {
		return "", ErrIncompleteResult
	}
	if partition == "" {
		partition = *root.ConfigurationNamingContext
	}
	a, err := parseIdentityDN(partition)
	b, e := parseIdentityDN(*root.ConfigurationNamingContext)
	if err != nil || e != nil || !sameIdentityDN(a, b) {
		return "", ErrReplicationTopology
	}
	if root.Capabilities().Type == DirectoryADDS && (config.Endpoint.Port == 3268 || config.Endpoint.Port == 3269) {
		return "", ErrObjectWriteTarget
	}
	return *root.ConfigurationNamingContext, nil
}
func topologyIdentity(identity Identity, options ResolveIdentityOptions) error {
	if options.Target != IdentityTargetObject || (identity.Form() != IdentityFormDN && identity.Form() != IdentityFormGUID) {
		return ErrUnsupportedIdentity
	}
	return validateIdentityOperation(identity, options)
}
func topologyDirectChild(object Object, parent, class string) error {
	if err := topologyClass(object, class); err != nil {
		return err
	}
	dn, err := parseIdentityDN(object.DistinguishedName)
	container, e := parseIdentityDN(parent)
	if err != nil || e != nil || len(dn) != len(container)+1 || !sameIdentityDN(dn[1:], container) {
		return ErrReplicationTopology
	}
	return nil
}
func topologySiteProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectGUID", "uSNChanged", "objectClass", "name", "description", "managedBy")
}
func topologySettingsProperties() []string {
	return []string{"objectGUID", "uSNChanged", "objectClass", "options", "schedule", "interSiteTopologyGenerator", "msDS-Preferred-GC-Site"}
}
func decodeReplicationSite(object Object) (ReplicationSite, error) {
	result := ReplicationSite{ForestSite: ForestSite{Raw: object}}
	if err := topologyClass(object, "site"); err != nil {
		return result, err
	}
	d := rootDSEDecoder{attributes: object.Attributes}
	result.Name = d.text("name")
	result.Description = d.text("description")
	result.ManagedBy = d.text("managedBy")
	guid, err := topologyGUID(object)
	if err == nil {
		result.GUID = &guid
	}
	return result, errors.Join(err, errors.Join(d.errors...))
}
func decodeReplicationSiteSettings(object Object) (ReplicationSiteSettings, error) {
	result := ReplicationSiteSettings{Raw: object}
	if err := topologyClass(object, "nTDSSiteSettings"); err != nil {
		return result, err
	}
	d := rootDSEDecoder{attributes: object.Attributes}
	if flags := decodeScalar(&d, "options", parseDirectoryMask); flags != nil {
		value := ReplicationSiteOptions(*flags)
		result.Options = &value
	}
	result.InterSiteTopologyGenerator = d.text("interSiteTopologyGenerator")
	result.UniversalGroupCachingRefreshSite = d.text("msDS-Preferred-GC-Site")
	if _, state := object.Attribute("schedule"); state == AttributePresent {
		value, err := object.Values("schedule").Single()
		if err == nil {
			schedule, e := ReplicationScheduleFromBytes(value.Bytes())
			err = e
			if err == nil {
				result.Schedule = &schedule
			}
		}
		d.errors = append(d.errors, err)
	}
	return result, errors.Join(d.errors...)
}
func readReplicationSite(ctx context.Context, session directorySession, config Config, root RootDSE, identity Identity, options ResolveIdentityOptions) (ReplicationSiteResult, error) {
	var result ReplicationSiteResult
	configuration, err := topologyConfiguration(root, config, options.Partition)
	if err != nil {
		return result, err
	}
	options.Partition = configuration
	options.Properties = topologySiteProperties(options.Properties)
	result.Observation, err = resolveIdentitySession(ctx, session, config, root, identity, options)
	if err != nil {
		return result, err
	}
	object := *result.Observation.Object
	if err := topologyDirectChild(object, "CN=Sites,"+configuration, "site"); err != nil {
		return result, err
	}
	site, err := decodeReplicationSite(object)
	result.Site = &site
	if err != nil {
		return result, err
	}
	settingsIdentity, _ := IdentityByDN("CN=NTDS Site Settings," + object.DistinguishedName)
	result.SettingsObservation, err = resolveIdentitySession(ctx, session, config, root, settingsIdentity, ResolveIdentityOptions{Partition: configuration, Properties: topologySettingsProperties()})
	if result.SettingsObservation.Object != nil {
		settings, e := decodeReplicationSiteSettings(*result.SettingsObservation.Object)
		result.Site.Settings = &settings
		err = errors.Join(err, e)
	}
	var e error
	if context.Cause(ctx) != nil {
		return result, errors.Join(err, context.Cause(ctx))
	}
	result.Servers, e = searchIdentitySession(ctx, session, SearchOptions{Base: "CN=Servers," + object.DistinguishedName, Scope: ScopeOneLevel, Filter: "(objectClass=server)", Properties: []string{"objectGUID", "objectClass", "name", "dnsHostName", "serverReference"}})
	err = errors.Join(err, e)
	if context.Cause(ctx) != nil {
		return result, errors.Join(err, context.Cause(ctx))
	}
	result.Subnets, e = searchIdentitySession(ctx, session, SearchOptions{Base: "CN=Subnets,CN=Sites," + configuration, Scope: ScopeOneLevel, TypedFilter: FilterAnd(FilterEqual("objectClass", FilterText("subnet")), FilterEqual("siteObject", FilterText(object.DistinguishedName))), Properties: topologySubnetProperties(nil)})
	err = errors.Join(err, e)
	result.Complete = err == nil
	return result, err
}
func (c *Client) ReplicationSite(ctx context.Context, identity Identity, options ResolveIdentityOptions) (ReplicationSiteResult, error) {
	var result ReplicationSiteResult
	if err := topologyIdentity(identity, options); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		result, err = readReplicationSite(ctx, c.session, c.config, root, identity, options)
		return err
	})
	result.Complete = result.Complete && err == nil
	return result, err
}
func topologySearch(options SearchOptions, parent, class string) (SearchOptions, error) {
	if err := options.Validate(); err != nil {
		return options, err
	}
	if options.Base != "" {
		a, e := parseIdentityDN(options.Base)
		b, _ := parseIdentityDN(parent)
		if e != nil || !sameIdentityDN(a, b) {
			return options, ErrReplicationTopology
		}
	}
	options.Base, options.Scope = parent, ScopeOneLevel
	classFilter := FilterEqual("objectClass", FilterText(class))
	if !options.TypedFilter.unset() {
		options.TypedFilter = FilterAnd(classFilter, options.TypedFilter)
	} else if options.Filter != "" {
		options.Filter = "(&(objectClass=" + class + ")" + options.Filter + ")"
	} else {
		options.TypedFilter = classFilter
	}
	return options, nil
}
func (c *Client) ReplicationSites(ctx context.Context, options SearchOptions) (ReplicationSitesResult, error) {
	var result ReplicationSitesResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err := topologyConfiguration(root, c.config, "")
		if err != nil {
			return err
		}
		query, err := topologySearch(options, "CN=Sites,"+configuration, "site")
		if err != nil {
			return err
		}
		query.Properties = topologySiteProperties(options.Properties)
		result.Observation, err = searchIdentitySession(ctx, c.session, query)
		for _, object := range result.Observation.Objects {
			entry := ReplicationSiteResult{Observation: IdentityResult{Object: &object, Candidates: []Object{object}, Partition: configuration, Complete: true}}
			site, e := decodeReplicationSite(object)
			entry.Site = &site
			err = errors.Join(err, e, topologyDirectChild(object, query.Base, "site"))
			result.Sites = append(result.Sites, entry)
		}
		// Listing returns only site-object projections; ReplicationSite reads the
		// settings and complete server/subnet associations on demand.
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}
