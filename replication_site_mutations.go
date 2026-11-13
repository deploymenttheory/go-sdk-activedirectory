package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// SetOptions/ClearOptions change only selected documented bits, preserving
// unrecognized bits. Schedule is UTC; ClearSchedule explicitly requests removal.
type ReplicationSiteSettingsPatch struct {
	SetOptions, ClearOptions                                     ReplicationSiteOptions
	Schedule                                                     *ReplicationSchedule
	ClearSchedule                                                bool
	InterSiteTopologyGenerator, UniversalGroupCachingRefreshSite *Identity
}
type CreateReplicationSiteRequest struct {
	Name        string
	Description *string
	Settings    ReplicationSiteSettingsPatch
	Options     ObjectMutationOptions
}
type UpdateReplicationSiteRequest struct {
	Identity    Identity
	Description *string
	Changes     []AttributeChange
	Settings    *ReplicationSiteSettingsPatch
	Options     ObjectMutationOptions
	// The site and its NTDS Site Settings are different objects. A settings
	// precondition must identify the settings GUID/USN, not the site's version.
	SettingsExpectedVersion *ObjectVersion
}

func validateReplicationSiteSettings(patch ReplicationSiteSettingsPatch) error {
	if patch.SetOptions&patch.ClearOptions != 0 || (patch.SetOptions|patch.ClearOptions)&^ReplicationSiteOptions(0x1fff) != 0 || (patch.Schedule != nil && patch.ClearSchedule) {
		return ErrReplicationTopology
	}
	for _, identity := range []*Identity{patch.InterSiteTopologyGenerator, patch.UniversalGroupCachingRefreshSite} {
		if identity != nil {
			if err := topologyIdentity(*identity, ResolveIdentityOptions{}); err != nil {
				return err
			}
		}
	}
	return nil
}
func siteSettingsPatchPresent(patch ReplicationSiteSettingsPatch) bool {
	return patch.SetOptions|patch.ClearOptions != 0 || patch.Schedule != nil || patch.ClearSchedule || patch.InterSiteTopologyGenerator != nil || patch.UniversalGroupCachingRefreshSite != nil
}
func (c *Client) siteSettingsLinkChanges(ctx context.Context, patch ReplicationSiteSettingsPatch, root RootDSE, siteDN, configuration string) ([]AttributeChange, error) {
	if root.Capabilities().Type == DirectoryADLDS && ((patch.SetOptions&SiteEnableUniversalGroupCaching) != 0 || patch.UniversalGroupCachingRefreshSite != nil) {
		return nil, ErrUnsupportedDirectory
	}
	var changes []AttributeChange
	if patch.InterSiteTopologyGenerator != nil {
		observed, err := c.ResolveIdentity(ctx, *patch.InterSiteTopologyGenerator, ResolveIdentityOptions{Partition: configuration, Properties: []string{"objectGUID", "objectClass"}})
		if err != nil {
			return nil, err
		}
		if err := topologyClass(*observed.Object, "nTDSDSA"); err != nil {
			return nil, err
		}
		dn, err := parseIdentityDN(observed.Object.DistinguishedName)
		site, e := parseIdentityDN(siteDN)
		if err != nil || e != nil || len(dn) != len(site)+3 || !sameIdentityDN(dn[3:], site) {
			return nil, ErrReplicationTopology
		}
		value := observed.Object.DistinguishedName
		changes = append(changes, topologyTextChange("interSiteTopologyGenerator", &value)...)
	}
	if patch.UniversalGroupCachingRefreshSite != nil {
		observed, err := c.topologyLinkedSite(ctx, *patch.UniversalGroupCachingRefreshSite, configuration)
		if err != nil {
			return nil, err
		}
		value := observed.Object.DistinguishedName
		changes = append(changes, topologyTextChange("msDS-Preferred-GC-Site", &value)...)
	}
	return changes, nil
}
func replicationSiteSettingsMods(object Object, patch ReplicationSiteSettingsPatch, links []AttributeChange, create bool) ([]ldapAttributeModification, error) {
	changes := append([]AttributeChange{}, links...)
	if create || patch.SetOptions|patch.ClearOptions != 0 {
		var old uint32
		var oldRaw RawValue
		if !create {
			value, err := object.Values("options").Single()
			if err != nil {
				return nil, err
			}
			flags, err := value.Flags32()
			if err != nil {
				return nil, err
			}
			old = uint32(flags)
			oldRaw = value
		}
		next := (old | uint32(patch.SetOptions)) &^ uint32(patch.ClearOptions)
		text := strconv.FormatInt(int64(int32(next)), 10)
		if create {
			changes = append(changes, topologyTextChange("options", &text)...)
		} else if old != next {
			// Strict delete-old/add-new rejects concurrent option changes without
			// overwriting unknown bits observed in the original value.
			changes = append(changes, AttributeChange{Attribute: "options", Kind: AttributeRemoveValues, Values: []RawValue{oldRaw}}, AttributeChange{Attribute: "options", Kind: AttributeAddValues, Values: []RawValue{NewRawValue([]byte(text))}})
		}
	}
	if patch.Schedule != nil {
		changes = append(changes, AttributeChange{Attribute: "schedule", Kind: AttributeSet, Values: []RawValue{NewRawValue(patch.Schedule.Bytes())}})
	} else if patch.ClearSchedule {
		changes = append(changes, AttributeChange{Attribute: "schedule", Kind: AttributeClear})
	}
	if len(changes) == 0 {
		return nil, nil
	}
	return objectChanges(changes)
}
func (c *Client) CreateReplicationSite(ctx context.Context, request CreateReplicationSiteRequest) (ReplicationSiteMutationResult, error) {
	var result ReplicationSiteMutationResult
	if request.Name == "" || !validDirectoryText(request.Name) || (request.Description != nil && !validDirectoryText(*request.Description)) {
		return result, ErrReplicationTopology
	}
	if err := validateReplicationSiteSettings(request.Settings); err != nil {
		return result, err
	}
	if request.Settings.InterSiteTopologyGenerator != nil || request.Settings.ClearSchedule {
		return result, ErrReplicationTopology
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	ctx, cancel, err := topologyMutationContext(ctx, c)
	if err != nil {
		return result, err
	}
	defer cancel()
	root, options, err := c.topologyMutationRoot(ctx, request.Options)
	if err != nil {
		return result, err
	}
	links, err := c.siteSettingsLinkChanges(ctx, request.Settings, root, "", options.Partition)
	if err != nil {
		return result, err
	}
	settingsMods, err := replicationSiteSettingsMods(Object{}, request.Settings, links, true)
	if err != nil {
		return result, err
	}
	parent, _ := IdentityByDN("CN=Sites," + options.Partition)
	attrs := map[string][]RawValue{}
	if request.Description != nil {
		attrs["description"] = []RawValue{NewRawValue([]byte(*request.Description))}
	}
	options.Properties = topologySiteProperties(options.Properties)
	mutation, err := c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: "site", Name: request.Name, Attributes: attrs, Options: options})
	if err := topologyStep(&result, "site", mutation, err); err != nil {
		return result, err
	}
	parent = objectGUIDIdentity(*mutation.TargetGUID)
	settingsAttrs := map[string][]RawValue{}
	for _, mod := range settingsMods {
		for _, value := range mod.values {
			settingsAttrs[mod.attribute] = append(settingsAttrs[mod.attribute], NewRawValue(value))
		}
	}
	children := []struct {
		name, class string
		attrs       map[string][]RawValue
	}{{"NTDS Site Settings", "nTDSSiteSettings", settingsAttrs}, {"Servers", "serversContainer", nil}}
	if root.Capabilities().Type == DirectoryADDS {
		children = append(children, struct {
			name, class string
			attrs       map[string][]RawValue
		}{"Licensing Site Settings", "licensingSiteSettings", nil})
	}
	for _, child := range children {
		childOptions := ObjectMutationOptions{Partition: options.Partition}
		step, e := c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Name: child.name, Class: child.class, Attributes: child.attrs, Options: childOptions})
		if e := topologyStep(&result, child.name, step, e); e != nil {
			return result, e
		}
	}
	result.After, err = c.ReplicationSite(ctx, parent, ResolveIdentityOptions{Partition: options.Partition, Properties: request.Options.Properties})
	result.Complete = err == nil
	return result, topologyAfterMutationError(mutation, err)
}
func (c *Client) UpdateReplicationSite(ctx context.Context, request UpdateReplicationSiteRequest) (ReplicationSiteMutationResult, error) {
	var result ReplicationSiteMutationResult
	if err := topologyMutationInput(request.Identity, request.Options); err != nil {
		return result, err
	}
	if request.Description != nil && !validDirectoryText(*request.Description) {
		return result, ErrInvalidValue
	}
	if request.Settings != nil {
		if err := validateReplicationSiteSettings(*request.Settings); err != nil {
			return result, err
		}
	}
	if len(request.Changes) > 0 {
		if _, err := topologyValidateChanges(request.Changes, []string{"cn", "options", "schedule", "interSiteTopologyGenerator", "msDS-Preferred-GC-Site"}); err != nil {
			return result, err
		}
	}
	changes := append(topologyTextChange("description", request.Description), request.Changes...)
	var mods []ldapAttributeModification
	var err error
	if len(changes) > 0 {
		mods, err = objectChanges(changes)
		if err != nil {
			return result, err
		}
	}
	settingsChange := request.Settings != nil && siteSettingsPatchPresent(*request.Settings)
	if (len(mods) == 0 && request.Options.ExpectedVersion != nil) || (!settingsChange && request.SettingsExpectedVersion != nil) {
		return result, ErrObjectControlUnsupported
	}
	if len(mods) == 0 && !settingsChange {
		return result, ErrInvalidObjectMutation
	}
	ctx, cancel, err := topologyMutationContext(ctx, c)
	if err != nil {
		return result, err
	}
	defer cancel()
	root, options, err := c.topologyMutationRoot(ctx, request.Options)
	if err != nil {
		return result, err
	}
	before, err := c.topologyLinkedSite(ctx, request.Identity, options.Partition)
	result.Preflight = before
	if err != nil {
		return result, err
	}
	siteDN := before.Object.DistinguishedName
	var settingsIdentity Identity
	var links []AttributeChange
	if settingsChange {
		links, err = c.siteSettingsLinkChanges(ctx, *request.Settings, root, siteDN, options.Partition)
		if err != nil {
			return result, err
		}
		settingsIdentity, _ = IdentityByDN("CN=NTDS Site Settings," + siteDN)
		// Validate the second object and expected-version capability before any
		// first-stage write. Each server request still enforces its own assertion.
		settings, err := c.ResolveIdentity(ctx, settingsIdentity, ResolveIdentityOptions{Partition: options.Partition, Properties: topologySettingsProperties()})
		result.SettingsPreflight = settings
		if err != nil {
			return result, err
		}
		if err := topologyDirectChild(*settings.Object, siteDN, "nTDSSiteSettings"); err != nil {
			return result, err
		}
		guid, err := topologyGUID(*settings.Object)
		if err != nil {
			return result, err
		}
		settingsIdentity = objectGUIDIdentity(guid)
		planned, err := replicationSiteSettingsMods(*settings.Object, *request.Settings, links, false)
		if err != nil {
			return result, err
		}
		if len(planned) == 0 && request.SettingsExpectedVersion != nil {
			return result, ErrObjectControlUnsupported
		}
		if _, err := objectWriteControls(root, c.config.Endpoint, ObjectMutationOptions{ExpectedVersion: request.SettingsExpectedVersion}, guid, false); err != nil {
			return result, err
		}
	}
	if len(mods) > 0 {
		step, e := c.topologyModify(ctx, request.Identity, options, "CN=Sites,"+options.Partition, "site", topologySiteProperties(nil), func(Object) ([]ldapAttributeModification, error) { return mods, nil })
		if e := topologyStep(&result, "site", step, e); e != nil {
			return result, e
		}
	}
	if settingsChange {
		settingsOptions := ObjectMutationOptions{Partition: options.Partition, ExpectedVersion: request.SettingsExpectedVersion}
		step, e := c.topologyModify(ctx, settingsIdentity, settingsOptions, siteDN, "nTDSSiteSettings", topologySettingsProperties(), func(object Object) ([]ldapAttributeModification, error) {
			return replicationSiteSettingsMods(object, *request.Settings, links, false)
		})
		if e := topologyStep(&result, "NTDS Site Settings", step, e); e != nil {
			return result, e
		}
	}
	result.After, err = c.ReplicationSite(ctx, request.Identity, ResolveIdentityOptions{Partition: options.Partition, Properties: request.Options.Properties})
	result.Complete = err == nil
	if err != nil {
		return result, errors.Join(ErrObjectReadback, err)
	}
	return result, nil
}

// DeleteReplicationSite refuses servers, linked subnets and unrecognized
// descendants. Only recognized administrative children are deleted, by separate
// leaf deletes, then the site. New children cause native non-leaf rejection.
func (c *Client) DeleteReplicationSite(ctx context.Context, identity Identity, options ObjectMutationOptions) (ReplicationSiteMutationResult, error) {
	var result ReplicationSiteMutationResult
	if err := topologyMutationInput(identity, options); err != nil {
		return result, err
	}
	if options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	ctx, cancel, err := topologyMutationContext(ctx, c)
	if err != nil {
		return result, err
	}
	defer cancel()
	_, options, err = c.topologyMutationRoot(ctx, options)
	if err != nil {
		return result, err
	}
	site, err := c.topologyLinkedSite(ctx, identity, options.Partition)
	result.Preflight = site
	if err != nil {
		return result, err
	}
	dn := site.Object.DistinguishedName
	children, err := c.Search(ctx, SearchOptions{Base: dn, Scope: ScopeSubtree, Properties: []string{"objectGUID", "objectClass", "name"}})
	result.Children = children
	if err != nil {
		return result, err
	}
	links, err := c.Search(ctx, SearchOptions{Base: "CN=Subnets,CN=Sites," + options.Partition, Scope: ScopeOneLevel, TypedFilter: FilterEqual("siteObject", FilterText(dn)), Properties: []string{"objectGUID"}})
	result.LinkedSubnets = links
	if err != nil {
		return result, err
	}
	if len(links.Objects) > 0 {
		return result, ErrReplicationSiteNotEmpty
	}
	type childEntry struct {
		object Object
		class  string
	}
	var removable []childEntry
	for _, object := range children.Objects {
		if strings.EqualFold(object.DistinguishedName, dn) {
			continue
		}
		class := ""
		for _, candidate := range []struct{ name, class string }{{"NTDS Site Settings", "nTDSSiteSettings"}, {"Servers", "serversContainer"}, {"Licensing Site Settings", "licensingSiteSettings"}} {
			if strings.EqualFold(object.DistinguishedName, "CN="+candidate.name+","+dn) && topologyDirectChild(object, dn, candidate.class) == nil {
				class = candidate.class
				break
			}
		}
		if class == "" {
			return result, ErrReplicationSiteNotEmpty
		}
		if _, err := topologyGUID(object); err != nil {
			return result, err
		}
		removable = append(removable, childEntry{object, class})
	}
	// A hidden/concurrently added server must make the Servers leaf delete fail
	// before any site settings are removed. Never rely on query visibility alone.
	slices.SortFunc(removable, func(a, b childEntry) int {
		if a.class == "serversContainer" && b.class != "serversContainer" {
			return -1
		}
		if b.class == "serversContainer" && a.class != "serversContainer" {
			return 1
		}
		return strings.Compare(a.object.DistinguishedName, b.object.DistinguishedName)
	})
	for _, child := range removable {
		guid, _ := topologyGUID(child.object)
		step, e := c.topologyDelete(ctx, objectGUIDIdentity(guid), ObjectMutationOptions{Partition: options.Partition}, dn, child.class)
		if e := topologyStep(&result, child.object.DistinguishedName, step, e); e != nil {
			return result, e
		}
	}
	guid, err := topologyGUID(*site.Object)
	if err != nil {
		return result, err
	}
	step, err := c.topologyDelete(ctx, objectGUIDIdentity(guid), options, "CN=Sites,"+options.Partition, "site")
	_ = topologyStep(&result, "site", step, err)
	result.Complete = err == nil
	return result, err
}
