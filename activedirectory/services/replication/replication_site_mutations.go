package replication

import (
	"context"
	"errors"
	"slices"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// internalServiceSiteSettingsLinkChanges resolves site-settings references and builds their attribute
// modifications.
func internalServiceSiteSettingsLinkChanges(c *Service,
	ctx context.Context,
	patch admodel.ReplicationSiteSettingsPatch,
	root admodel.RootDSE,
	siteDN, configuration string,
) ([]admodel.AttributeChange, error) {
	if root.Capabilities().Type == admodel.DirectoryADLDS &&
		((patch.SetOptions&admodel.SiteEnableUniversalGroupCaching) != 0 || patch.UniversalGroupCachingRefreshSite != nil) {
		return nil, admodel.ErrUnsupportedDirectory
	}
	var changes []admodel.AttributeChange
	if patch.InterSiteTopologyGenerator != nil {
		observed, err := c.engine().
			ResolveIdentity(ctx, *patch.InterSiteTopologyGenerator, admodel.ResolveIdentityOptions{Partition: configuration, Properties: []string{"objectGUID", "objectClass"}})
		if err != nil {
			return nil, err
		}
		if err := admodel.InternalTopologyClass(*observed.Object, "nTDSDSA"); err != nil {
			return nil, err
		}
		dn, err := admodel.InternalParseIdentityDN(observed.Object.DistinguishedName)
		site, e := admodel.InternalParseIdentityDN(siteDN)
		if err != nil || e != nil || len(dn) != len(site)+3 ||
			!admodel.InternalSameIdentityDN(dn[3:], site) {
			return nil, admodel.ErrReplicationTopology
		}
		value := observed.Object.DistinguishedName
		changes = append(
			changes,
			admodel.InternalTopologyTextChange("interSiteTopologyGenerator", &value)...)
	}
	if patch.UniversalGroupCachingRefreshSite != nil {
		observed, err := internalServiceTopologyLinkedSite(c,
			ctx,
			*patch.UniversalGroupCachingRefreshSite,
			configuration,
		)
		if err != nil {
			return nil, err
		}
		value := observed.Object.DistinguishedName
		changes = append(
			changes,
			admodel.InternalTopologyTextChange("msDS-Preferred-GC-Site", &value)...)
	}
	return changes, nil
}

// CreateReplicationSite creates a site and its required child objects, applying the requested topology
// settings. These are separate writes; inspect the stage outcomes when creation is only partially
// accepted.
//
// Related cmdlet: New-ADReplicationSite.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adreplicationsite?view=windowsserver2025-ps
func (c *Service) CreateReplicationSite(
	ctx context.Context,
	request CreateReplicationSiteRequest,
) (result ReplicationSiteMutationResult, err error) {
	defer func() { err = admodel.InternalTopologyIncompleteError(result, err) }()
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) ||
		(request.Description != nil && !admodel.InternalValidDirectoryText(*request.Description)) {
		return result, admodel.ErrReplicationTopology
	}
	if err := admodel.InternalValidateReplicationSiteSettings(request.Settings); err != nil {
		return result, err
	}
	if request.Settings.InterSiteTopologyGenerator != nil || request.Settings.ClearSchedule {
		return result, admodel.ErrReplicationTopology
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return result, err
	}
	defer cancel()
	root, options, err := internalServiceTopologyMutationRoot(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	links, err := internalServiceSiteSettingsLinkChanges(c,
		ctx,
		request.Settings,
		root,
		"",
		options.Partition,
	)
	if err != nil {
		return result, err
	}
	settingsMods, err := admodel.InternalReplicationSiteSettingsMods(
		admodel.Object{},
		request.Settings,
		links,
		true,
	)
	if err != nil {
		return result, err
	}
	parent, _ := admodel.IdentityByDN("CN=Sites," + options.Partition)
	attrs := map[string][]admodel.RawValue{}
	if request.Description != nil {
		attrs["description"] = []admodel.RawValue{admodel.NewRawValue([]byte(*request.Description))}
	}
	options.Properties = admodel.InternalTopologySiteProperties(options.Properties)
	mutation, err := c.engine().
		CreateObject(ctx, admodel.CreateObjectRequest{Parent: parent, Class: "site", Name: request.Name, Attributes: attrs, Options: options})
	if err := admodel.InternalTopologyStep(&result, "site", mutation, err); err != nil {
		return result, err
	}
	parent = admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID)
	settingsAttrs := map[string][]admodel.RawValue{}
	for _, mod := range settingsMods {
		for _, value := range mod.InternalValues {
			settingsAttrs[mod.InternalAttribute] = append(
				settingsAttrs[mod.InternalAttribute],
				admodel.NewRawValue(value),
			)
		}
	}
	children := []struct {
		InternalName, InternalClass string
		InternalAttrs               map[string][]admodel.RawValue
	}{{"NTDS Site Settings", "nTDSSiteSettings", settingsAttrs}, {"Servers", "serversContainer", nil}}
	if root.Capabilities().Type == admodel.DirectoryADDS {
		children = append(children, struct {
			InternalName, InternalClass string
			InternalAttrs               map[string][]admodel.RawValue
		}{"Licensing Site Settings", "licensingSiteSettings", nil})
	}
	for _, child := range children {
		childOptions := admodel.ObjectMutationOptions{Partition: options.Partition}
		step, e := c.engine().
			CreateObject(ctx, admodel.CreateObjectRequest{
				Parent:     parent,
				Name:       child.InternalName,
				Class:      child.InternalClass,
				Attributes: child.InternalAttrs,
				Options:    childOptions,
			})
		if e := admodel.InternalTopologyStep(&result, child.InternalName, step, e); e != nil {
			return result, e
		}
	}
	result.After, err = c.ReplicationSite(
		ctx,
		parent,
		admodel.ResolveIdentityOptions{
			Partition:  options.Partition,
			Properties: request.Options.Properties,
		},
	)
	result.Complete = err == nil
	return result, admodel.InternalTopologyAfterMutationError(mutation, err)
}

// UpdateReplicationSite changes a site's attributes and optional topology settings. Site and settings
// writes have separate outcomes; accepted stages are retained if a later stage fails.
//
// Related cmdlet: Set-ADReplicationSite.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adreplicationsite?view=windowsserver2025-ps
func (c *Service) UpdateReplicationSite(
	ctx context.Context,
	request UpdateReplicationSiteRequest,
) (result ReplicationSiteMutationResult, err error) {
	defer func() { err = admodel.InternalTopologyIncompleteError(result, err) }()
	if err := admodel.InternalTopologyMutationInput(request.Identity, request.Options); err != nil {
		return result, err
	}
	if request.Description != nil && !admodel.InternalValidDirectoryText(*request.Description) {
		return result, admodel.ErrInvalidValue
	}
	if request.Settings != nil {
		if err := admodel.InternalValidateReplicationSiteSettings(*request.Settings); err != nil {
			return result, err
		}
	}
	if len(request.Changes) > 0 {
		if _, err := admodel.InternalTopologyValidateChanges(
			request.Changes,
			[]string{
				"cn",
				"options",
				"schedule",
				"interSiteTopologyGenerator",
				"msDS-Preferred-GC-Site",
			},
		); err != nil {
			return result, err
		}
	}
	changes := append(
		admodel.InternalTopologyTextChange("description", request.Description),
		request.Changes...)
	var mods []admodel.InternalLdapAttributeModification
	if len(changes) > 0 {
		mods, err = admodel.InternalObjectChanges(changes)
		if err != nil {
			return result, err
		}
	}
	settingsChange := request.Settings != nil &&
		admodel.InternalSiteSettingsPatchPresent(*request.Settings)
	if (len(mods) == 0 && request.Options.ExpectedVersion != nil) ||
		(!settingsChange && request.SettingsExpectedVersion != nil) {
		return result, admodel.ErrObjectControlUnsupported
	}
	if len(mods) == 0 && !settingsChange {
		return result, admodel.ErrInvalidObjectMutation
	}
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return result, err
	}
	defer cancel()
	root, options, err := internalServiceTopologyMutationRoot(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	before, err := internalServiceTopologyLinkedSite(c, ctx, request.Identity, options.Partition)
	result.Preflight = before
	if err != nil {
		return result, err
	}
	siteDN := before.Object.DistinguishedName
	var settingsIdentity admodel.Identity
	var links []admodel.AttributeChange
	if settingsChange {
		links, err = internalServiceSiteSettingsLinkChanges(c,
			ctx,
			*request.Settings,
			root,
			siteDN,
			options.Partition,
		)
		if err != nil {
			return result, err
		}
		settingsIdentity, _ = admodel.IdentityByDN("CN=NTDS Site Settings," + siteDN)
		// Validate the second object and expected-version capability before any
		// first-stage write. Each server request still enforces its own assertion.
		settings, err := c.engine().
			ResolveIdentity(ctx, settingsIdentity, admodel.ResolveIdentityOptions{Partition: options.Partition, Properties: admodel.InternalTopologySettingsProperties()})
		result.SettingsPreflight = settings
		if err != nil {
			return result, err
		}
		if err := admodel.InternalTopologyDirectChild(
			*settings.Object,
			siteDN,
			"nTDSSiteSettings",
		); err != nil {
			return result, err
		}
		guid, err := admodel.InternalTopologyGUID(*settings.Object)
		if err != nil {
			return result, err
		}
		settingsIdentity = admodel.InternalObjectGUIDIdentity(guid)
		planned, err := admodel.InternalReplicationSiteSettingsMods(
			*settings.Object,
			*request.Settings,
			links,
			false,
		)
		if err != nil {
			return result, err
		}
		if len(planned) == 0 && request.SettingsExpectedVersion != nil {
			return result, admodel.ErrObjectControlUnsupported
		}
		if _, err := admodel.InternalObjectWriteControls(
			root,
			adengine.InternalClientConfig(c.engine()).Endpoint,
			admodel.ObjectMutationOptions{ExpectedVersion: request.SettingsExpectedVersion},
			guid,
			false,
		); err != nil {
			return result, err
		}
	}
	if len(mods) > 0 {
		step, e := internalServiceTopologyModify(
			c,
			ctx,
			request.Identity,
			options,
			"CN=Sites,"+options.Partition,
			"site",
			admodel.InternalTopologySiteProperties(nil),
			func(admodel.Object) ([]admodel.InternalLdapAttributeModification, error) { return mods, nil },
		)
		if e := admodel.InternalTopologyStep(&result, "site", step, e); e != nil {
			return result, e
		}
	}
	if settingsChange {
		settingsOptions := admodel.ObjectMutationOptions{
			Partition:       options.Partition,
			ExpectedVersion: request.SettingsExpectedVersion,
		}
		step, e := internalServiceTopologyModify(c,
			ctx,
			settingsIdentity,
			settingsOptions,
			siteDN,
			"nTDSSiteSettings",
			admodel.InternalTopologySettingsProperties(),
			func(object admodel.Object) ([]admodel.InternalLdapAttributeModification, error) {
				return admodel.InternalReplicationSiteSettingsMods(
					object,
					*request.Settings,
					links,
					false,
				)
			},
		)
		if e := admodel.InternalTopologyStep(&result, "NTDS Site Settings", step, e); e != nil {
			return result, e
		}
	}
	result.After, err = c.ReplicationSite(
		ctx,
		request.Identity,
		admodel.ResolveIdentityOptions{
			Partition:  options.Partition,
			Properties: request.Options.Properties,
		},
	)
	result.Complete = err == nil
	if err != nil {
		return result, errors.Join(admodel.ErrObjectReadback, err)
	}
	return result, nil
}

// DeleteReplicationSite refuses servers, linked subnets and unrecognized
// descendants. Only recognized administrative children are deleted, by separate
// leaf deletes, then the site. New children cause native non-leaf rejection.
//
// Related cmdlet: Remove-ADReplicationSite.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adreplicationsite?view=windowsserver2025-ps
func (c *Service) DeleteReplicationSite(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (result ReplicationSiteMutationResult, err error) {
	defer func() { err = admodel.InternalTopologyIncompleteError(result, err) }()
	if err := admodel.InternalTopologyMutationInput(identity, options); err != nil {
		return result, err
	}
	if options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return result, err
	}
	defer cancel()
	_, options, err = internalServiceTopologyMutationRoot(c, ctx, options)
	if err != nil {
		return result, err
	}
	site, err := internalServiceTopologyLinkedSite(c, ctx, identity, options.Partition)
	result.Preflight = site
	if err != nil {
		return result, err
	}
	dn := site.Object.DistinguishedName
	children, err := c.engine().
		Search(ctx, admodel.SearchOptions{Base: dn, Scope: admodel.ScopeSubtree, Properties: []string{"objectGUID", "objectClass", "name"}})
	result.Children = children
	if err != nil {
		return result, err
	}
	links, err := c.engine().
		Search(ctx, admodel.SearchOptions{
			Base:        "CN=Subnets,CN=Sites," + options.Partition,
			Scope:       admodel.ScopeOneLevel,
			TypedFilter: admodel.FilterEqual("siteObject", admodel.FilterText(dn)),
			Properties:  []string{"objectGUID"},
		})
	result.LinkedSubnets = links
	if err != nil {
		return result, err
	}
	if len(links.Objects) > 0 {
		return result, admodel.ErrReplicationSiteNotEmpty
	}
	type childEntry struct {
		InternalObject admodel.Object
		InternalClass  string
	}
	var removable []childEntry
	for _, object := range children.Objects {
		if strings.EqualFold(object.DistinguishedName, dn) {
			continue
		}
		class := ""
		for _, candidate := range []struct{ InternalName, InternalClass string }{
			{"NTDS Site Settings", "nTDSSiteSettings"},
			{"Servers", "serversContainer"},
			{"Licensing Site Settings", "licensingSiteSettings"},
		} {
			if strings.EqualFold(object.DistinguishedName, "CN="+candidate.InternalName+","+dn) &&
				admodel.InternalTopologyDirectChild(object, dn, candidate.InternalClass) == nil {
				class = candidate.InternalClass
				break
			}
		}
		if class == "" {
			return result, admodel.ErrReplicationSiteNotEmpty
		}
		if _, err := admodel.InternalTopologyGUID(object); err != nil {
			return result, err
		}
		removable = append(removable, childEntry{object, class})
	}
	// A hidden/concurrently added server must make the Servers leaf delete fail
	// before any site settings are removed. Never rely on query visibility alone.
	slices.SortFunc(removable, func(a, b childEntry) int {
		if a.InternalClass == "serversContainer" && b.InternalClass != "serversContainer" {
			return -1
		}
		if b.InternalClass == "serversContainer" && a.InternalClass != "serversContainer" {
			return 1
		}
		return strings.Compare(
			a.InternalObject.DistinguishedName,
			b.InternalObject.DistinguishedName,
		)
	})
	for _, child := range removable {
		guid, _ := admodel.InternalTopologyGUID(child.InternalObject)
		step, e := internalServiceTopologyDelete(c,
			ctx,
			admodel.InternalObjectGUIDIdentity(guid),
			admodel.ObjectMutationOptions{Partition: options.Partition},
			dn,
			child.InternalClass,
		)
		if e := admodel.InternalTopologyStep(
			&result,
			child.InternalObject.DistinguishedName,
			step,
			e,
		); e != nil {
			return result, e
		}
	}
	guid, err := admodel.InternalTopologyGUID(*site.Object)
	if err != nil {
		return result, err
	}
	step, err := internalServiceTopologyDelete(c,
		ctx,
		admodel.InternalObjectGUIDIdentity(guid),
		options,
		"CN=Sites,"+options.Partition,
		"site",
	)
	_ = admodel.InternalTopologyStep(&result, "site", step, err)
	result.Complete = err == nil
	return result, err
}
