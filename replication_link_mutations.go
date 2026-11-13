package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
)

type CreateReplicationSiteLinkRequest struct {
	Name                                string
	Transport                           ReplicationTransport
	Description                         *string
	Cost, ReplicationFrequencyInMinutes *int32
	Schedule                            *ReplicationSchedule
	LinkOptions                         ReplicationSiteLinkOptions
	Sites                               []Identity
	Attributes                          map[string][]RawValue
	Options                             ObjectMutationOptions
}
type UpdateReplicationSiteLinkRequest struct {
	Identity                            Identity
	Description                         *string
	Cost, ReplicationFrequencyInMinutes *int32
	Schedule                            *ReplicationSchedule
	ClearSchedule                       bool
	SetOptions, ClearOptions            ReplicationSiteLinkOptions
	Sites                               ReplicationReferenceChanges
	Changes                             []AttributeChange
	Options                             ObjectMutationOptions
}
type CreateReplicationSiteLinkBridgeRequest struct {
	Name        string
	Transport   ReplicationTransport
	Description *string
	SiteLinks   []Identity
	Attributes  map[string][]RawValue
	Options     ObjectMutationOptions
}
type UpdateReplicationSiteLinkBridgeRequest struct {
	Identity    Identity
	Description *string
	SiteLinks   ReplicationReferenceChanges
	Changes     []AttributeChange
	Options     ObjectMutationOptions
}
type ReplicationLinkMutationResult struct {
	Mutation        ObjectMutationResult
	References      []ReplicationReferenceInput
	AfterReferences ReplicationReferencesResult
	Link            *ReplicationSiteLink
	Bridge          *ReplicationSiteLinkBridge
}

func replicationLinkManaged() []string {
	return []string{"cn", "name", "cost", "replInterval", "options", "schedule", "siteList", "siteLinkList", "fromServer", "transportType", "enabledConnection"}
}
func replicationLinkValues(cost, interval *int32, schedule *ReplicationSchedule, clear bool) ([]AttributeChange, error) {
	if cost != nil && *cost < 0 {
		return nil, ErrReplicationTopology
	}
	if interval != nil && (*interval < 15 || *interval > 10080 || *interval%15 != 0) {
		return nil, ErrReplicationTopology
	}
	if clear && schedule != nil {
		return nil, ErrReplicationTopology
	}
	var changes []AttributeChange
	for _, item := range []struct {
		name  string
		value *int32
	}{{"cost", cost}, {"replInterval", interval}} {
		if item.value != nil {
			text := strconv.FormatInt(int64(*item.value), 10)
			changes = append(changes, topologyTextChange(item.name, &text)...)
		}
	}
	if schedule != nil {
		changes = append(changes, AttributeChange{Attribute: "schedule", Kind: AttributeSet, Values: []RawValue{NewRawValue(schedule.Bytes())}})
	} else if clear {
		changes = append(changes, AttributeChange{Attribute: "schedule", Kind: AttributeClear})
	}
	return changes, nil
}
func replicationOptionsMods(object Object, set, clear, known uint32) ([]ldapAttributeModification, error) {
	if set&clear != 0 || (set|clear)&^known != 0 {
		return nil, ErrReplicationTopology
	}
	if set|clear == 0 {
		return nil, nil
	}
	value, err := object.Values("options").Single()
	if err != nil {
		return nil, err
	}
	text, err := value.Text()
	if err != nil {
		return nil, err
	}
	current, err := parseDirectoryMask(text)
	if err != nil {
		return nil, err
	}
	next := (current | set) &^ clear
	if next == current {
		return nil, nil
	}
	return []ldapAttributeModification{{operation: 1, attribute: "options", values: [][]byte{value.Bytes()}}, {operation: 0, attribute: "options", values: [][]byte{[]byte(strconv.FormatInt(int64(int32(next)), 10))}}}, nil
}
func replicationLinkProject(result ReplicationLinkMutationResult, configuration string, bridge bool, err error) (ReplicationLinkMutationResult, error) {
	if result.Mutation.After != nil {
		if bridge {
			value, e := decodeReplicationBridge(*result.Mutation.After, configuration)
			result.Bridge = &value
			err = errors.Join(err, e)
		} else {
			value, e := decodeReplicationLink(*result.Mutation.After, configuration)
			result.Link = &value
			err = errors.Join(err, e)
		}
	}
	return result, err
}
func replicationReferenceVerify(ctx context.Context, values ReplicationReferencesResult, mods []ldapAttributeModification, attribute string) error {
	index := make(map[string]struct{}, len(values.References))
	for _, ref := range values.References {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		parsed, err := parseIdentityDN(ref.DistinguishedName)
		if err != nil {
			return err
		}
		index[identityDNKey(parsed)] = struct{}{}
	}
	for _, mod := range mods {
		if mod.attribute != attribute {
			continue
		}
		if !values.Complete || !values.AttributeReturned {
			return ErrObjectVerification
		}
		if mod.operation == 2 && len(mod.values) != len(values.References) {
			return ErrObjectVerification
		}
		if mod.operation == 1 && len(mod.values) == 0 && len(values.References) != 0 {
			return ErrObjectVerification
		}
		for _, value := range mod.values {
			if err := context.Cause(ctx); err != nil {
				return err
			}
			parsed, err := parseIdentityDN(string(value))
			if err != nil {
				return err
			}
			_, contains := index[identityDNKey(parsed)]
			if contains == (mod.operation == 1) {
				return ErrObjectVerification
			}
		}
	}
	return nil
}
func (c *Client) createReplicationLink(ctx context.Context, name string, transport ReplicationTransport, description *string, attributes map[string][]RawValue, identities []Identity, options ObjectMutationOptions, bridge bool) (ReplicationLinkMutationResult, error) {
	var result ReplicationLinkMutationResult
	if name == "" || !validDirectoryText(name) {
		return result, ErrInvalidValue
	}
	if options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if err := replicationReferenceChangesValid(ReplicationReferenceChanges{Replace: identities}); err != nil {
		return result, err
	}
	if description != nil && !validDirectoryText(*description) {
		return result, ErrInvalidValue
	}
	if description != nil {
		for attribute := range attributes {
			if strings.EqualFold(attribute, "description") {
				return result, ErrInvalidObjectMutation
			}
		}
	}
	ctx, cancel, err := topologyMutationContext(ctx, c)
	if err != nil {
		return result, err
	}
	defer cancel()
	var configuration, parent string
	class, attr, refClass := "siteLink", "siteList", "site"
	if bridge {
		class, attr, refClass = "siteLinkBridge", "siteLinkList", "siteLink"
	}
	var values [][]byte
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err = topologyConfiguration(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		parent, err = replicationTransportParent(root, c.config, configuration, transport)
		if err != nil {
			return err
		}
		container, err := topologyResolveDN(ctx, c.session, c.config, root, parent, configuration, []string{"objectClass"})
		if err != nil {
			return err
		}
		if err := topologyClass(*container.Object, "interSiteTransport"); err != nil {
			return err
		}
		refParent := "CN=Sites," + configuration
		if bridge {
			refParent = parent
		}
		values, err = resolveReplicationReferences(ctx, c.session, c.config, root, configuration, refParent, refClass, identities, &result.References)
		return err
	})
	if err != nil {
		return result, err
	}
	attrs := make(map[string][]RawValue, len(attributes)+2)
	for name, values := range attributes {
		attrs[name] = slices.Clone(values)
	}
	if description != nil {
		attrs["description"] = []RawValue{NewRawValue([]byte(*description))}
	}
	if len(values) > 0 {
		for _, value := range values {
			attrs[attr] = append(attrs[attr], NewRawValue(value))
		}
	}
	options.Partition = configuration
	options.Properties = replicationLinkProperties(options.Properties, bridge)
	parentIdentity, _ := IdentityByDN(parent)
	result.Mutation, err = c.createObjectWithReadback(ctx, CreateObjectRequest{Parent: parentIdentity, Class: class, Name: name, Attributes: attrs, Options: options}, func(ctx context.Context, session ldapWriteSession, root RootDSE, mutation *ObjectMutationResult, mods []ldapAttributeModification) error {
		plainMods := slices.DeleteFunc(slices.Clone(mods), func(mod ldapAttributeModification) bool { return strings.EqualFold(mod.attribute, attr) })
		identity, e := IdentityByDN(mutation.TargetDN)
		if e != nil {
			return errors.Join(ErrObjectReadback, e)
		}
		if e := observeObjectWrite(ctx, session, c.config, root, identity, mutation, objectWriteProperties(options, plainMods), false); e != nil {
			return e
		}
		if e := verifyObjectWrite(mutation, plainMods, name); e != nil {
			return e
		}
		mutation.Verified = false
		limits, _ := normalizeReplicationReferenceLimits(ReplicationReferenceLimits{})
		result.AfterReferences, e = collectReplicationReferences(ctx, session, *mutation.After, attr, limits)
		if e != nil {
			return errors.Join(ErrObjectReadback, e)
		}
		if len(values) > 0 {
			if e := replicationReferenceVerify(ctx, result.AfterReferences, []ldapAttributeModification{{operation: 2, attribute: attr, values: values}}, attr); e != nil {
				return e
			}
		}
		mutation.Verified = true
		return nil
	})
	return replicationLinkProject(result, configuration, bridge, err)
}
func (c *Client) CreateReplicationSiteLink(ctx context.Context, request CreateReplicationSiteLinkRequest) (ReplicationLinkMutationResult, error) {
	if request.LinkOptions & ^ReplicationSiteLinkOptions(7) != 0 {
		return ReplicationLinkMutationResult{}, ErrReplicationTopology
	}
	attrs := map[string][]RawValue{}
	for name, values := range request.Attributes {
		if _, err := topologyValidateChanges([]AttributeChange{{Attribute: name, Kind: AttributeSet, Values: values}}, replicationLinkManaged()); err != nil {
			return ReplicationLinkMutationResult{}, err
		}
		attrs[name] = slices.Clone(values)
	}
	cost, interval := int32(100), int32(180)
	if request.Cost != nil {
		cost = *request.Cost
	}
	if request.ReplicationFrequencyInMinutes != nil {
		interval = *request.ReplicationFrequencyInMinutes
	}
	changes, err := replicationLinkValues(&cost, &interval, request.Schedule, false)
	if err != nil {
		return ReplicationLinkMutationResult{}, err
	}
	for _, change := range changes {
		attrs[change.Attribute] = change.Values
	}
	attrs["options"] = []RawValue{NewRawValue([]byte(strconv.FormatUint(uint64(request.LinkOptions), 10)))}
	return c.createReplicationLink(ctx, request.Name, request.Transport, request.Description, attrs, request.Sites, request.Options, false)
}
func (c *Client) CreateReplicationSiteLinkBridge(ctx context.Context, request CreateReplicationSiteLinkBridgeRequest) (ReplicationLinkMutationResult, error) {
	for name, values := range request.Attributes {
		if _, err := topologyValidateChanges([]AttributeChange{{Attribute: name, Kind: AttributeSet, Values: values}}, replicationLinkManaged()); err != nil {
			return ReplicationLinkMutationResult{}, err
		}
	}
	return c.createReplicationLink(ctx, request.Name, request.Transport, request.Description, request.Attributes, request.SiteLinks, request.Options, true)
}
func (c *Client) updateReplicationLink(ctx context.Context, identity Identity, options ObjectMutationOptions, changes []AttributeChange, references ReplicationReferenceChanges, set, clear uint32, bridge bool) (ReplicationLinkMutationResult, error) {
	var result ReplicationLinkMutationResult
	if err := topologyMutationInput(identity, options); err != nil {
		return result, err
	}
	if err := replicationReferenceChangesValid(references); err != nil {
		return result, err
	}
	var mods []ldapAttributeModification
	var err error
	if len(changes) > 0 {
		mods, err = objectChanges(changes)
		if err != nil {
			return result, err
		}
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
	class, attr, refClass := "siteLink", "siteList", "site"
	if bridge {
		class, attr, refClass = "siteLinkBridge", "siteLinkList", "siteLink"
	}
	var configuration string
	result.Mutation, err = c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{Properties: replicationLinkProperties(options.Properties, bridge)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		configuration, err = topologyConfiguration(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		transport, err := replicationObjectTransport(*observed.Object, configuration)
		if err != nil {
			return err
		}
		parent, err := replicationTransportParent(root, c.config, configuration, transport)
		if err != nil {
			return err
		}
		if err := topologyDirectChild(*observed.Object, parent, class); err != nil {
			return err
		}
		refParent := "CN=Sites," + configuration
		if bridge {
			refParent = parent
		}
		refMods, err := replicationReferenceMods(ctx, session, c.config, root, configuration, refParent, refClass, attr, references, &result.References)
		if err != nil {
			return err
		}
		flags, err := replicationOptionsMods(*observed.Object, set, clear, 7)
		if err != nil {
			return err
		}
		mods = append(mods, flags...)
		plainMods := slices.Clone(mods)
		mods = append(mods, refMods...)
		if len(mods) == 0 {
			if options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			mutation.After = mutation.Before
			mutation.ReadbackComplete = true
			mutation.Verified = true
			return nil
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); err != nil {
			return err
		}
		readOptions := options
		readOptions.Properties = replicationLinkProperties(readOptions.Properties, bridge)
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, objectWriteProperties(readOptions, plainMods), false); err != nil {
			return err
		}
		if err := verifyObjectWrite(mutation, plainMods, ""); err != nil {
			return err
		}
		if len(refMods) > 0 {
			mutation.Verified = false
			limits, _ := normalizeReplicationReferenceLimits(ReplicationReferenceLimits{})
			result.AfterReferences, err = collectReplicationReferences(ctx, session, *mutation.After, attr, limits)
			if err != nil {
				return errors.Join(ErrObjectReadback, err)
			}
			if err := replicationReferenceVerify(ctx, result.AfterReferences, refMods, attr); err != nil {
				return err
			}
			mutation.Verified = true
		}
		return nil
	})
	return replicationLinkProject(result, configuration, bridge, err)
}
func (c *Client) UpdateReplicationSiteLink(ctx context.Context, request UpdateReplicationSiteLinkRequest) (ReplicationLinkMutationResult, error) {
	if request.SetOptions&request.ClearOptions != 0 || (request.SetOptions|request.ClearOptions)&^ReplicationSiteLinkOptions(7) != 0 {
		return ReplicationLinkMutationResult{}, ErrReplicationTopology
	}
	if len(request.Changes) > 0 {
		if _, err := topologyValidateChanges(request.Changes, replicationLinkManaged()); err != nil {
			return ReplicationLinkMutationResult{}, err
		}
	}
	changes, err := replicationLinkValues(request.Cost, request.ReplicationFrequencyInMinutes, request.Schedule, request.ClearSchedule)
	if err != nil {
		return ReplicationLinkMutationResult{}, err
	}
	changes = append(changes, topologyTextChange("description", request.Description)...)
	changes = append(changes, request.Changes...)
	return c.updateReplicationLink(ctx, request.Identity, request.Options, changes, request.Sites, uint32(request.SetOptions), uint32(request.ClearOptions), false)
}
func (c *Client) UpdateReplicationSiteLinkBridge(ctx context.Context, request UpdateReplicationSiteLinkBridgeRequest) (ReplicationLinkMutationResult, error) {
	if len(request.Changes) > 0 {
		if _, err := topologyValidateChanges(request.Changes, replicationLinkManaged()); err != nil {
			return ReplicationLinkMutationResult{}, err
		}
	}
	return c.updateReplicationLink(ctx, request.Identity, request.Options, append(topologyTextChange("description", request.Description), request.Changes...), request.SiteLinks, 0, 0, true)
}
func (c *Client) deleteReplicationLink(ctx context.Context, identity Identity, options ObjectMutationOptions, bridge bool) (ObjectMutationResult, error) {
	if err := topologyMutationInput(identity, options); err != nil {
		return ObjectMutationResult{}, err
	}
	ctx, cancel, err := topologyMutationContext(ctx, c)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	defer cancel()
	_, options, err = c.topologyMutationRoot(ctx, options)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	return c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		configuration, err := topologyConfiguration(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		transport, err := replicationObjectTransport(*observed.Object, configuration)
		if err != nil {
			return err
		}
		parent, err := replicationTransportParent(root, c.config, configuration, transport)
		if err != nil {
			return err
		}
		class := "siteLink"
		if bridge {
			class = "siteLinkBridge"
		}
		if err := topologyDirectChild(*observed.Object, parent, class); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}, false, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
}
func (c *Client) DeleteReplicationSiteLink(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	return c.deleteReplicationLink(ctx, identity, options, false)
}
func (c *Client) DeleteReplicationSiteLinkBridge(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	return c.deleteReplicationLink(ctx, identity, options, true)
}
