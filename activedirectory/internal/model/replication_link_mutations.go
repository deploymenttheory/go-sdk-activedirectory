package model

import (
	"context"
	"errors"
	"strconv"
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

func InternalReplicationLinkManaged() []string {
	return []string{
		"cn",
		"name",
		"cost",
		"replInterval",
		"options",
		"schedule",
		"siteList",
		"siteLinkList",
		"fromServer",
		"transportType",
		"enabledConnection",
	}
}

func InternalReplicationLinkValues(
	cost, interval *int32,
	schedule *ReplicationSchedule,
	clear bool,
) ([]AttributeChange, error) {
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
		InternalName  string
		InternalValue *int32
	}{{"cost", cost}, {"replInterval", interval}} {
		if item.InternalValue != nil {
			text := strconv.FormatInt(int64(*item.InternalValue), 10)
			changes = append(changes, InternalTopologyTextChange(item.InternalName, &text)...)
		}
	}
	if schedule != nil {
		changes = append(
			changes,
			AttributeChange{
				Attribute: "schedule",
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue(schedule.Bytes())},
			},
		)
	} else if clear {
		changes = append(changes, AttributeChange{Attribute: "schedule", Kind: AttributeClear})
	}
	return changes, nil
}

func InternalReplicationOptionsMods(
	object Object,
	set, clear, known uint32,
) ([]InternalLdapAttributeModification, error) {
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
	current, err := InternalParseDirectoryMask(text)
	if err != nil {
		return nil, err
	}
	next := (current | set) &^ clear
	if next == current {
		return nil, nil
	}
	return []InternalLdapAttributeModification{
		{
			InternalOperation: 1,
			InternalAttribute: "options",
			InternalValues:    [][]byte{value.Bytes()},
		},
		{
			InternalOperation: 0,
			InternalAttribute: "options",
			InternalValues:    [][]byte{[]byte(strconv.FormatInt(int64(int32(next)), 10))},
		},
	}, nil
}

func InternalReplicationLinkProject(
	result ReplicationLinkMutationResult,
	configuration string,
	bridge bool,
	err error,
) (ReplicationLinkMutationResult, error) {
	if result.Mutation.After != nil {
		if bridge {
			value, e := InternalDecodeReplicationBridge(*result.Mutation.After, configuration)
			result.Bridge = &value
			err = errors.Join(err, e)
		} else {
			value, e := InternalDecodeReplicationLink(*result.Mutation.After, configuration)
			result.Link = &value
			err = errors.Join(err, e)
		}
	}
	return result, err
}

func InternalReplicationReferenceVerify(
	ctx context.Context,
	values ReplicationReferencesResult,
	mods []InternalLdapAttributeModification,
	attribute string,
) error {
	index := make(map[string]struct{}, len(values.References))
	for _, ref := range values.References {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		parsed, err := InternalParseIdentityDN(ref.DistinguishedName)
		if err != nil {
			return err
		}
		index[InternalIdentityDNKey(parsed)] = struct{}{}
	}
	for _, mod := range mods {
		if mod.InternalAttribute != attribute {
			continue
		}
		if !values.Complete || !values.AttributeReturned {
			return ErrObjectVerification
		}
		if mod.InternalOperation == 2 && len(mod.InternalValues) != len(values.References) {
			return ErrObjectVerification
		}
		if mod.InternalOperation == 1 && len(mod.InternalValues) == 0 &&
			len(values.References) != 0 {
			return ErrObjectVerification
		}
		for _, value := range mod.InternalValues {
			if err := context.Cause(ctx); err != nil {
				return err
			}
			parsed, err := InternalParseIdentityDN(string(value))
			if err != nil {
				return err
			}
			_, contains := index[InternalIdentityDNKey(parsed)]
			if contains == (mod.InternalOperation == 1) {
				return ErrObjectVerification
			}
		}
	}
	return nil
}
