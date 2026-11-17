package model

import (
	"strconv"
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

func InternalValidateReplicationSiteSettings(patch ReplicationSiteSettingsPatch) error {
	if patch.SetOptions&patch.ClearOptions != 0 ||
		(patch.SetOptions|patch.ClearOptions)&^ReplicationSiteOptions(0x1fff) != 0 ||
		(patch.Schedule != nil && patch.ClearSchedule) {
		return ErrReplicationTopology
	}
	for _, identity := range []*Identity{patch.InterSiteTopologyGenerator, patch.UniversalGroupCachingRefreshSite} {
		if identity != nil {
			if err := InternalTopologyIdentity(*identity, ResolveIdentityOptions{}); err != nil {
				return err
			}
		}
	}
	return nil
}

func InternalSiteSettingsPatchPresent(patch ReplicationSiteSettingsPatch) bool {
	return patch.SetOptions|patch.ClearOptions != 0 || patch.Schedule != nil ||
		patch.ClearSchedule ||
		patch.InterSiteTopologyGenerator != nil ||
		patch.UniversalGroupCachingRefreshSite != nil
}

func InternalReplicationSiteSettingsMods(
	object Object,
	patch ReplicationSiteSettingsPatch,
	links []AttributeChange,
	create bool,
) ([]InternalLdapAttributeModification, error) {
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
			changes = append(changes, InternalTopologyTextChange("options", &text)...)
		} else if old != next {
			// Strict delete-old/add-new rejects concurrent option changes without
			// overwriting unknown bits observed in the original value.
			changes = append(
				changes,
				AttributeChange{
					Attribute: "options",
					Kind:      AttributeRemoveValues,
					Values:    []RawValue{oldRaw},
				},
				AttributeChange{
					Attribute: "options",
					Kind:      AttributeAddValues,
					Values:    []RawValue{NewRawValue([]byte(text))},
				},
			)
		}
	}
	if patch.Schedule != nil {
		changes = append(
			changes,
			AttributeChange{
				Attribute: "schedule",
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue(patch.Schedule.Bytes())},
			},
		)
	} else if patch.ClearSchedule {
		changes = append(changes, AttributeChange{Attribute: "schedule", Kind: AttributeClear})
	}
	if len(changes) == 0 {
		return nil, nil
	}
	return InternalObjectChanges(changes)
}
