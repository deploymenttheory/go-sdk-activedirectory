package model

import (
	"errors"
	"strconv"
)

type CreateFineGrainedPasswordPolicyRequest struct {
	Name                     string
	Settings                 FineGrainedPasswordPolicySettings
	Description, DisplayName *string
	Options                  ObjectMutationOptions
}
type UpdateFineGrainedPasswordPolicyRequest struct {
	Identity                 Identity
	Settings                 FineGrainedPasswordPolicySettings
	Description, DisplayName *string
	Changes                  []AttributeChange
	Options                  ObjectMutationOptions
}

func InternalFineGrainedSettingsChanges(
	settings FineGrainedPasswordPolicySettings,
	complete bool,
) ([]AttributeChange, error) {
	var changes []AttributeChange
	add := func(name, text string) {
		changes = append(
			changes,
			AttributeChange{
				Attribute: name,
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue([]byte(text))},
			},
		)
	}
	if settings.Precedence != nil {
		if *settings.Precedence < 1 {
			return nil, ErrInvalidFineGrainedPolicy
		}
		add("msDS-PasswordSettingsPrecedence", strconv.FormatInt(int64(*settings.Precedence), 10))
	}
	for _, field := range []struct {
		InternalName  string
		InternalValue *bool
	}{{"msDS-PasswordComplexityEnabled", settings.ComplexityEnabled}, {"msDS-PasswordReversibleEncryptionEnabled", settings.ReversibleEncryptionEnabled}} {
		if field.InternalValue != nil {
			text := "FALSE"
			if *field.InternalValue {
				text = "TRUE"
			}
			add(field.InternalName, text)
		}
	}
	for _, field := range []struct {
		InternalName  string
		InternalValue *uint16
		InternalMax   uint16
	}{
		{"msDS-PasswordHistoryLength", settings.PasswordHistoryCount, 1024},
		{"msDS-MinimumPasswordLength", settings.MinPasswordLength, 256},
		{"msDS-LockoutThreshold", settings.LockoutThreshold, 65535},
	} {
		if field.InternalValue != nil {
			if *field.InternalValue > field.InternalMax {
				return nil, ErrInvalidFineGrainedPolicy
			}
			add(field.InternalName, strconv.FormatUint(uint64(*field.InternalValue), 10))
		}
	}
	for _, field := range []struct {
		InternalName  string
		InternalValue *PolicyInterval
	}{
		{"msDS-MinimumPasswordAge", settings.MinPasswordAge},
		{"msDS-MaximumPasswordAge", settings.MaxPasswordAge},
		{"msDS-LockoutDuration", settings.LockoutDuration},
		{"msDS-LockoutObservationWindow", settings.LockoutObservationWindow},
	} {
		if field.InternalValue == nil {
			continue
		}
		value := *field.InternalValue
		if value > PolicyNever {
			return nil, ErrPolicyIntervalRange
		}
		if field.InternalName == "msDS-MaximumPasswordAge" && value == 0 {
			value = PolicyNever
		}
		add(field.InternalName, InternalFormatPolicyInterval(value))
	}
	if complete && len(changes) != 10 {
		return nil, ErrInvalidFineGrainedPolicy
	}
	return changes, nil
}

func InternalFineGrainedSettingsRelationships(
	before, patch FineGrainedPasswordPolicySettings,
	complete bool,
) error {
	merge := func(old, next *PolicyInterval) *PolicyInterval {
		if next != nil {
			return next
		}
		return old
	}
	if complete || patch.MinPasswordAge != nil || patch.MaxPasswordAge != nil {
		minimum, maximum := merge(
			before.MinPasswordAge,
			patch.MinPasswordAge,
		), merge(
			before.MaxPasswordAge,
			patch.MaxPasswordAge,
		)
		if minimum == nil || maximum == nil {
			return ErrAttributeUnavailable
		}
		max := *maximum
		if max == 0 {
			max = PolicyNever
		}
		if max <= *minimum {
			return ErrInvalidFineGrainedPolicy
		}
	}
	if complete || patch.LockoutDuration != nil || patch.LockoutObservationWindow != nil {
		duration, window := merge(
			before.LockoutDuration,
			patch.LockoutDuration,
		), merge(
			before.LockoutObservationWindow,
			patch.LockoutObservationWindow,
		)
		if duration == nil || window == nil {
			return ErrAttributeUnavailable
		}
		if *duration < *window {
			return ErrInvalidFineGrainedPolicy
		}
	}
	return nil
}

func InternalFineGrainedTextChanges(description, displayName *string) ([]AttributeChange, error) {
	var changes []AttributeChange
	for _, field := range []struct {
		InternalName  string
		InternalValue *string
	}{{"description", description}, {"displayName", displayName}} {
		if field.InternalValue != nil {
			if !InternalValidDirectoryText(*field.InternalValue) {
				return nil, ErrInvalidValue
			}
			changes = append(
				changes,
				AttributeChange{
					Attribute: field.InternalName,
					Kind:      AttributeSet,
					Values:    []RawValue{NewRawValue([]byte(*field.InternalValue))},
				},
			)
		}
	}
	return changes, nil
}

func InternalFineGrainedMutationResult(
	mutation ObjectMutationResult,
	err error,
) (FineGrainedPasswordPolicyMutationResult, error) {
	result := FineGrainedPasswordPolicyMutationResult{Mutation: mutation}
	if mutation.After != nil {
		policy, decodeErr := InternalDecodeFineGrainedPolicy(*mutation.After)
		result.Policy = &policy
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func InternalFineGrainedMutationOptions(identity Identity, options ObjectMutationOptions) error {
	if identity.Form() != IdentityFormDN && identity.Form() != IdentityFormGUID {
		return ErrUnsupportedIdentity
	}
	return InternalValidateObjectOptions(identity, options)
}
