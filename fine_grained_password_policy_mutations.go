package activedirectory

import (
	"context"
	"errors"
	"strconv"
	"strings"
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

func fineGrainedSettingsChanges(settings FineGrainedPasswordPolicySettings, complete bool) ([]AttributeChange, error) {
	var changes []AttributeChange
	add := func(name, text string) {
		changes = append(changes, AttributeChange{Attribute: name, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(text))}})
	}
	if settings.Precedence != nil {
		if *settings.Precedence < 1 {
			return nil, ErrInvalidFineGrainedPolicy
		}
		add("msDS-PasswordSettingsPrecedence", strconv.FormatInt(int64(*settings.Precedence), 10))
	}
	for _, field := range []struct {
		name  string
		value *bool
	}{{"msDS-PasswordComplexityEnabled", settings.ComplexityEnabled}, {"msDS-PasswordReversibleEncryptionEnabled", settings.ReversibleEncryptionEnabled}} {
		if field.value != nil {
			text := "FALSE"
			if *field.value {
				text = "TRUE"
			}
			add(field.name, text)
		}
	}
	for _, field := range []struct {
		name  string
		value *uint16
		max   uint16
	}{{"msDS-PasswordHistoryLength", settings.PasswordHistoryCount, 1024}, {"msDS-MinimumPasswordLength", settings.MinPasswordLength, 256}, {"msDS-LockoutThreshold", settings.LockoutThreshold, 65535}} {
		if field.value != nil {
			if *field.value > field.max {
				return nil, ErrInvalidFineGrainedPolicy
			}
			add(field.name, strconv.FormatUint(uint64(*field.value), 10))
		}
	}
	for _, field := range []struct {
		name  string
		value *PolicyInterval
	}{{"msDS-MinimumPasswordAge", settings.MinPasswordAge}, {"msDS-MaximumPasswordAge", settings.MaxPasswordAge}, {"msDS-LockoutDuration", settings.LockoutDuration}, {"msDS-LockoutObservationWindow", settings.LockoutObservationWindow}} {
		if field.value == nil {
			continue
		}
		value := *field.value
		if value > PolicyNever {
			return nil, ErrPolicyIntervalRange
		}
		if field.name == "msDS-MaximumPasswordAge" && value == 0 {
			value = PolicyNever
		}
		add(field.name, formatPolicyInterval(value))
	}
	if complete && len(changes) != 10 {
		return nil, ErrInvalidFineGrainedPolicy
	}
	return changes, nil
}

func fineGrainedSettingsRelationships(before, patch FineGrainedPasswordPolicySettings, complete bool) error {
	merge := func(old, next *PolicyInterval) *PolicyInterval {
		if next != nil {
			return next
		}
		return old
	}
	if complete || patch.MinPasswordAge != nil || patch.MaxPasswordAge != nil {
		minimum, maximum := merge(before.MinPasswordAge, patch.MinPasswordAge), merge(before.MaxPasswordAge, patch.MaxPasswordAge)
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
		duration, window := merge(before.LockoutDuration, patch.LockoutDuration), merge(before.LockoutObservationWindow, patch.LockoutObservationWindow)
		if duration == nil || window == nil {
			return ErrAttributeUnavailable
		}
		if *duration < *window {
			return ErrInvalidFineGrainedPolicy
		}
	}
	return nil
}

func fineGrainedTextChanges(description, displayName *string) ([]AttributeChange, error) {
	var changes []AttributeChange
	for _, field := range []struct {
		name  string
		value *string
	}{{"description", description}, {"displayName", displayName}} {
		if field.value != nil {
			if !validDirectoryText(*field.value) {
				return nil, ErrInvalidValue
			}
			changes = append(changes, AttributeChange{Attribute: field.name, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*field.value))}})
		}
	}
	return changes, nil
}

func fineGrainedMutationResult(mutation ObjectMutationResult, err error) (FineGrainedPasswordPolicyMutationResult, error) {
	result := FineGrainedPasswordPolicyMutationResult{Mutation: mutation}
	if mutation.After != nil {
		policy, decodeErr := decodeFineGrainedPolicy(*mutation.After)
		result.Policy = &policy
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// CreateFineGrainedPasswordPolicy requires all settings explicitly; it does not
// silently import a PowerShell/default-domain template. One Add creates the PSO
// under the connected domain's Password Settings Container.
func (c *Client) CreateFineGrainedPasswordPolicy(ctx context.Context, request CreateFineGrainedPasswordPolicyRequest) (FineGrainedPasswordPolicyMutationResult, error) {
	var result FineGrainedPasswordPolicyMutationResult
	changes, err := fineGrainedSettingsChanges(request.Settings, true)
	if err != nil {
		return result, err
	}
	if err := fineGrainedSettingsRelationships(FineGrainedPasswordPolicySettings{}, request.Settings, true); err != nil {
		return result, err
	}
	text, err := fineGrainedTextChanges(request.Description, request.DisplayName)
	if err != nil {
		return result, err
	}
	changes = append(changes, text...)
	if request.Name == "" || !validDirectoryText(request.Name) {
		return result, ErrInvalidFineGrainedPolicy
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	// Discovery and generic creation share one budget; neither stage can restart
	// Config.Timeout after the previous stage has consumed part of it.
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	root, err := c.RootDSE(ctx, RootDSEOptions{})
	if err != nil {
		return result, err
	}
	domain, err := fineGrainedPolicyDomain(root, c.config, request.Options.Partition)
	if err != nil {
		return result, err
	}
	parent, err := IdentityByDN(fineGrainedPolicyContainer(domain))
	if err != nil {
		return result, err
	}
	attributes := make(map[string][]RawValue, len(changes))
	for _, change := range changes {
		attributes[change.Attribute] = change.Values
	}
	request.Options.Partition = domain
	request.Options.Properties = fineGrainedPolicyProperties(request.Options.Properties)
	return fineGrainedMutationResult(c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: "msDS-PasswordSettings", Name: request.Name, Attributes: attributes, Options: request.Options}))
}

func fineGrainedMutationOptions(identity Identity, options ObjectMutationOptions) error {
	if identity.Form() != IdentityFormDN && identity.Form() != IdentityFormGUID {
		return ErrUnsupportedIdentity
	}
	return validateObjectOptions(identity, options)
}

func (c *Client) mutateFineGrainedPolicy(ctx context.Context, identity Identity, options ObjectMutationOptions, workflow objectMutationWorkflow) (ObjectMutationResult, error) {
	resolve := ResolveIdentityOptions{Partition: options.Partition, Properties: fineGrainedPolicyProperties(options.Properties)}
	return c.objectMutationIdentity(ctx, identity, options, resolve, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		domain, err := fineGrainedPolicyDomain(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		if err := fineGrainedPolicyLocation(*observed.Object, domain); err != nil {
			return err
		}
		return workflow(ctx, session, root, observed, result)
	})
}

// UpdateFineGrainedPasswordPolicy submits all selected changes atomically in
// one strict Modify. The server validates resulting cross-field constraints.
func (c *Client) UpdateFineGrainedPasswordPolicy(ctx context.Context, request UpdateFineGrainedPasswordPolicyRequest) (FineGrainedPasswordPolicyMutationResult, error) {
	if err := fineGrainedMutationOptions(request.Identity, request.Options); err != nil {
		return FineGrainedPasswordPolicyMutationResult{}, err
	}
	changes, err := fineGrainedSettingsChanges(request.Settings, false)
	if err != nil {
		return FineGrainedPasswordPolicyMutationResult{}, err
	}
	text, err := fineGrainedTextChanges(request.Description, request.DisplayName)
	if err != nil {
		return FineGrainedPasswordPolicyMutationResult{}, err
	}
	changes = append(changes, text...)
	for _, change := range request.Changes {
		for _, managed := range fineGrainedPolicyProperties(nil) {
			if strings.EqualFold(change.Attribute, managed) && !strings.EqualFold(managed, "description") && !strings.EqualFold(managed, "displayName") {
				return FineGrainedPasswordPolicyMutationResult{}, ErrInvalidFineGrainedPolicy
			}
		}
		changes = append(changes, change)
	}
	mods, err := objectChanges(changes)
	if err != nil {
		return FineGrainedPasswordPolicyMutationResult{}, err
	}
	mutation, err := c.mutateFineGrainedPolicy(ctx, request.Identity, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		before, err := decodeFineGrainedPolicy(*observed.Object)
		if err != nil {
			return err
		}
		if err := fineGrainedSettingsRelationships(before.Settings, request.Settings, false); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: mods, controls: controls}, false, result); err != nil {
			return err
		}
		options := request.Options
		options.Properties = fineGrainedPolicyProperties(options.Properties)
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(options, mods), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, mods, "")
	})
	return fineGrainedMutationResult(mutation, err)
}

// DeleteFineGrainedPasswordPolicy is a leaf delete. It never removes subjects
// themselves, disables protection or retries a rejected/uncertain request.
func (c *Client) DeleteFineGrainedPasswordPolicy(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	if err := fineGrainedMutationOptions(identity, options); err != nil {
		return ObjectMutationResult{}, err
	}
	return c.mutateFineGrainedPolicy(ctx, identity, options, func(ctx context.Context, session ldapWriteSession, root RootDSE, _ IdentityResult, result *ObjectMutationResult) error {
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
