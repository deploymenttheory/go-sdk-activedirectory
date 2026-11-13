package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// FunctionalLevel is msDS-Behavior-Version, not a schema or OS version. There
// are no distinct Windows Server 2019/2022 levels; those releases use 2016.
type FunctionalLevel uint32

const (
	FunctionalLevelWindows2000        FunctionalLevel = 0
	FunctionalLevelWindows2003Interim FunctionalLevel = 1
	FunctionalLevelWindows2003        FunctionalLevel = 2
	FunctionalLevelWindows2008        FunctionalLevel = 3
	FunctionalLevelWindows2008R2      FunctionalLevel = 4
	FunctionalLevelWindows2012        FunctionalLevel = 5
	FunctionalLevelWindows2012R2      FunctionalLevel = 6
	FunctionalLevelWindows2016        FunctionalLevel = 7
	FunctionalLevelWindows2025        FunctionalLevel = 10
)

var (
	ErrInvalidFunctionalLevel      = errors.New("unknown or invalid functional level")
	ErrFunctionalLevelRoleOwner    = errors.New("functional-level transition requires the authoritative role owner")
	ErrFunctionalLevelPrerequisite = errors.New("functional-level prerequisite is not satisfied")
	ErrFunctionalLevelLowering     = errors.New("lowering a functional level requires explicit AllowLowering")
)

// FunctionalLevelTransitionRequest identifies the domain NC root (domain
// operation) or CN=Partitions in the configuration NC (forest operation), by
// DN or GUID. A forest GUID needs Options.Partition set to the configuration NC.
// AllowLowering is intent, not an override of compatibility or feature guards.
type FunctionalLevelTransitionRequest struct {
	Identity      Identity
	Level         FunctionalLevel
	AllowLowering bool
	Options       ObjectMutationOptions
}

// FunctionalLevelTransitionResult retains local raw prerequisite observations
// on failure. PreflightComplete means these checks completed, not that the
// forest is healthy, fully replicated, or every object/attribute was visible.
// The server enforces the transition at write time. No DC is contacted except
// Source, and the SDK never performs ADPrep, replication, or feature changes.
type FunctionalLevelTransitionResult struct {
	Mutation          ObjectMutationResult
	Requested         FunctionalLevel
	Current           *FunctionalLevel
	Role              OperationMasterRole
	RoleOwnerDN       string
	SchemaVersion     *uint32
	Observations      []Object
	PreflightComplete bool
	Unchanged         bool
}

// SetDomainMode submits a single functional-level change on the connected PDC.
// It supports raises and explicit supported lowering, with no automatic replay.
func (c *Client) SetDomainMode(ctx context.Context, request FunctionalLevelTransitionRequest) (FunctionalLevelTransitionResult, error) {
	return c.setFunctionalLevel(ctx, request, false)
}

// SetForestMode targets the Schema Master, as specified by MS-ADTS 3.1.1.5.3.4
// and the current Set-ADForestMode cmdlet. It never follows a role referral.
func (c *Client) SetForestMode(ctx context.Context, request FunctionalLevelTransitionRequest) (FunctionalLevelTransitionResult, error) {
	return c.setFunctionalLevel(ctx, request, true)
}

func (c *Client) setFunctionalLevel(ctx context.Context, request FunctionalLevelTransitionRequest, forest bool) (FunctionalLevelTransitionResult, error) {
	result := FunctionalLevelTransitionResult{Requested: request.Level, Role: OperationMasterPDCEmulator}
	if forest {
		result.Role = OperationMasterSchemaMaster
	}
	if !knownFunctionalLevel(request.Level) {
		return result, ErrInvalidFunctionalLevel
	}
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	mutation, err := c.objectMutation(ctx, request.Identity, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, resolved IdentityResult, mutation *ObjectMutationResult) error {
		if err := directorySettingsTarget(ctx, session, root, *resolved.Object, forest); err != nil {
			return err
		}
		target, plans, err := prepareOperationMasters(ctx, session, []OperationMasterRole{result.Role})
		if err != nil {
			return err
		}
		result.RoleOwnerDN = plans[0].owner
		if !sameSettingsDN(target, result.RoleOwnerDN) {
			return ErrFunctionalLevelRoleOwner
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		properties := append([]string{"objectGUID", "objectClass", "msDS-Behavior-Version", "nTMixedDomain", "msDS-ExpirePasswordsOnSmartCardOnlyAccounts"}, request.Options.Properties...)
		before, err := functionalLevelRead(ctx, session, mutation.TargetDN, properties, &result)
		if err != nil {
			return err
		}
		value, err := before.Values("objectGUID").Single()
		if err != nil {
			return err
		}
		guid, err := value.GUID()
		if err != nil || guid != *mutation.TargetGUID {
			return errors.Join(ErrInvalidResult, err)
		}
		mutation.Before = &before
		current, err := observedFunctionalLevel(before)
		if err != nil {
			return err
		}
		result.Current = &current
		advertised := root.DomainFunctionality
		if forest {
			advertised = root.ForestFunctionality
		}
		if advertised == nil || FunctionalLevel(*advertised) != current {
			return functionalLevelPrerequisite("RootDSE and the authoritative level attribute disagree or are unavailable")
		}
		if current == request.Level {
			if request.Options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			mutation.After, mutation.ReadbackComplete, mutation.Verified = &before, true, true
			result.Unchanged = true
			return nil
		}
		if request.Level < current && !request.AllowLowering {
			return ErrFunctionalLevelLowering
		}
		if err := functionalLevelPrerequisites(ctx, session, root, before, request.Level, forest, &result); err != nil {
			return err
		}
		result.PreflightComplete = true
		mods := []ldapAttributeModification{{operation: 2, attribute: "msDS-Behavior-Version", values: [][]byte{[]byte(strconv.FormatUint(uint64(request.Level), 10))}}}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(guid), modifications: mods, controls: controls}, false, mutation); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(guid), mutation, objectWriteProperties(request.Options, mods), false); err != nil {
			return err
		}
		return verifyObjectWrite(mutation, mods, "")
	})
	result.Mutation = mutation
	return result, err
}

func knownFunctionalLevel(level FunctionalLevel) bool {
	return level <= FunctionalLevelWindows2016 || level == FunctionalLevelWindows2025
}

func observedFunctionalLevel(object Object) (FunctionalLevel, error) {
	// MS-ADTS defines an absent behavior version as Windows 2000. A missing
	// DC/cross-reference value therefore cannot pass a positive-level guard.
	// The target additionally has to agree with computed RootDSE functionality.
	if object.Values("msDS-Behavior-Version").State == AttributeAbsent {
		return FunctionalLevelWindows2000, nil
	}
	value, err := functionalLevelUint(object, "msDS-Behavior-Version")
	if err != nil {
		return 0, err
	}
	level := FunctionalLevel(value)
	if !knownFunctionalLevel(level) {
		return level, ErrInvalidFunctionalLevel
	}
	return level, nil
}

func functionalLevelUint(object Object, attribute string) (uint32, error) {
	value, err := object.Values(attribute).Single()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", attribute, err)
	}
	parsed, err := parseUint32(string(value.Bytes()))
	if err != nil {
		return 0, fmt.Errorf("%w: malformed %s", ErrInvalidResult, attribute)
	}
	return parsed, nil
}

func functionalLevelRead(ctx context.Context, session directorySession, dn string, properties []string, result *FunctionalLevelTransitionResult) (Object, error) {
	attrs, err := session.baseObject(ctx, dn, properties)
	object := Object{DistinguishedName: dn, Attributes: attrs, RequestedProperties: properties}
	result.Observations = append(result.Observations, object)
	return object, err
}

func functionalLevelSearch(ctx context.Context, session directorySession, query SearchOptions, result *FunctionalLevelTransitionResult) ([]Object, error) {
	query.ResultLimit = 4096
	found, err := searchIdentitySession(ctx, session, query)
	result.Observations = append(result.Observations, found.Objects...)
	if !found.Complete {
		err = errors.Join(err, ErrIncompleteResult)
	}
	return found.Objects, err
}

func functionalLevelPrerequisite(reason string) error {
	return fmt.Errorf("%w: %s", ErrFunctionalLevelPrerequisite, reason)
}
