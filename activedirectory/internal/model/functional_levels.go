package model

import (
	"context"
	"errors"
	"fmt"
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
	ErrInvalidFunctionalLevel   = errors.New("unknown or invalid functional level")
	ErrFunctionalLevelRoleOwner = errors.New(
		"functional-level transition requires the authoritative role owner",
	)
	ErrFunctionalLevelPrerequisite = errors.New("functional-level prerequisite is not satisfied")
	ErrFunctionalLevelLowering     = errors.New(
		"lowering a functional level requires explicit AllowLowering",
	)
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

func InternalKnownFunctionalLevel(level FunctionalLevel) bool {
	return level <= FunctionalLevelWindows2016 || level == FunctionalLevelWindows2025
}

func InternalObservedFunctionalLevel(object Object) (FunctionalLevel, error) {
	// MS-ADTS defines an absent behavior version as Windows 2000. A missing
	// DC/cross-reference value therefore cannot pass a positive-level guard.
	// The target additionally has to agree with computed RootDSE functionality.
	if object.Values("msDS-Behavior-Version").State == AttributeAbsent {
		return FunctionalLevelWindows2000, nil
	}
	value, err := InternalFunctionalLevelUint(object, "msDS-Behavior-Version")
	if err != nil {
		return 0, err
	}
	level := FunctionalLevel(value)
	if !InternalKnownFunctionalLevel(level) {
		return level, ErrInvalidFunctionalLevel
	}
	return level, nil
}

func InternalFunctionalLevelUint(object Object, attribute string) (uint32, error) {
	value, err := object.Values(attribute).Single()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", attribute, err)
	}
	parsed, err := InternalParseUint32(string(value.Bytes()))
	if err != nil {
		return 0, fmt.Errorf("%w: malformed %s", ErrInvalidResult, attribute)
	}
	return parsed, nil
}

func InternalFunctionalLevelRead(
	ctx context.Context,
	session InternalDirectorySession,
	dn string,
	properties []string,
	result *FunctionalLevelTransitionResult,
) (Object, error) {
	attrs, err := session.InternalBaseObject(ctx, dn, properties)
	object := Object{DistinguishedName: dn, Attributes: attrs, RequestedProperties: properties}
	result.Observations = append(result.Observations, object)
	return object, err
}

func InternalFunctionalLevelSearch(
	ctx context.Context,
	session InternalDirectorySession,
	query SearchOptions,
	result *FunctionalLevelTransitionResult,
) ([]Object, error) {
	query.ResultLimit = 4096
	found, err := InternalSearchIdentitySession(ctx, session, query)
	result.Observations = append(result.Observations, found.Objects...)
	if !found.Complete {
		err = errors.Join(err, ErrIncompleteResult)
	}
	return found.Objects, err
}

func InternalFunctionalLevelPrerequisite(reason string) error {
	return fmt.Errorf("%w: %s", ErrFunctionalLevelPrerequisite, reason)
}
