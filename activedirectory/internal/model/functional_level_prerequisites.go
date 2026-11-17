package model

import (
	"context"
	"errors"
	"strings"
)

func InternalFunctionalLevelPrerequisites(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	before Object,
	target FunctionalLevel,
	forest bool,
	result *FunctionalLevelTransitionResult,
) error {
	if root.SchemaNamingContext == nil || root.ConfigurationNamingContext == nil ||
		root.DSServiceName == nil {
		return ErrInvalidResult
	}
	schema, err := InternalFunctionalLevelRead(
		ctx,
		session,
		*root.SchemaNamingContext,
		[]string{"objectVersion"},
		result,
	)
	if err != nil {
		return err
	}
	version, err := InternalFunctionalLevelUint(schema, "objectVersion")
	if err != nil {
		return err
	}
	result.SchemaVersion = &version
	minimum := map[FunctionalLevel]uint32{
		0:  13,
		1:  30,
		2:  30,
		3:  44,
		4:  47,
		5:  56,
		6:  69,
		7:  87,
		10: 91,
	}
	if version < minimum[target] {
		return InternalFunctionalLevelPrerequisite(
			"schema version is below the target DC release requirement",
		)
	}
	if target < *result.Current {
		if target < FunctionalLevelWindows2008 {
			return InternalFunctionalLevelPrerequisite(
				"rollback below Windows Server 2008 is unsupported",
			)
		}
		if root.DomainControllerFunctionality == nil ||
			*root.DomainControllerFunctionality < uint32(FunctionalLevelWindows2008R2) {
			return InternalFunctionalLevelPrerequisite(
				"this DC does not support lowering functional levels",
			)
		}
	}
	if !forest {
		if root.ForestFunctionality == nil ||
			!InternalKnownFunctionalLevel(FunctionalLevel(*root.ForestFunctionality)) {
			return ErrInvalidResult
		}
		if target < FunctionalLevel(*root.ForestFunctionality) {
			return InternalFunctionalLevelPrerequisite(
				"domain target is below the current forest level",
			)
		}
		if err := InternalFunctionalLevelMixedDomain(before, *result.Current, target); err != nil {
			return err
		}
		if target < FunctionalLevelWindows2016 {
			values := before.Values("msDS-ExpirePasswordsOnSmartCardOnlyAccounts")
			if values.State == AttributePartial {
				return ErrIncompleteResult
			}
			if values.State == AttributePresent {
				value, err := values.Single()
				if err != nil {
					return err
				}
				enabled, err := value.Bool()
				if err != nil {
					return err
				}
				if enabled {
					return InternalFunctionalLevelPrerequisite(
						"smart-card-only account password rolling requires Windows Server 2016",
					)
				}
			}
		}
	}
	controllers, err := InternalFunctionalLevelControllers(
		ctx,
		session,
		root,
		before.DistinguishedName,
		target,
		forest,
		result,
	)
	if err != nil {
		return err
	}
	if forest {
		if err := InternalFunctionalLevelDomains(ctx, session, root, target, result); err != nil {
			return err
		}
	}
	return InternalFunctionalLevelFeatures(
		ctx,
		session,
		root,
		before.DistinguishedName,
		controllers,
		target,
		forest,
		result,
	)
}

func InternalFunctionalLevelMixedDomain(object Object, current, target FunctionalLevel) error {
	if current >= FunctionalLevelWindows2003 || target < FunctionalLevelWindows2003 {
		return nil
	}
	mixed, err := InternalFunctionalLevelUint(object, "nTMixedDomain")
	if err != nil {
		return err
	}
	if mixed != 0 {
		return InternalFunctionalLevelPrerequisite(
			"mixed-mode domain must first be converted to native mode",
		)
	}
	return nil
}

func InternalFunctionalLevelControllers(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	domainDN string,
	target FunctionalLevel,
	forest bool,
	result *FunctionalLevelTransitionResult,
) ([]Object, error) {
	filter := "(|(objectClass=nTDSDSA)(objectClass=nTDSDSARO))"
	if !forest {
		value := InternalLdapLiteral(domainDN)
		filter = "(&" + filter + "(|(msDS-HasDomainNCs=" + value + ")(hasMasterNCs=" + value + ")(msDS-hasMasterNCs=" + value + ")(msDS-hasFullReplicaNCs=" + value + ")))"
	}
	// Replica declarations select relevant DCs in the filter. Do not project
	// those potentially ranged attributes when only the level is consumed.
	controllers, err := InternalFunctionalLevelSearch(
		ctx,
		session,
		SearchOptions{
			Base:       *root.ConfigurationNamingContext,
			Scope:      ScopeSubtree,
			Filter:     filter,
			Properties: []string{"objectClass", "msDS-Behavior-Version"},
		},
		result,
	)
	if err != nil {
		return controllers, err
	}
	ownerFound := false
	for _, controller := range controllers {
		if !InternalFunctionalLevelHasClass(controller, "nTDSDSA") &&
			!InternalFunctionalLevelHasClass(controller, "nTDSDSARO") {
			return controllers, ErrInvalidResult
		}
		ownerFound = ownerFound ||
			InternalSameSettingsDN(controller.DistinguishedName, *root.DSServiceName)
		level, err := InternalObservedFunctionalLevel(controller)
		if err != nil {
			return controllers, err
		}
		if level < target {
			return controllers, InternalFunctionalLevelPrerequisite(
				"a domain controller is below the requested functional level",
			)
		}
		if level >= FunctionalLevelWindows2025 && target < FunctionalLevelWindows2016 {
			return controllers, InternalFunctionalLevelPrerequisite(
				"Windows Server 2025 controllers require at least Windows Server 2016",
			)
		}
	}
	if !ownerFound {
		return controllers, errors.Join(
			ErrIncompleteResult,
			InternalFunctionalLevelPrerequisite(
				"the connected role owner was not returned by the controller search",
			),
		)
	}
	return controllers, nil
}

func InternalFunctionalLevelDomains(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	target FunctionalLevel,
	result *FunctionalLevelTransitionResult,
) error {
	refs, err := InternalFunctionalLevelSearch(
		ctx,
		session,
		SearchOptions{
			Base:   "CN=Partitions," + *root.ConfigurationNamingContext,
			Scope:  ScopeOneLevel,
			Filter: "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))",
			Properties: []string{
				"nCName",
				"msDS-Behavior-Version",
				"nTMixedDomain",
				"systemFlags",
				"enabled",
			},
		},
		result,
	)
	if err != nil {
		return err
	}
	rootFound := false
	for _, ref := range refs {
		name, err := InternalOperationMasterText(ref.Attributes, "nCName")
		if err != nil {
			return err
		}
		if _, err := InternalParseIdentityDN(name); err != nil {
			return errors.Join(ErrInvalidResult, err)
		}
		rootFound = rootFound ||
			(root.RootDomainNamingContext != nil && InternalSameSettingsDN(name, *root.RootDomainNamingContext))
		level, err := InternalObservedFunctionalLevel(ref)
		if err != nil {
			return err
		}
		if level < target {
			return InternalFunctionalLevelPrerequisite(
				"a domain remains below the requested forest level",
			)
		}
		if err := InternalFunctionalLevelMixedDomain(ref, *result.Current, target); err != nil {
			return err
		}
	}
	if !rootFound {
		return errors.Join(
			ErrIncompleteResult,
			InternalFunctionalLevelPrerequisite(
				"forest root domain was not returned by the cross-reference search",
			),
		)
	}
	return nil
}

func InternalFunctionalLevelFeatures(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	targetDN string,
	controllers []Object,
	target FunctionalLevel,
	forest bool,
	result *FunctionalLevelTransitionResult,
) error {
	// Enumerate metadata separately: native Search deliberately reports range
	// descriptions as incomplete. The shared optional-feature reader consumes
	// every backlink range under this same gate, with identity/bounds checks.
	features, err := InternalFunctionalLevelSearch(
		ctx,
		session,
		SearchOptions{
			Base:   *root.ConfigurationNamingContext,
			Scope:  ScopeSubtree,
			Filter: "(&(objectClass=msDS-OptionalFeature)(msDS-EnabledFeatureBL=*))",
			Properties: []string{
				"objectGUID",
				"msDS-RequiredForestBehaviorVersion",
				"msDS-RequiredDomainBehaviorVersion",
				"msDS-OptionalFeatureGUID",
			},
		},
		result,
	)
	if err != nil {
		return err
	}
	for _, feature := range features {
		value, err := feature.Values("objectGUID").Single()
		if err != nil {
			return err
		}
		guid, err := value.GUID()
		if err != nil {
			return err
		}
		guidText := guid.String()
		observed := OptionalFeature{
			DistinguishedName: feature.DistinguishedName,
			ObjectGUID:        &guidText,
		}
		err = InternalReadOptionalFeatureScopes(ctx, session, &observed)
		result.Observations = append(result.Observations, observed.EnabledScopeObjects...)
		if err != nil {
			return err
		}
		if observed.EnabledScopesState != AttributePresent || len(observed.EnabledScopes) == 0 {
			return errors.Join(ErrIncompleteResult, ErrAttributeUnavailable)
		}
		relevant := forest
		for _, scope := range observed.EnabledScopes {
			if _, err := InternalParseIdentityDN(scope); err != nil {
				return errors.Join(ErrInvalidResult, err)
			}
			relevant = relevant || InternalSameSettingsDN(scope, targetDN)
			for _, controller := range controllers {
				relevant = relevant || InternalSameSettingsDN(scope, controller.DistinguishedName)
			}
		}
		if !relevant {
			continue
		}
		attribute := "msDS-RequiredDomainBehaviorVersion"
		if forest {
			attribute = "msDS-RequiredForestBehaviorVersion"
		}
		required := feature.Values(attribute)
		if required.State == AttributePartial {
			return ErrIncompleteResult
		}
		// These attributes are optional when that feature has no corresponding
		// level requirement. Missing values remain in the raw observation; the
		// server's write-time feature constraints remain authoritative.
		if required.State != AttributePresent {
			continue
		}
		level, err := InternalFunctionalLevelUint(feature, attribute)
		if err != nil {
			return err
		}
		if !InternalKnownFunctionalLevel(FunctionalLevel(level)) ||
			FunctionalLevel(level) > target {
			return InternalFunctionalLevelPrerequisite(
				"an enabled optional feature requires a higher level",
			)
		}
	}
	return nil
}

func InternalFunctionalLevelHasClass(object Object, class string) bool {
	for _, value := range object.Attributes["objectclass"] {
		if strings.EqualFold(string(value), class) {
			return true
		}
	}
	return false
}
