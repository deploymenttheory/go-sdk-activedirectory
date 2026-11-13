package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

var (
	ErrInvalidDirectorySettings = errors.New("invalid domain or forest settings")
	ErrDirectorySettingsTarget  = errors.New("domain or forest settings require the corresponding AD DS naming context on a writable LDAP endpoint")
)

func sameSettingsDN(left, right string) bool {
	a, err := parseIdentityDN(left)
	if err != nil {
		return false
	}
	b, err := parseIdentityDN(right)
	return err == nil && sameIdentityDN(a, b)
}

// UpdateDomainRequest identifies the connected DC's domain NC root by DN or
// GUID. Nil typed fields are omitted. A non-nil empty suffix slice clears that
// attribute; Changes supplies exact add/remove/clear and raw binary operations.
// Typed and raw changes for the same attribute conflict. Raw changes cannot
// alter functional levels, role ownership, or object identity through this API.
type UpdateDomainRequest struct {
	Identity           Identity
	AllowedDNSSuffixes *[]string
	// LastLogonReplicationIntervalDays is the LDAP integer number of days,
	// including explicit zero (schema rangeLower=0). No duration is rounded.
	LastLogonReplicationIntervalDays *uint32
	ManagedByDN                      *string
	PublicKeyRequiredPasswordRolling *bool
	Changes                          []AttributeChange
	Options                          ObjectMutationOptions
}

// UpdateForestRequest identifies CN=Partitions in this connection's
// configuration NC by DN or GUID. GUID identities need the configuration NC
// in Options.Partition. The suffix fields replace their entire value set;
// use Changes for exact add/remove, and omit nil fields to preserve values.
type UpdateForestRequest struct {
	Identity    Identity
	UPNSuffixes *[]string
	SPNSuffixes *[]string
	Changes     []AttributeChange
	Options     ObjectMutationOptions
}

// UpdateDomain submits one LDAP Modify, retaining server diagnostics and the
// shared accepted/rejected/uncertain result. It does not contact another DC.
func (c *Client) UpdateDomain(ctx context.Context, request UpdateDomainRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	changes, err := domainSettingsChanges(request)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	return c.updateDirectorySettings(ctx, request.Identity, request.Options, changes, false)
}

// UpdateForest changes suffix settings on this forest's Partitions container.
// It does not change trust routing, DNS records, account names, or SPNs on users.
func (c *Client) UpdateForest(ctx context.Context, request UpdateForestRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	changes := append([]AttributeChange(nil), request.Changes...)
	for _, value := range []struct {
		name   string
		values *[]string
	}{{"uPNSuffixes", request.UPNSuffixes}, {"msDS-SPNSuffixes", request.SPNSuffixes}} {
		if value.values != nil {
			change, err := directorySuffixChange(value.name, *value.values)
			if err != nil {
				return ObjectMutationResult{}, err
			}
			changes = append(changes, change)
		}
	}
	return c.updateDirectorySettings(ctx, request.Identity, request.Options, changes, true)
}

func domainSettingsChanges(request UpdateDomainRequest) ([]AttributeChange, error) {
	changes := append([]AttributeChange(nil), request.Changes...)
	if request.AllowedDNSSuffixes != nil {
		change, err := directorySuffixChange("msDS-AllowedDNSSuffixes", *request.AllowedDNSSuffixes)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	if days := request.LastLogonReplicationIntervalDays; days != nil {
		if *days > math.MaxInt32 {
			return nil, ErrInvalidDirectorySettings
		}
		changes = append(changes, directorySetting("msDS-LogonTimeSyncInterval", strconv.FormatUint(uint64(*days), 10)))
	}
	if dn := request.ManagedByDN; dn != nil {
		if _, err := parseIdentityDN(*dn); err != nil {
			return nil, errors.Join(ErrInvalidDirectorySettings, err)
		}
		changes = append(changes, directorySetting("managedBy", *dn))
	}
	if rolling := request.PublicKeyRequiredPasswordRolling; rolling != nil {
		value := "FALSE"
		if *rolling {
			value = "TRUE"
		}
		changes = append(changes, directorySetting("msDS-ExpirePasswordsOnSmartCardOnlyAccounts", value))
	}
	return changes, nil
}

func directorySetting(attribute, value string) AttributeChange {
	return AttributeChange{Attribute: attribute, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(value))}}
}

func directorySuffixChange(attribute string, values []string) (AttributeChange, error) {
	change := AttributeChange{Attribute: attribute, Kind: AttributeClear}
	if len(values) != 0 {
		change.Kind = AttributeSet
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		// Do not perform DNS lookup, IDNA conversion or case normalization.
		// The directory schema/server remain authoritative for suffix syntax.
		if value == "" || !validDirectoryText(value) || seen[strings.ToLower(value)] {
			return change, ErrInvalidDirectorySettings
		}
		seen[strings.ToLower(value)] = true
		change.Values = append(change.Values, NewRawValue([]byte(value)))
	}
	return change, nil
}

func directorySettingsModifications(changes []AttributeChange, forest bool) ([]ldapAttributeModification, error) {
	for _, change := range changes {
		name := strings.ToLower(change.Attribute)
		if forest && name != "upnsuffixes" && name != "msds-spnsuffixes" {
			return nil, fmt.Errorf("%w: forest suffix settings only", ErrInvalidDirectorySettings)
		}
		switch name {
		case "msds-behavior-version", "ntmixeddomain", "fsmoroleowner", "objectguid", "objectsid", "objectclass", "distinguishedname", "instancetype", "ridmanagerreference", "msds-enabledfeature":
			return nil, fmt.Errorf("%w: %s requires its dedicated operation", ErrInvalidDirectorySettings, change.Attribute)
		}
	}
	mods, err := objectChanges(changes)
	return mods, errors.Join(err)
}

func (c *Client) updateDirectorySettings(ctx context.Context, identity Identity, options ObjectMutationOptions, changes []AttributeChange, forest bool) (ObjectMutationResult, error) {
	mods, err := directorySettingsModifications(changes, forest)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	return c.objectMutation(ctx, identity, options, func(ctx context.Context, session ldapWriteSession, root RootDSE, resolved IdentityResult, result *ObjectMutationResult) error {
		if err := directorySettingsTarget(ctx, session, root, *resolved.Object, forest); err != nil {
			return err
		}
		for _, mod := range mods {
			if strings.EqualFold(mod.attribute, "msDS-ExpirePasswordsOnSmartCardOnlyAccounts") && mod.operation != 1 && len(mod.values) == 1 && strings.EqualFold(string(mod.values[0]), "TRUE") && (root.DomainFunctionality == nil || *root.DomainFunctionality < uint32(FunctionalLevelWindows2016)) {
				return functionalLevelPrerequisite("smart-card-only account password rolling requires Windows Server 2016")
			}
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: mods, controls: controls}, false, result); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(options, mods), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, mods, "")
	})
}

func directorySettingsTarget(ctx context.Context, session directorySession, root RootDSE, object Object, forest bool) error {
	if err := root.Capabilities().RequireADDS("domain and forest settings"); err != nil {
		return err
	}
	expected, class := root.DefaultNamingContext, "domainDNS"
	if forest {
		if root.ConfigurationNamingContext == nil {
			return ErrDirectorySettingsTarget
		}
		value := "CN=Partitions," + *root.ConfigurationNamingContext
		expected, class = &value, "crossRefContainer"
	}
	if expected == nil || !sameSettingsDN(object.DistinguishedName, *expected) {
		return ErrDirectorySettingsTarget
	}
	decoder := rootDSEDecoder{attributes: object.Attributes}
	classes := decoder.texts("objectClass")
	if len(decoder.errors) != 0 {
		return errors.Join(decoder.errors...)
	}
	found := false
	for _, value := range classes {
		found = found || strings.EqualFold(value, class)
	}
	if !found {
		return ErrDirectorySettingsTarget
	}
	_, _, err := prepareOperationMasters(ctx, session, nil)
	return err
}
