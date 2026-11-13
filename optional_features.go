package activedirectory

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrInvalidOptionalFeature      = errors.New("invalid optional feature request")
	ErrOptionalFeatureScope        = errors.New("optional feature is not supported at the requested scope")
	ErrOptionalFeaturePrerequisite = errors.New("optional feature prerequisite is not satisfied")
	ErrOptionalFeatureRole         = errors.New("connect to the domain naming master for this configuration")
	ErrOptionalFeatureIrreversible = errors.New("optional feature cannot be disabled; enabling requires explicit acknowledgement")
	ErrOptionalFeaturePermission   = errors.New("optional feature access denied")
	ErrOptionalFeatureUncertain    = errors.New("optional feature write outcome is unknown; reconcile before another write")
	ErrOptionalFeatureReadback     = errors.New("optional feature readback did not verify the requested state")
)

type OptionalFeatureFlags uint32

const (
	OptionalFeatureForestFlag     OptionalFeatureFlags = 1
	OptionalFeatureDomainFlag     OptionalFeatureFlags = 2
	OptionalFeatureDisablableFlag OptionalFeatureFlags = 4
	OptionalFeatureServerFlag     OptionalFeatureFlags = 8
)

type OptionalFeatureScope string

const (
	OptionalFeatureForest OptionalFeatureScope = "ForestOrConfigurationSet"
	OptionalFeatureDomain OptionalFeatureScope = "Domain"
	OptionalFeatureServer OptionalFeatureScope = "Server"
)

const (
	OptionalFeatureRecycleBinGUID       = "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a"
	OptionalFeaturePAMGUID              = "ec43e873-cce8-4640-b4ab-07ffe4ab5bcd"
	OptionalFeatureDatabase32KPagesGUID = "52982ac6-1e73-754f-ae24-73ae2775aab8"
)

// OptionalFeature preserves unknown flags and missing properties. EnabledScopes
// are observations, not proof that an omitted backlink is empty. Raw retains
// metadata; EnabledScopeObjects retains unmerged backlink range responses.
type OptionalFeature struct {
	DistinguishedName   string
	Name                *string
	ObjectGUID          *string
	FeatureGUID         *string
	Flags               *OptionalFeatureFlags
	Disablable          *bool
	Scopes              []OptionalFeatureScope
	RequiredForestLevel *uint32
	RequiredDomainLevel *uint32
	EnabledScopes       []string
	EnabledScopesState  AttributeState
	// EnabledScopeObjects retains each unmerged backlink response, including
	// failed or malformed continuations. Raw remains the metadata search row.
	EnabledScopeObjects []Object
	Raw                 Object
}

// OptionalFeatureQuery selects at most one identity/filter; zero selects all.
// GUID selectors use binary LDAP equality. LDAPFilter uses LDAP syntax, not
// PowerShell expressions. ResultLimit is explicit and never means completion.
type OptionalFeatureQuery struct {
	DistinguishedName string
	Name              string
	FeatureGUID       string
	ObjectGUID        string
	LDAPFilter        string
	PageSize          int
	ResultLimit       int
}

func (q OptionalFeatureQuery) Validate() error {
	count := 0
	for _, value := range []string{q.DistinguishedName, q.Name, q.FeatureGUID, q.ObjectGUID, q.LDAPFilter} {
		if !validDirectoryText(value) {
			return ErrInvalidOptionalFeature
		}
		if value != "" {
			count++
		}
	}
	if count > 1 || q.PageSize < 0 || q.ResultLimit < 0 {
		return ErrInvalidOptionalFeature
	}
	for _, guid := range []string{q.FeatureGUID, q.ObjectGUID} {
		if guid != "" {
			if _, err := optionalFeatureGUIDBytes(guid); err != nil {
				return err
			}
		}
	}
	return (SearchOptions{PageSize: q.PageSize, ResultLimit: q.ResultLimit}).Validate()
}

type OptionalFeaturesResult struct {
	Features     []OptionalFeature
	Observation  DirectoryObservation
	Complete     bool
	LimitReached bool
}

func optionalFeatureProperties() []string {
	return []string{"distinguishedName", "name", "objectClass", "objectGUID", "msDS-OptionalFeatureGUID", "msDS-OptionalFeatureFlags", "msDS-RequiredForestBehaviorVersion", "msDS-RequiredDomainBehaviorVersion", "msDS-EnabledFeatureBL"}
}

// OptionalFeatures reads the configuration's Optional Features container on
// this authenticated endpoint. Backlink ranges continue on this connection.
// A complete read does not establish that every attribute was visible.
func (c *Client) OptionalFeatures(ctx context.Context, query OptionalFeatureQuery) (OptionalFeaturesResult, error) {
	var result OptionalFeaturesResult
	if err := query.Validate(); err != nil {
		return result, err
	}
	err := c.read(ctx, func(bounded context.Context) error {
		root, err := optionalFeatureRoot(bounded, c.session)
		result.Observation.Source = c.config.Endpoint
		result.Observation.RootDSE = root
		if err != nil {
			return err
		}
		search, searchErr := optionalFeatureSearch(bounded, c.session, root, query)
		err = searchErr
		result.LimitReached = search.LimitReached
		result.Observation.Objects = search.Objects
		for _, object := range search.Objects {
			feature, decodeErr := decodeOptionalFeature(object)
			if searchErr == nil && decodeErr == nil {
				decodeErr = readOptionalFeatureScopes(bounded, c.session, &feature)
				result.Observation.Objects = append(result.Observation.Objects, feature.EnabledScopeObjects...)
			}
			result.Features = append(result.Features, feature)
			err = errors.Join(err, decodeErr)
		}
		result.Complete = search.Complete && err == nil
		return err
	})
	result.Complete = result.Complete && err == nil
	result.Observation.Complete = result.Complete
	return result, err
}

func optionalFeatureRoot(ctx context.Context, session directorySession) (RootDSE, error) {
	attrs, err := session.baseObject(ctx, "", defaultRootDSEAttributes())
	root, decodeErr := decodeRootDSE(attrs, defaultRootDSEAttributes())
	err = errors.Join(err, decodeErr)
	if root.Capabilities().Type == DirectoryUnknown {
		err = errors.Join(err, ErrOptionalFeaturePrerequisite)
	}
	if root.ConfigurationNamingContext == nil || *root.ConfigurationNamingContext == "" {
		err = errors.Join(err, ErrIncompleteResult)
	}
	return root, err
}

func optionalFeatureSearch(ctx context.Context, session directorySession, root RootDSE, query OptionalFeatureQuery) (SearchResult, error) {
	container := "CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + *root.ConfigurationNamingContext
	// Keep paged metadata enumeration independent of value ranges. Public
	// Search intentionally reports ranged rows as incomplete; each backlink
	// sequence is read below using a base-object consumer on this same gate.
	properties := slices.DeleteFunc(optionalFeatureProperties(), func(name string) bool { return strings.EqualFold(name, "msDS-EnabledFeatureBL") })
	options := SearchOptions{Base: container, Scope: ScopeOneLevel, Filter: "(objectClass=msDS-OptionalFeature)", Properties: properties, PageSize: query.PageSize, ResultLimit: query.ResultLimit}
	filter := ""
	switch {
	case query.DistinguishedName != "":
		parent, err := parentDirectoryDN(query.DistinguishedName)
		if err != nil || !strings.EqualFold(parent, container) {
			return SearchResult{}, ErrInvalidOptionalFeature
		}
		options.Base = query.DistinguishedName
		options.Scope = ScopeBase
	case query.Name != "":
		filter = "(name=" + ldapLiteral(query.Name) + ")"
	case query.FeatureGUID != "" || query.ObjectGUID != "":
		name, value := "msDS-OptionalFeatureGUID", query.FeatureGUID
		if value == "" {
			name, value = "objectGUID", query.ObjectGUID
		}
		bytes, err := optionalFeatureGUIDBytes(value)
		if err != nil {
			return SearchResult{}, err
		}
		var escaped strings.Builder
		for _, b := range bytes {
			fmt.Fprintf(&escaped, "\\%02x", b)
		}
		filter = "(" + name + "=" + escaped.String() + ")"
	case query.LDAPFilter != "":
		filter = query.LDAPFilter
	}
	if filter != "" {
		options.Filter = "(&" + options.Filter + filter + ")"
	}
	options, err := options.normalized()
	if err != nil {
		return SearchResult{}, err
	}
	cursor, err := session.startSearch(ctx, options)
	if err != nil {
		return SearchResult{}, err
	}
	result, err := collectSearch(ctx, cursor, options)
	if err != nil {
		result.Complete = false
		return result, &SearchError{Returned: len(result.Objects), Cause: err}
	}
	return result, nil
}

func decodeOptionalFeature(object Object) (OptionalFeature, error) {
	d := rootDSEDecoder{attributes: object.Attributes}
	feature := OptionalFeature{DistinguishedName: object.DistinguishedName, Raw: object}
	_, classErr := operationMasterObject(object.Attributes, "msDS-OptionalFeature")
	feature.Name = d.text("name")
	for name, destination := range map[string]**string{"objectGUID": &feature.ObjectGUID, "msDS-OptionalFeatureGUID": &feature.FeatureGUID} {
		value := copiedBinary(&d, name, 16)
		if value != nil {
			text := optionalFeatureGUIDString(value)
			*destination = &text
		}
	}
	if flags := decodeScalar(&d, "msDS-OptionalFeatureFlags", parseDirectoryMask); flags != nil {
		value := OptionalFeatureFlags(*flags)
		feature.Flags = &value
		disablable := value&OptionalFeatureDisablableFlag != 0
		feature.Disablable = &disablable
		for _, scope := range []OptionalFeatureScope{OptionalFeatureForest, OptionalFeatureDomain, OptionalFeatureServer} {
			if value&optionalFeatureScopeFlag(scope) != 0 {
				feature.Scopes = append(feature.Scopes, scope)
			}
		}
	}
	feature.RequiredForestLevel = decodeScalar(&d, "msDS-RequiredForestBehaviorVersion", parseUint32)
	feature.RequiredDomainLevel = decodeScalar(&d, "msDS-RequiredDomainBehaviorVersion", parseUint32)
	feature.EnabledScopes = d.texts("msDS-EnabledFeatureBL")
	_, feature.EnabledScopesState = object.Attribute("msDS-EnabledFeatureBL")
	var rangeErr error
	for name := range object.Attributes {
		if strings.Contains(name, ";range=") {
			rangeErr = ErrIncompleteResult
		}
	}
	return feature, errors.Join(classErr, rangeErr, errors.Join(d.errors...))
}

func optionalFeatureScopeFlag(scope OptionalFeatureScope) OptionalFeatureFlags {
	switch scope {
	case OptionalFeatureForest:
		return OptionalFeatureForestFlag
	case OptionalFeatureDomain:
		return OptionalFeatureDomainFlag
	case OptionalFeatureServer:
		return OptionalFeatureServerFlag
	}
	return 0
}

func optionalFeatureGUIDBytes(value string) ([]byte, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return nil, ErrInvalidOptionalFeature
	}
	bytes, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(bytes) != 16 || slices.Equal(bytes, make([]byte, 16)) {
		return nil, ErrInvalidOptionalFeature
	}
	slices.Reverse(bytes[:4])
	slices.Reverse(bytes[4:6])
	slices.Reverse(bytes[6:8])
	return bytes, nil
}

func optionalFeatureGUIDString(value []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%x", binary.LittleEndian.Uint32(value), binary.LittleEndian.Uint16(value[4:]), binary.LittleEndian.Uint16(value[6:]), value[8], value[9], value[10:])
}
