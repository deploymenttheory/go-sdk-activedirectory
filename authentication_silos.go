package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalidAuthenticationSilo = errors.New("invalid authentication silo request")
	ErrNotAuthenticationSilo     = errors.New("object is not an authentication silo in this forest's silo container")
	ErrAuthenticationSiloGrant   = errors.New("account's permission to join the silo was not observed")
	ErrAuthenticationSiloChanged = errors.New("authentication silo changed during linked-value retrieval")
)

const siloMembersAttribute = "msDS-AuthNPolicySiloMembers"
const siloAssignedAttribute = "msDS-AssignedAuthNPolicySiloBL"

type AuthenticationPolicySilo struct {
	DistinguishedName                                                                   string
	GUID                                                                                *GUID
	Name, Description                                                                   *string
	Enforced                                                                            *bool
	UserAuthenticationPolicy, ComputerAuthenticationPolicy, ServiceAuthenticationPolicy *string
	ProtectedFromAccidentalDeletion                                                     *bool
	Raw                                                                                 Object
}

// AuthenticationSiloLinks describes one linked attribute, not effective access.
// Complete means all server-visible ranges were read without an observed change.
// AttributeReturned=false never proves that ACL-hidden links do not exist.
type AuthenticationSiloLinks struct {
	DistinguishedNames                        []string
	AttributeReturned, Complete, LimitReached bool
	Observations                              []Object
}

type AuthenticationPolicySiloReadOptions struct {
	ResolveIdentityOptions
	// MaxMembers bounds each linked set. Zero defaults to 16384; maximum 1048576.
	MaxMembers int
}

type AuthenticationPolicySiloSearchOptions struct {
	SearchOptions
	MaxMembers int
}

type AuthenticationPolicySiloResult struct {
	Silo        *AuthenticationPolicySilo
	Observation IdentityResult
	// Members are grants. AssignedAccounts are backlinks from account assignment.
	Members, AssignedAccounts AuthenticationSiloLinks
	Protection                OUProtectionResult
}

type AuthenticationPolicySilosResult struct {
	Silos       []AuthenticationPolicySiloResult
	Observation SearchResult
}

func authenticationSiloProperties(extra []string) []string {
	properties := slices.DeleteFunc(slices.Clone(extra), func(name string) bool {
		return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") || strings.EqualFold(name, siloMembersAttribute) || strings.EqualFold(name, siloAssignedAttribute)
	})
	return append(properties, "objectGUID", "objectClass", "uSNChanged", "name", "description", "msDS-AuthNPolicySiloEnforced", "msDS-UserAuthNPolicy", "msDS-ComputerAuthNPolicy", "msDS-ServiceAuthNPolicy")
}

func authenticationSiloContainer(root RootDSE) (string, error) {
	if _, err := authenticationPolicyContainer(root); err != nil {
		return "", err
	}
	return "CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services," + *root.ConfigurationNamingContext, nil
}

func authenticationSiloScope(root RootDSE, object Object) error {
	container, err := authenticationSiloContainer(root)
	if err != nil {
		return err
	}
	parts, err := splitIdentityDN(object.DistinguishedName, ',')
	if err != nil || len(parts) < 2 || !sameAuthenticationDN(strings.Join(parts[1:], ","), container) {
		return ErrNotAuthenticationSilo
	}
	classes, state := object.Attribute("objectClass")
	if state != AttributePresent || !slices.ContainsFunc(classes, func(value []byte) bool { return strings.EqualFold(string(value), "msDS-AuthNPolicySilo") }) {
		return ErrNotAuthenticationSilo
	}
	return nil
}

func decodeAuthenticationSilo(object Object) (AuthenticationPolicySilo, error) {
	result := AuthenticationPolicySilo{DistinguishedName: object.DistinguishedName, Raw: object}
	d := rootDSEDecoder{attributes: object.Attributes}
	result.Name, result.Description = d.text("name"), d.text("description")
	result.Enforced = decodeScalar(&d, "msDS-AuthNPolicySiloEnforced", parseLDAPBool)
	result.UserAuthenticationPolicy = d.text("msDS-UserAuthNPolicy")
	result.ComputerAuthenticationPolicy = d.text("msDS-ComputerAuthNPolicy")
	result.ServiceAuthenticationPolicy = d.text("msDS-ServiceAuthNPolicy")
	value, err := object.Values("objectGUID").Single()
	if err == nil {
		var guid GUID
		guid, err = value.GUID()
		if err == nil {
			result.GUID = &guid
		}
	}
	return result, errors.Join(errors.Join(d.errors...), err)
}

func authenticationSiloLimit(limit int) (int, error) {
	if limit < 0 || limit > 1048576 {
		return 0, ErrInvalidAuthenticationSilo
	}
	if limit == 0 {
		limit = 16384
	}
	return limit, nil
}

func (c *Client) AuthenticationPolicySilo(ctx context.Context, identity Identity, options AuthenticationPolicySiloReadOptions) (AuthenticationPolicySiloResult, error) {
	var result AuthenticationPolicySiloResult
	if options.Target != IdentityTargetObject {
		return result, ErrUnsupportedIdentity
	}
	protection := authenticationProtectionRequested(options.Properties)
	options.Properties = authenticationSiloProperties(options.Properties)
	if err := validateIdentityOperation(identity, options.ResolveIdentityOptions); err != nil {
		return result, err
	}
	limit, err := authenticationSiloLimit(options.MaxMembers)
	if err != nil {
		return result, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if _, err := authenticationSiloContainer(root); err != nil {
			return err
		}
		if options.Partition != "" && !sameAuthenticationDN(options.Partition, *root.ConfigurationNamingContext) {
			return ErrIdentityScope
		}
		options.Partition = *root.ConfigurationNamingContext
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options.ResolveIdentityOptions)
		if err != nil {
			return err
		}
		properties := options.Properties
		if protection {
			properties = append(slices.Clone(properties), "ProtectedFromAccidentalDeletion")
		}
		return readAuthenticationSilo(ctx, c.session, c.config, root, *result.Observation.Object, limit, properties, &result)
	})
	return result, err
}

func readAuthenticationSilo(ctx context.Context, session directorySession, config Config, root RootDSE, object Object, limit int, properties []string, result *AuthenticationPolicySiloResult) error {
	if err := authenticationSiloScope(root, object); err != nil {
		return err
	}
	silo, err := decodeAuthenticationSilo(object)
	result.Silo = &silo
	if err != nil {
		return err
	}
	result.Members, err = readAuthenticationSiloLinks(ctx, session, object, siloMembersAttribute, limit)
	if err != nil {
		return err
	}
	result.AssignedAccounts, err = readAuthenticationSiloLinks(ctx, session, object, siloAssignedAttribute, limit)
	if err != nil {
		return err
	}
	if authenticationProtectionRequested(properties) {
		result.Protection, err = readOUProtection(ctx, session, root, config, OrganizationalUnit{DistinguishedName: silo.DistinguishedName, GUID: silo.GUID}, *root.ConfigurationNamingContext)
		result.Silo.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
	}
	return err
}

func (c *Client) AuthenticationPolicySilos(ctx context.Context, options AuthenticationPolicySiloSearchOptions) (AuthenticationPolicySilosResult, error) {
	var result AuthenticationPolicySilosResult
	protection := authenticationProtectionRequested(options.Properties)
	options.Properties = authenticationSiloProperties(options.Properties)
	if err := options.SearchOptions.Validate(); err != nil {
		return result, err
	}
	limit, err := authenticationSiloLimit(options.MaxMembers)
	if err != nil {
		return result, err
	}
	if !options.TypedFilter.unset() {
		options.TypedFilter = FilterAnd(FilterEqual("objectClass", FilterText("msDS-AuthNPolicySilo")), options.TypedFilter)
	} else if options.Filter == "" {
		options.Filter = "(objectClass=msDS-AuthNPolicySilo)"
	} else {
		options.Filter = "(&(objectClass=msDS-AuthNPolicySilo)" + options.Filter + ")"
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		container, err := authenticationSiloContainer(root)
		if err != nil {
			return err
		}
		if options.Base == "" {
			options.Base, options.Scope = container, ScopeOneLevel
		}
		base, err := parseIdentityDN(options.Base)
		if err != nil {
			return err
		}
		parent, _ := parseIdentityDN(container)
		if !identityWithin(base, parent) {
			return ErrIdentityScope
		}
		result.Observation, err = searchIdentitySession(ctx, c.session, options.SearchOptions)
		searchErr := err
		properties := options.Properties
		if protection {
			properties = append(slices.Clone(properties), "ProtectedFromAccidentalDeletion")
		}
		for _, object := range result.Observation.Objects {
			row := AuthenticationPolicySiloResult{Observation: IdentityResult{Object: &object, Candidates: []Object{object}, Complete: searchErr == nil}}
			if searchErr == nil {
				err = errors.Join(err, readAuthenticationSilo(ctx, c.session, c.config, root, object, limit, properties, &row))
			} else {
				silo, decodeErr := decodeAuthenticationSilo(object)
				row.Silo = &silo
				err = errors.Join(err, decodeErr)
			}
			result.Silos = append(result.Silos, row)
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}
