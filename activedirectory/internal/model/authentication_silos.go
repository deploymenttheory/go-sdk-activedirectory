package model

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalidAuthenticationSilo = errors.New("invalid authentication silo request")
	ErrNotAuthenticationSilo     = errors.New(
		"object is not an authentication silo in this forest's silo container",
	)
	ErrAuthenticationSiloGrant = errors.New(
		"account's permission to join the silo was not observed",
	)
	ErrAuthenticationSiloChanged = errors.New(
		"authentication silo changed during linked-value retrieval",
	)
)

const (
	InternalSiloMembersAttribute  = "msDS-AuthNPolicySiloMembers"
	InternalSiloAssignedAttribute = "msDS-AssignedAuthNPolicySiloBL"
)

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

func InternalAuthenticationSiloProperties(extra []string) []string {
	properties := slices.DeleteFunc(slices.Clone(extra), func(name string) bool {
		return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") ||
			strings.EqualFold(name, InternalSiloMembersAttribute) ||
			strings.EqualFold(name, InternalSiloAssignedAttribute)
	})
	return append(
		properties,
		"objectGUID",
		"objectClass",
		"uSNChanged",
		"name",
		"description",
		"msDS-AuthNPolicySiloEnforced",
		"msDS-UserAuthNPolicy",
		"msDS-ComputerAuthNPolicy",
		"msDS-ServiceAuthNPolicy",
	)
}

func InternalAuthenticationSiloContainer(root RootDSE) (string, error) {
	if _, err := InternalAuthenticationPolicyContainer(root); err != nil {
		return "", err
	}
	return "CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services," + *root.ConfigurationNamingContext, nil
}

func InternalAuthenticationSiloScope(root RootDSE, object Object) error {
	container, err := InternalAuthenticationSiloContainer(root)
	if err != nil {
		return err
	}
	parts, err := InternalSplitIdentityDN(object.DistinguishedName, ',')
	if err != nil || len(parts) < 2 ||
		!InternalSameAuthenticationDN(strings.Join(parts[1:], ","), container) {
		return ErrNotAuthenticationSilo
	}
	classes, state := object.Attribute("objectClass")
	if state != AttributePresent ||
		!slices.ContainsFunc(
			classes,
			func(value []byte) bool { return strings.EqualFold(string(value), "msDS-AuthNPolicySilo") },
		) {
		return ErrNotAuthenticationSilo
	}
	return nil
}

func InternalDecodeAuthenticationSilo(object Object) (AuthenticationPolicySilo, error) {
	result := AuthenticationPolicySilo{DistinguishedName: object.DistinguishedName, Raw: object}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.Name, result.Description = d.InternalText("name"), d.InternalText("description")
	result.Enforced = InternalDecodeScalar(
		&d,
		"msDS-AuthNPolicySiloEnforced",
		InternalParseLDAPBool,
	)
	result.UserAuthenticationPolicy = d.InternalText("msDS-UserAuthNPolicy")
	result.ComputerAuthenticationPolicy = d.InternalText("msDS-ComputerAuthNPolicy")
	result.ServiceAuthenticationPolicy = d.InternalText("msDS-ServiceAuthNPolicy")
	value, err := object.Values("objectGUID").Single()
	if err == nil {
		var guid GUID
		guid, err = value.GUID()
		if err == nil {
			result.GUID = &guid
		}
	}
	return result, errors.Join(errors.Join(d.InternalErrors...), err)
}

func InternalAuthenticationSiloLimit(limit int) (int, error) {
	if limit < 0 || limit > 1048576 {
		return 0, ErrInvalidAuthenticationSilo
	}
	if limit == 0 {
		limit = 16384
	}
	return limit, nil
}

func InternalReadAuthenticationSilo(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
	object Object,
	limit int,
	properties []string,
	result *AuthenticationPolicySiloResult,
) error {
	if err := InternalAuthenticationSiloScope(root, object); err != nil {
		return err
	}
	silo, err := InternalDecodeAuthenticationSilo(object)
	result.Silo = &silo
	if err != nil {
		return err
	}
	result.Members, err = InternalReadAuthenticationSiloLinks(
		ctx,
		session,
		object,
		InternalSiloMembersAttribute,
		limit,
	)
	if err != nil {
		return err
	}
	result.AssignedAccounts, err = InternalReadAuthenticationSiloLinks(
		ctx,
		session,
		object,
		InternalSiloAssignedAttribute,
		limit,
	)
	if err != nil {
		return err
	}
	if InternalAuthenticationProtectionRequested(properties) {
		result.Protection, err = InternalReadOUProtection(
			ctx,
			session,
			root,
			config,
			OrganizationalUnit{DistinguishedName: silo.DistinguishedName, GUID: silo.GUID},
			*root.ConfigurationNamingContext,
		)
		result.Silo.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
	}
	return err
}
