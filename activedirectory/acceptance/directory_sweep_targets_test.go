package acceptance

import (
	"context"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_authentication_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
	adservice_claims "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/claims"
	adservice_computers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
	adservice_groups "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
	adservice_organizational_units "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/organizational_units"
	adservice_replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
	adservice_resource_properties "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/resource_properties"
	adservice_service_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
	adservice_users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

// sweepTarget is one operation's read, reduced to the shape every paged read in
// this SDK shares: SearchOptions in, a SearchResult observation out. Adding an
// operation to the endpoint-and-partition sweep is a table row, not a test.
type InternalSweepTarget struct {
	InternalCmdlet string
	// domainScoped separates the two base families this SDK actually has.
	// A domain-scoped read defaults to the default naming context and accepts
	// any base the caller chooses inside it. A container-scoped read pins its
	// own container in the configuration partition and refuses a base outside
	// it, so an explicit domain base is not applicable and a mismatched base is
	// refused by the SDK rather than by the directory. Both are legitimate
	// refusals of a naming context the operation does not serve.
	InternalDomainScoped bool
	// suppliesOwnBase is false only for the generic object read. Every typed
	// read defaults an empty base to the default naming context and sets its
	// own subtree scope, but Client.Search takes the caller's options as given:
	// an empty base with the default base scope reads the RootDSE, which
	// returns one object and no paging control. The SDK then retires the
	// connection rather than reuse an uncertain server cursor, so that one
	// mistake also closes the session.
	//
	// Its base here is the domain's Users container rather than the domain
	// root. The root holds three subordinate naming contexts — configuration,
	// DomainDnsZones and ForestDnsZones — and a subtree read of it returns
	// references to them, which this SDK reports rather than chases because
	// LDAP_OPT_REFERRALS is off. That is correct and deliberate, and belongs to
	// referral handling rather than to endpoint and partition selection, so the
	// sweep reads a plain container with no subordinate context beneath it.
	InternalSuppliesOwnBase bool
	InternalRead            func(context.Context, *adengine.Client, admodel.SearchOptions) (admodel.SearchResult, error)
}

func InternalEndpointSweepTargets() []InternalSweepTarget {
	return []InternalSweepTarget{
		{
			"Get-ADObject",
			true,
			false,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				return c.Search(ctx, o)
			},
		},
		{
			"Get-ADUser",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_users.New(c).Users(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADComputer",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_computers.New(c).Computers(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADGroup",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_groups.New(c).Groups(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADOrganizationalUnit",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_organizational_units.New(c).OrganizationalUnits(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADServiceAccount",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_service_accounts.New(c).ServiceAccounts(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADClaimType",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_claims.New(c).ClaimTypes(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADClaimTransformPolicy",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_claims.New(c).ClaimTransformPolicies(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADResourceProperty",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_resource_properties.New(c).ResourceProperties(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADResourcePropertyList",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_resource_properties.New(c).ResourcePropertyLists(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADResourcePropertyValueType",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_resource_properties.New(c).ResourceValueTypes(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADAuthenticationPolicy",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_authentication_policies.New(c).AuthenticationPolicies(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADReplicationConnection",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_replication.New(c).ReplicationConnections(ctx, o)
				return r.Observation, err
			},
		},
	}
}
