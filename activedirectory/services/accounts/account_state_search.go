package accounts

import (
	"context"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// SearchAccountState searches accounts using the requested state condition, account kind, and bounded
// search options. The result includes the evaluated query, source endpoint, and completeness;
// inactivity uses the directory's timestamp synchronization interval.
//
// Related cmdlet: Search-ADAccount.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/search-adaccount?view=windowsserver2025-ps
func (c *Service) SearchAccountState(
	ctx context.Context,
	query AccountStateQuery,
) (result AccountStateSearchResult, err error) {
	query, err = admodel.InternalNormalizeAccountStateQuery(query)
	if err != nil {
		return result, err
	}
	result.Query = query
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	result.Source = adengine.InternalClientConfig(c.engine()).Endpoint
	result.StartedAt = time.Now().UTC()
	defer func() {
		result.FinishedAt = time.Now().UTC()
		if err != nil {
			result.Complete = false
		}
	}()
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		result.Directory = root.Capabilities().Type
		if result.Directory != admodel.DirectoryADDS && result.Directory != admodel.DirectoryADLDS {
			return admodel.ErrUnsupportedDirectory
		}
		if result.Directory == admodel.DirectoryADDS &&
			(adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3268 || adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3269) {
			return admodel.ErrAccountStateTarget
		}
		options := query.Search
		if options.Base == "" {
			options.Base = adengine.InternalClientConfig(c.engine()).Partition
			if options.Base == "" && root.DefaultNamingContext != nil {
				options.Base = *root.DefaultNamingContext
			}
			if options.Base == "" {
				return admodel.ErrNoDefaultPartition
			}
		}
		identity, err := admodel.IdentityByDN(options.Base)
		if err != nil {
			return err
		}
		if _, _, err := admodel.InternalIdentityPartition(
			identity,
			adengine.InternalClientConfig(c.engine()).Partition,
			root,
		); err != nil {
			return err
		}
		class := admodel.InternalAccountStateFilter(result.Directory, query.Kind)
		evaluation := query
		if query.Condition == admodel.AccountInactive {
			result.Inactivity, err = admodel.InternalReadAccountInactivity(
				ctx,
				adengine.InternalClientSession(c.engine()),
				root,
				query.Boundary,
			)
			if err != nil {
				return err
			}
			evaluation.Boundary = result.Inactivity.Cutoff
			cutoff, _ := admodel.InternalFiniteAccountTime(evaluation.Boundary)
			class = admodel.FilterAnd(
				class,
				admodel.FilterNot(
					admodel.FilterGreaterOrEqual(
						"lastLogonTimestamp",
						admodel.FilterText(cutoff.LDAPString()),
					),
				),
			)
		}
		if !admodel.InternalFilterUnset(options.TypedFilter) {
			options.TypedFilter = admodel.FilterAnd(class, options.TypedFilter)
		} else if options.Filter != "" {
			text, _ := class.LDAP()
			options.Filter = "(&" + text + options.Filter + ")"
		} else {
			options.TypedFilter = class
		}
		options.Properties = admodel.InternalAccountStateProperties(query, result.Directory)
		// The cursor's paging bound is the candidate scan budget. Match limits
		// are enforced only after evaluation, never as LDAP candidate limits.
		options.ResultLimit = 0
		options, err = admodel.InternalSearchOptionsNormalized(options)
		if err != nil {
			return err
		}
		cursor, err := adengine.InternalClientSession(c.engine()).InternalStartSearch(ctx, options)
		if err != nil {
			return &admodel.SearchError{Cause: err}
		}
		err = admodel.InternalCollectAccountState(ctx, cursor, options, evaluation, &result)
		if err != nil {
			return &admodel.SearchError{Returned: len(result.Observation.Objects), Cause: err}
		}
		return nil
	})
	return result, err
}
