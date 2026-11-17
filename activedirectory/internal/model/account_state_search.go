package model

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

var (
	ErrInvalidAccountStateSearch = errors.New("invalid account-state search criteria")
	ErrAccountStateUnreadable    = errors.New(
		"one or more candidate account states could not be determined",
	)
)

type AccountStateCondition uint8

const (
	AccountDisabled AccountStateCondition = iota + 1
	AccountLockedOut
	AccountExpired
	AccountExpiring
	AccountInactive
	AccountPasswordExpired
	AccountPasswordNeverExpires
)

type AccountStateKind uint8

const (
	AccountStateAll AccountStateKind = iota
	AccountStateUsers
	AccountStateComputers
)

// AccountStateQuery selects exactly one condition. Expired requires AsOf;
// Expiring requires AsOf and Boundary and matches [AsOf, Boundary). Inactive
// requires Boundary; the module-compatible synchronization allowance is
// subtracted before submitting NOT(lastLogonTimestamp >= effective cutoff).
// Other conditions use the selected server's returned state, not historical
// evaluation. Unused time fields are errors. Relative windows are explicit
// caller computations, e.g. Boundary: reference.Add(-90*24*time.Hour).
//
// Search supplies scope, extra filter/properties, paging and the match limit
// (Search.ResultLimit). ScanLimit separately bounds candidate accounts evaluated,
// default 10,000. The query scans account classes plus the caller's filter and
// evaluates computed state locally, so absent/hidden values remain unknown.
// Inactivity uses the directory predicate, including its absent-value semantics.
type AccountStateQuery struct {
	Condition      AccountStateCondition
	Kind           AccountStateKind
	AsOf, Boundary time.Time
	Search         SearchOptions
	ScanLimit      int
}

type AccountStateUnknown struct {
	Object Object
	Error  error
}

// AccountInactivityObservation preserves the effective criterion. AD DS reads
// the default domain's msDS-LogonTimeSyncInterval; an omitted value, or AD LDS,
// uses the module's 15-day default. Defaulted is not proof the value is unset:
// ACLs can also hide it. Domain preserves the raw interval read, including errors.
type AccountInactivityObservation struct {
	Cutoff                      time.Time
	SynchronizationIntervalDays int32
	Defaulted                   bool
	Domain                      Object
	DomainReadComplete          bool
}

// Observation contains every received candidate, including any unexamined tail
// of the final page after the match limit. Scanned counts evaluated candidates.
// Complete additionally requires every received candidate to be evaluated and
// no unreadable state. Limits do not prove that further matches exist. A server
// can omit objects entirely under ACLs; completeness is relative to that view.
type AccountStateSearchResult struct {
	Source                                        Endpoint
	Directory                                     DirectoryType
	Query                                         AccountStateQuery
	StartedAt, FinishedAt                         time.Time
	Accounts                                      []Object
	Unknown                                       []AccountStateUnknown
	Inactivity                                    *AccountInactivityObservation
	Observation                                   SearchResult
	Scanned                                       int
	Complete, ScanLimitReached, MatchLimitReached bool
}

func InternalNormalizeAccountStateQuery(query AccountStateQuery) (AccountStateQuery, error) {
	if query.Condition < AccountDisabled || query.Condition > AccountPasswordNeverExpires ||
		query.Kind > AccountStateComputers ||
		query.ScanLimit < 0 {
		return query, ErrInvalidAccountStateSearch
	}
	if err := query.Search.Validate(); err != nil {
		return query, err
	}
	for _, property := range query.Search.Properties {
		if property == "1.1" {
			return query, ErrInvalidProperty
		}
	}
	var times []time.Time
	switch query.Condition {
	case AccountExpired:
		if query.AsOf.IsZero() || !query.Boundary.IsZero() {
			return query, ErrInvalidAccountStateSearch
		}
		times = []time.Time{query.AsOf}
	case AccountExpiring:
		if query.AsOf.IsZero() || query.Boundary.IsZero() || query.Boundary.Before(query.AsOf) {
			return query, ErrInvalidAccountStateSearch
		}
		times = []time.Time{query.AsOf, query.Boundary}
	case AccountInactive:
		if !query.AsOf.IsZero() || query.Boundary.IsZero() {
			return query, ErrInvalidAccountStateSearch
		}
		times = []time.Time{query.Boundary}
	default:
		if !query.AsOf.IsZero() || !query.Boundary.IsZero() {
			return query, ErrInvalidAccountStateSearch
		}
	}
	for _, at := range times {
		if _, err := InternalFiniteAccountTime(at); err != nil {
			return query, errors.Join(ErrInvalidAccountStateSearch, err)
		}
	}
	if query.ScanLimit == 0 {
		query.ScanLimit = 10000
	}
	query.Search.Properties = slices.Clone(query.Search.Properties)
	return query, nil
}

func InternalAccountStateFilter(kind DirectoryType, selection AccountStateKind) Filter {
	classes := []Filter{
		FilterEqual("objectClass", FilterText("user")),
		FilterEqual("objectClass", FilterText("inetOrgPerson")),
	}
	if kind == DirectoryADLDS {
		classes = append(classes, FilterEqual("objectClass", FilterText("msDS-BindableObject")))
	}
	class := FilterOr(classes...)
	computer := FilterEqual("objectClass", FilterText("computer"))
	if selection == AccountStateUsers {
		return FilterAnd(class, FilterNot(computer))
	}
	if selection == AccountStateComputers {
		return FilterAnd(class, computer)
	}
	return class
}

func InternalAccountStateProperties(query AccountStateQuery, kind DirectoryType) []string {
	properties := append(slices.Clone(query.Search.Properties), "objectClass", "objectGUID", "name")
	switch query.Condition {
	case AccountDisabled, AccountPasswordNeverExpires:
		properties = append(
			properties,
			"userAccountControl",
			"msDS-UserAccountDisabled",
			"msDS-UserDontExpirePassword",
		)
	case AccountLockedOut, AccountPasswordExpired:
		if kind == DirectoryADLDS {
			if query.Condition == AccountLockedOut {
				properties = append(properties, "ms-DS-UserAccountAutoLocked")
			} else {
				properties = append(properties, "msDS-UserPasswordExpired")
			}
		} else {
			properties = append(properties, "msDS-User-Account-Control-Computed")
		}
	case AccountExpired, AccountExpiring:
		properties = append(properties, "accountExpires")
	case AccountInactive:
		properties = append(properties, "lastLogonTimestamp")
	}
	return properties
}

func InternalReadAccountInactivity(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	boundary time.Time,
) (*AccountInactivityObservation, error) {
	result := &AccountInactivityObservation{SynchronizationIntervalDays: 15, Defaulted: true}
	if root.Capabilities().Type == DirectoryADDS && root.DomainFunctionality != nil &&
		*root.DomainFunctionality < 2 {
		return result, fmt.Errorf(
			"%w: inactivity requires Windows Server 2003 domain functional level or later",
			ErrInvalidAccountStateSearch,
		)
	}
	if root.Capabilities().Type == DirectoryADDS && root.DefaultNamingContext != nil &&
		*root.DefaultNamingContext != "" {
		properties := []string{"msDS-LogonTimeSyncInterval"}
		attributes, err := session.InternalBaseObject(ctx, *root.DefaultNamingContext, properties)
		result.Domain = Object{
			DistinguishedName:   *root.DefaultNamingContext,
			Attributes:          attributes,
			RequestedProperties: properties,
		}
		result.DomainReadComplete = err == nil
		if err != nil {
			return result, err
		}
		_, state := result.Domain.Attribute(properties[0])
		if state != AttributeAbsent {
			value, err := result.Domain.Values(properties[0]).Single()
			if err != nil {
				return result, err
			}
			days, err := value.Int64()
			if err != nil || days < 0 || days > math.MaxInt32 {
				return result, errors.Join(ErrInvalidValue, err)
			}
			result.SynchronizationIntervalDays = int32(days)
			result.Defaulted = false
		}
	}
	// Calendar arithmetic in UTC avoids local DST shifts and duration overflow.
	result.Cutoff = boundary.UTC().AddDate(0, 0, -int(result.SynchronizationIntervalDays))
	if _, err := InternalFiniteAccountTime(result.Cutoff); err != nil {
		return result, errors.Join(ErrInvalidAccountStateSearch, err)
	}
	return result, nil
}

func InternalCollectAccountState(
	ctx context.Context,
	cursor InternalSearchCursor,
	options SearchOptions,
	query AccountStateQuery,
	result *AccountStateSearchResult,
) (err error) {
	defer func() {
		err = errors.Join(err, cursor.InternalClose(), context.Cause(ctx))
		if err != nil {
			result.Observation.Complete = false
		}
		if len(result.Unknown) != 0 {
			err = errors.Join(err, ErrAccountStateUnreadable)
		}
		if err != nil {
			result.Complete = false
		}
	}()
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if result.Scanned == query.ScanLimit {
			result.ScanLimitReached = true
			result.Observation.LimitReached = true
			return nil
		}
		size := min(options.PageSize, query.ScanLimit-result.Scanned)
		objects, done, nextErr := cursor.InternalNext(ctx, uint32(size))
		for i := range objects {
			objects[i].RequestedProperties = slices.Clone(options.Properties)
		}
		result.Observation.Objects = append(result.Observation.Objects, objects...)
		if len(objects) > size {
			return errors.Join(
				nextErr,
				fmt.Errorf("%w: server exceeded requested account page size", ErrInvalidResult),
			)
		}
		for i, object := range objects {
			if err := context.Cause(ctx); err != nil {
				return errors.Join(nextErr, err)
			}
			result.Scanned++
			match, evalErr := InternalMatchAccountState(object, result.Directory, query)
			if evalErr != nil {
				result.Unknown = append(
					result.Unknown,
					AccountStateUnknown{Object: object, Error: evalErr},
				)
			} else if match {
				result.Accounts = append(result.Accounts, object)
			}
			if query.Search.ResultLimit > 0 && len(result.Accounts) >= query.Search.ResultLimit &&
				(i < len(objects)-1 || !done) {
				result.MatchLimitReached = true
				return nextErr
			}
		}
		if nextErr != nil {
			return nextErr
		}
		if done {
			result.Observation.Complete = true
			result.Complete = len(result.Unknown) == 0
			return nil
		}
	}
}

func InternalMatchAccountState(
	object Object,
	kind DirectoryType,
	query AccountStateQuery,
) (bool, error) {
	if err := InternalAccountControlClass(object, kind); err != nil {
		return false, err
	}
	classes, _ := object.Attribute("objectClass")
	computer := false
	for _, class := range classes {
		computer = computer || strings.EqualFold(string(class), "computer")
	}
	if (query.Kind == AccountStateUsers && computer) ||
		(query.Kind == AccountStateComputers && !computer) {
		return false, ErrInvalidResult
	}
	switch query.Condition {
	case AccountDisabled, AccountPasswordNeverExpires:
		attribute := "userAccountControl"
		if kind == DirectoryADLDS {
			attribute = "msDS-UserAccountDisabled"
			if query.Condition == AccountPasswordNeverExpires {
				attribute = "msDS-UserDontExpirePassword"
			}
		}
		value, err := object.Values(attribute).Single()
		if err != nil {
			return false, err
		}
		if kind == DirectoryADLDS {
			return value.Bool()
		}
		flags, err := value.Flags32()
		if err != nil {
			return false, err
		}
		mask := Flags32(2)
		if query.Condition == AccountPasswordNeverExpires {
			mask = 0x10000
		}
		return flags.Has(mask), nil
	case AccountLockedOut, AccountPasswordExpired:
		if kind == DirectoryADLDS {
			attribute := "ms-DS-UserAccountAutoLocked"
			if query.Condition == AccountPasswordExpired {
				attribute = "msDS-UserPasswordExpired"
			}
			value, err := object.Values(attribute).Single()
			if err != nil {
				return false, err
			}
			return value.Bool()
		}
		value, err := object.Values("msDS-User-Account-Control-Computed").Single()
		if err != nil {
			return false, err
		}
		flags, err := value.Flags32()
		if err != nil {
			return false, err
		}
		mask := Flags32(0x10)
		if query.Condition == AccountPasswordExpired {
			mask = 0x800000
		}
		return flags.Has(mask), nil
	case AccountExpired, AccountExpiring:
		expiration, err := InternalDecodeAccountExpiration(object)
		if err != nil {
			return false, err
		}
		if expiration.NeverExpires == nil {
			return false, ErrAttributeUnavailable
		}
		if *expiration.NeverExpires {
			return false, nil
		}
		if query.Condition == AccountExpired {
			return expiration.ExpiresAt.Before(query.AsOf), nil
		}
		return !expiration.ExpiresAt.Before(query.AsOf) &&
			expiration.ExpiresAt.Before(query.Boundary), nil
	case AccountInactive:
		// The server applied NOT(timestamp >= cutoff). An absent projected
		// timestamp does not disprove that predicate, and does not establish
		// that the account has never logged on. Preserve the raw absence.
		if _, state := object.Attribute("lastLogonTimestamp"); state == AttributeAbsent {
			return true, nil
		}
		value, err := object.Values("lastLogonTimestamp").Single()
		if err != nil {
			return false, err
		}
		stamp, err := value.Int64()
		if err != nil || stamp < 0 {
			return false, errors.Join(ErrInvalidValue, err)
		}
		cutoff, err := InternalFiniteAccountTime(query.Boundary)
		return uint64(stamp) < uint64(cutoff), err
	}
	return false, ErrInvalidAccountStateSearch
}
