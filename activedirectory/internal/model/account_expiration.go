package model

import (
	"errors"
	"math"
	"time"
)

var (
	ErrInvalidAccountExpiration = errors.New("invalid finite account expiration time")
	ErrAccountStateTarget       = errors.New(
		"account state requires a full LDAP replica, not a global catalog port",
	)
)

// AccountExpiration preserves both documented never-expire sentinels. Nil
// Value/NeverExpires means accountExpires was not returned; it does not mean
// never expires. ExpiresAt is an exact UTC instant at 100ns precision.
type AccountExpiration struct {
	DistinguishedName string
	Value             *FileTime
	NeverExpires      *bool
	ExpiresAt         *time.Time
	Raw               Object
}

type AccountExpirationResult struct {
	Expiration  *AccountExpiration
	Observation IdentityResult
}

type AccountExpirationMutationResult struct {
	Expiration *AccountExpiration
	Mutation   ObjectMutationResult
}

// SetAccountExpirationRequest accepts an absolute instant. For relative expiry,
// explicitly compute At from a caller-selected reference time using time.Add.
// The SDK never parses locale-dependent dates or chooses midnight/current time.
type SetAccountExpirationRequest struct {
	Identity Identity
	At       time.Time
	Options  ObjectMutationOptions
}

func InternalDecodeAccountExpiration(object Object) (AccountExpiration, error) {
	result := AccountExpiration{DistinguishedName: object.DistinguishedName, Raw: object}
	values := object.Values("accountExpires")
	if values.State == AttributeAbsent || values.State == AttributeUnloaded {
		return result, nil
	}
	value, err := values.Single()
	if err != nil {
		return result, err
	}
	stamp, err := value.FileTime()
	if err != nil {
		return result, err
	}
	result.Value = &stamp
	never := stamp == 0 || stamp == math.MaxInt64
	if never {
		result.NeverExpires = &never
		return result, nil
	}
	instant, err := stamp.Time()
	if err != nil {
		return result, err
	}
	result.NeverExpires, result.ExpiresAt = &never, &instant
	return result, nil
}

func InternalFiniteAccountTime(at time.Time) (FileTime, error) {
	stamp, err := FileTimeFromTime(at)
	if err != nil || stamp == 0 || stamp == math.MaxInt64 {
		return 0, errors.Join(ErrInvalidAccountExpiration, err)
	}
	return stamp, nil
}
