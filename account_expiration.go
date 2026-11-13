package activedirectory

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"
)

var (
	ErrInvalidAccountExpiration = errors.New("invalid finite account expiration time")
	ErrAccountStateTarget       = errors.New("account state requires a full LDAP replica, not a global catalog port")
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

func decodeAccountExpiration(object Object) (AccountExpiration, error) {
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

func finiteAccountTime(at time.Time) (FileTime, error) {
	stamp, err := FileTimeFromTime(at)
	if err != nil || stamp == 0 || stamp == math.MaxInt64 {
		return 0, errors.Join(ErrInvalidAccountExpiration, err)
	}
	return stamp, nil
}

func (c *Client) AccountExpiration(ctx context.Context, identity Identity, options ResolveIdentityOptions) (result AccountExpirationResult, err error) {
	if options.Target > IdentityTargetAccount {
		return result, ErrInvalidIdentity
	}
	options = accountControlIdentity(identity, options.Partition, append(slices.Clone(options.Properties), "accountExpires"))
	if err := validateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == DirectoryADDS && (c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269) {
			return ErrAccountStateTarget
		}
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if err != nil {
			return err
		}
		if err := accountControlClass(*result.Observation.Object, root.Capabilities().Type); err != nil {
			return err
		}
		expiration, err := decodeAccountExpiration(*result.Observation.Object)
		result.Expiration = &expiration
		return err
	})
	return result, err
}

func (c *Client) SetAccountExpiration(ctx context.Context, request SetAccountExpirationRequest) (AccountExpirationMutationResult, error) {
	stamp, err := finiteAccountTime(request.At)
	if err != nil {
		return AccountExpirationMutationResult{}, err
	}
	return c.writeAccountExpiration(ctx, request.Identity, request.Options, stamp)
}

// ClearAccountExpiration writes MaxInt64, matching the ActiveDirectory module's
// AccountExpirationDate clear conversion. Both 0 and MaxInt64 are recognized on
// reads. Clearing does not delete the attribute or write the -1 instruction.
func (c *Client) ClearAccountExpiration(ctx context.Context, identity Identity, options ObjectMutationOptions) (AccountExpirationMutationResult, error) {
	return c.writeAccountExpiration(ctx, identity, options, math.MaxInt64)
}

func (c *Client) writeAccountExpiration(ctx context.Context, identity Identity, options ObjectMutationOptions, stamp FileTime) (AccountExpirationMutationResult, error) {
	resolve := accountControlIdentity(identity, options.Partition, append(slices.Clone(options.Properties), "accountExpires"))
	if err := validateIdentityOperation(identity, resolve); err != nil {
		return AccountExpirationMutationResult{}, err
	}
	mod := ldapAttributeModification{operation: 2, attribute: "accountExpires", values: [][]byte{[]byte(stamp.LDAPString())}}
	mutation, err := c.objectMutationIdentity(ctx, identity, options, resolve, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := accountControlClass(*observed.Object, root.Capabilities().Type); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: []ldapAttributeModification{mod}, controls: controls}, false, result); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, accountControlProperties(objectWriteProperties(options, []ldapAttributeModification{mod})), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, []ldapAttributeModification{mod}, "")
	})
	result := AccountExpirationMutationResult{Mutation: mutation}
	if mutation.After != nil {
		expiration, decodeErr := decodeAccountExpiration(*mutation.After)
		result.Expiration = &expiration
		err = errors.Join(err, decodeErr)
	}
	return result, err
}
