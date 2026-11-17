package model

import (
	"context"
	"errors"
)

var ErrAccountPasswordPermission = errors.New(
	"account password-change permission is unknown or could not be established",
)

type InternalDirectoryDACLSession interface {
	InternalDirectorySession
	InternalReadDirectoryDACL(context.Context, string, []string) (Object, error)
	InternalEncodeDACL([]byte, [][]byte) ([]byte, error)
}

// AccountPasswordPermission describes SELF/Everyone Change-Password ACEs.
// CannotChangePassword is the recognized deny-pattern observation, not an
// effective-access check or a promise that a password change will succeed.
// Nil means the descriptor/pattern is unknown; it is never a userAccountControl
// bit. The original descriptor remains available in Raw.
type AccountPasswordPermission struct {
	DistinguishedName    string
	GUID                 *GUID
	CannotChangePassword *bool
	Self, Everyone       PasswordChangeACEObservation
	UnknownACE           bool
	Raw                  Object
}

type AccountPasswordPermissionResult struct {
	Permission  *AccountPasswordPermission
	Observation IdentityResult
}

type AccountPasswordPermissionMutationResult struct {
	Mutation      ObjectMutationResult
	Before, After *AccountPasswordPermission
	Changed       bool
}

func InternalDecodeAccountPasswordPermission(
	object Object,
) (AccountPasswordPermission, []byte, InternalDirectoryDACL, error) {
	result := AccountPasswordPermission{DistinguishedName: object.DistinguishedName, Raw: object}
	var acl InternalDirectoryDACL
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return result, nil, acl, errors.Join(ErrAccountPasswordPermission, err)
	}
	guid, err := value.GUID()
	if err != nil {
		return result, nil, acl, errors.Join(ErrAccountPasswordPermission, err)
	}
	result.GUID = &guid
	value, err = object.Values("nTSecurityDescriptor").Single()
	if err != nil {
		return result, nil, acl, errors.Join(ErrAccountPasswordPermission, err)
	}
	raw := value.Bytes()
	acl, err = InternalDecodeDirectoryDACL(raw)
	if err != nil {
		return result, raw, acl, errors.Join(ErrAccountPasswordPermission, err)
	}
	result.Self, result.Everyone, result.CannotChangePassword, result.UnknownACE = InternalObservePasswordChangeACL(
		acl,
	)
	return result, raw, acl, nil
}

func InternalReadAccountPasswordPermission(
	ctx context.Context,
	session InternalDirectoryDACLSession,
	root RootDSE,
	partition string,
	guid GUID,
	properties []string,
) (AccountPasswordPermission, []byte, InternalDirectoryDACL, error) {
	object, readErr := session.InternalReadDirectoryDACL(
		ctx,
		InternalObjectGUIDTarget(guid),
		properties,
	)
	result, raw, acl, err := InternalDecodeAccountPasswordPermission(object)
	if readErr != nil || err != nil {
		result.CannotChangePassword = nil
		return result, raw, acl, errors.Join(readErr, err)
	}
	if result.GUID == nil || *result.GUID != guid {
		result.CannotChangePassword = nil
		return result, raw, acl, ErrInvalidResult
	}
	identity, err := IdentityByDN(object.DistinguishedName)
	if err == nil {
		_, _, err = InternalIdentityPartition(identity, partition, root)
	}
	if err != nil {
		result.CannotChangePassword = nil
		return result, raw, acl, err
	}
	return result, raw, acl, nil
}

func InternalDirectoryACEsRetained(expected, actual [][]byte) bool {
	counts := make(map[string]int, len(actual))
	for _, ace := range actual {
		counts[string(ace)]++
	}
	for _, ace := range expected {
		if counts[string(ace)] == 0 {
			return false
		}
		counts[string(ace)]--
	}
	return true
}
