package accounts

import (
	"context"
	"errors"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ChangeAccountPassword changes a known old password to a new one in one
// protected Modify. It never falls back to an administrator reset or retries.
func (c *Service) ChangeAccountPassword(
	ctx context.Context,
	request PasswordChangeRequest,
) (PasswordResult, error) {
	if err := admodel.InternalValidatePasswordBytes(request.OldPassword); err != nil {
		return admodel.PasswordResult{}, err
	}
	if err := admodel.InternalValidatePasswordBytes(request.NewPassword); err != nil {
		return admodel.PasswordResult{}, err
	}
	return internalServiceAccountPassword(c,
		ctx,
		request.Identity,
		request.Partition,
		request.OldPassword,
		request.NewPassword,
		true,
	)
}

// ResetAccountPassword resets a password without knowing the old password.
// It submits no additional account-flag or pwdLastSet modifications. The
// server's password processing controls timestamps and other derived state.
func (c *Service) ResetAccountPassword(
	ctx context.Context,
	request PasswordResetRequest,
) (PasswordResult, error) {
	if err := admodel.InternalValidatePasswordBytes(request.NewPassword); err != nil {
		return admodel.PasswordResult{}, err
	}
	return internalServiceAccountPassword(c,
		ctx,
		request.Identity,
		request.Partition,
		nil,
		request.NewPassword,
		false,
	)
}

func internalServiceAccountPassword(c *Service,
	ctx context.Context,
	account admodel.Identity,
	partition string,
	oldPassword, newPassword []byte,
	change bool,
) (admodel.PasswordResult, error) {
	var result admodel.PasswordResult
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	options := admodel.ResolveIdentityOptions{
		Partition:  partition,
		Properties: []string{"objectGUID", "objectClass"},
	}
	// SID/account-name resolution is supported only for AD DS; DN/GUID also
	// address applicable AD LDS user classes without assuming objectSid exists.
	if account.Form() == admodel.IdentityFormSID ||
		account.Form() == admodel.IdentityFormAccountName {
		options.Target = admodel.IdentityTargetAccount
	}
	if err := admodel.InternalValidateIdentityOperation(account, options); err != nil {
		return result, err
	}
	result.Source = adengine.InternalClientConfig(c.engine()).Endpoint
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		session, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalPasswordSession)
		if !ok {
			return errors.Join(admodel.ErrPasswordProtection, admodel.ErrUnsupported)
		}
		protection, err := session.InternalPasswordProtection(
			ctx,
			adengine.InternalClientConfig(c.engine()).Transport,
		)
		if err != nil {
			return errors.Join(admodel.ErrPasswordProtection, err)
		}
		result.Protection = protection
		if protection.Transport != adengine.InternalClientConfig(c.engine()).Transport ||
			protection.CipherBits < 128 {
			return admodel.ErrPasswordProtection
		}
		root, err := admodel.InternalReadIdentityRoot(ctx, session)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == admodel.DirectoryADDS &&
			(adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3268 || adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3269) {
			return admodel.ErrPasswordTarget
		}
		if root.Capabilities().Type == admodel.DirectoryADDS {
			if root.DSServiceName == nil {
				return errors.Join(admodel.ErrPasswordTarget, admodel.ErrIncompleteResult)
			}
			if _, err := admodel.InternalParseIdentityDN(*root.DSServiceName); err != nil {
				return errors.Join(admodel.ErrPasswordTarget, admodel.ErrInvalidResult)
			}
			attributes, err := session.InternalBaseObject(
				ctx,
				*root.DSServiceName,
				[]string{"msDS-isRODC"},
			)
			if err != nil {
				return err
			}
			decoder := admodel.InternalRootDSEDecoder{InternalAttributes: attributes}
			readOnly := admodel.InternalDecodeScalar(
				&decoder,
				"msDS-isRODC",
				admodel.InternalParseLDAPBool,
			)
			if len(decoder.InternalErrors) != 0 {
				return errors.Join(decoder.InternalErrors...)
			}
			if readOnly == nil {
				return errors.Join(admodel.ErrPasswordTarget, admodel.ErrIncompleteResult)
			}
			if *readOnly {
				return admodel.ErrPasswordTarget
			}
		}
		resolved, err := admodel.InternalResolveIdentitySession(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			account,
			options,
		)
		result.Partition = resolved.Partition
		if err != nil {
			return err
		}
		result.TargetDN = resolved.Object.DistinguishedName
		classes, state := resolved.Object.Attribute("objectClass")
		if state != admodel.AttributePresent {
			return errors.Join(admodel.ErrPasswordTarget, admodel.ErrIncompleteResult)
		}
		eligible := false
		for _, class := range classes {
			if strings.EqualFold(string(class), "user") ||
				strings.EqualFold(string(class), "inetOrgPerson") {
				eligible = true
			}
		}
		if !eligible {
			return admodel.ErrPasswordTarget
		}
		value, err := resolved.Object.Values("objectGUID").Single()
		if err != nil {
			return errors.Join(admodel.ErrInvalidResult, err)
		}
		guid, err := value.GUID()
		if err != nil {
			return errors.Join(admodel.ErrInvalidResult, err)
		}
		result.TargetGUID = &guid
		// Check protection immediately before exposing encoded passwords to
		// native request construction; never infer it from the chosen port.
		protection, err = session.InternalPasswordProtection(
			ctx,
			adengine.InternalClientConfig(c.engine()).Transport,
		)
		if err != nil {
			return errors.Join(admodel.ErrPasswordProtection, err)
		}
		result.Protection = protection
		if protection.Transport != adengine.InternalClientConfig(c.engine()).Transport ||
			protection.CipherBits < 128 {
			return admodel.ErrPasswordProtection
		}
		if err := context.Cause(ctx); err != nil {
			return err
		}
		newValue := admodel.InternalQuotedPasswordUTF16(newPassword)
		defer admodel.InternalErasePasswordBuffer(newValue)
		mods := []admodel.InternalLdapAttributeModification{
			{
				InternalOperation: 2,
				InternalAttribute: "unicodePwd",
				InternalValues:    [][]byte{newValue},
			},
		}
		if change {
			oldValue := admodel.InternalQuotedPasswordUTF16(oldPassword)
			defer admodel.InternalErasePasswordBuffer(oldValue)
			mods = []admodel.InternalLdapAttributeModification{
				{
					InternalOperation: 1,
					InternalAttribute: "unicodePwd",
					InternalValues:    [][]byte{oldValue},
				},
				{
					InternalOperation: 0,
					InternalAttribute: "unicodePwd",
					InternalValues:    [][]byte{newValue},
				},
			}
		}
		attempt := session.InternalLdapWrite(
			ctx,
			admodel.InternalLdapWriteRequest{
				InternalOperation:     admodel.InternalLdapWriteModify,
				InternalDn:            admodel.InternalObjectGUIDTarget(guid),
				InternalModifications: mods,
			},
		)
		switch attempt.State {
		case admodel.InternalLdapWriteAccepted:
			result.State = admodel.ObjectWriteAccepted
		case admodel.InternalLdapWriteRejected:
			result.State = admodel.ObjectWriteRejected
		case admodel.InternalLdapWriteUncertain:
			result.State = admodel.ObjectWriteUncertain
		}
		if result.State == admodel.ObjectWriteUncertain {
			return errors.Join(admodel.ErrPasswordUncertain, attempt.Err)
		}
		if attempt.Err != nil {
			return attempt.Err
		}
		if result.State != admodel.ObjectWriteAccepted {
			return admodel.ErrInvalidResult
		}
		return nil
	})
	return result, admodel.InternalClassifyPasswordError(err)
}
