package service_accounts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

// CreateServiceAccount creates a standalone or group-managed service account with its properties,
// password-reader policy, and account controls. Password setup and enablement are separate stages
// where required; accepted stages are retained if a later stage fails.
//
// Related cmdlet: New-ADServiceAccount.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount?view=windowsserver2025-ps
func (c *Service) CreateServiceAccount(
	ctx context.Context,
	request CreateServiceAccountRequest,
) (result ServiceAccountCreationResult, err error) {
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	if ctx == nil {
		return result, admodel.ErrInvalidServiceAccount
	}
	if admodel.InternalServiceAccountClassName(request.Kind) == "" || request.Name == "" ||
		!admodel.InternalValidDirectoryText(request.Name) {
		return result, admodel.ErrInvalidServiceAccount
	}
	if err = admodel.InternalValidateAccountCreationOptions(
		request.Parent,
		request.Options,
	); err != nil {
		return
	}
	if err = admodel.InternalValidateServiceAccountProjection(
		request.Options.Properties,
	); err != nil {
		return
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	if err = admodel.InternalValidateServiceAccountControl(request.Control); err != nil {
		return
	}
	if request.Kind == admodel.ServiceAccountStandalone &&
		(request.ManagedPasswordIntervalDays != nil || request.PasswordReaders != nil) {
		return result, admodel.ErrInvalidServiceAccount
	}
	if request.Kind == admodel.ServiceAccountGroupManaged && request.InitialPassword != nil {
		return result, admodel.ErrInvalidServiceAccount
	}
	if request.OutboundAuthenticationOnly &&
		(request.Kind != admodel.ServiceAccountGroupManaged ||
			request.Properties.DNSHostName != nil ||
			request.ManagedPasswordIntervalDays != nil ||
			request.PasswordReaders != nil ||
			request.Properties.CompoundIdentitySupported != nil) {
		return result, admodel.ErrInvalidServiceAccount
	}
	if request.ManagedPasswordIntervalDays != nil &&
		(*request.ManagedPasswordIntervalDays == 0 || *request.ManagedPasswordIntervalDays > 2147483647) {
		return result, admodel.ErrInvalidServiceAccount
	}
	if request.Kind == admodel.ServiceAccountGroupManaged && !request.OutboundAuthenticationOnly &&
		(request.Properties.DNSHostName == nil || *request.Properties.DNSHostName == "") {
		return result, admodel.ErrInvalidServiceAccount
	}
	for name := range request.Attributes {
		if admodel.InternalServiceAccountManaged(name) ||
			(request.OutboundAuthenticationOnly && strings.EqualFold(name, "dNSHostName")) {
			return result, admodel.ErrInvalidServiceAccount
		}
	}
	properties := request.Properties
	if properties.SAMAccountName == nil {
		properties.SAMAccountName = &request.Name
	}
	changes, err := admodel.InternalServiceAccountChanges(properties, nil)
	if err != nil {
		return result, err
	}
	attributes := make(map[string][]admodel.RawValue, len(request.Attributes)+len(changes)+3)
	for name, values := range request.Attributes {
		key := strings.ToLower(name)
		if _, ok := attributes[key]; ok {
			return result, admodel.ErrInvalidServiceAccount
		}
		attributes[key] = values
	}
	for _, change := range changes {
		key := strings.ToLower(change.Attribute)
		if _, ok := attributes[key]; ok {
			return result, admodel.ErrInvalidServiceAccount
		}
		if change.Kind == admodel.AttributeClear {
			continue
		}
		attributes[key] = change.Values
	}
	wantEnabled := request.Control.Enabled == nil || *request.Control.Enabled
	control := request.Control
	disabled := false
	if request.Kind == admodel.ServiceAccountStandalone {
		control.Enabled = &disabled
	}
	flags := admodel.InternalAccountControlValues(0x1000, control)
	attributes["useraccountcontrol"] = []admodel.RawValue{
		admodel.NewRawValue([]byte(flags.LDAPString())),
	}
	if admodel.InternalComputerHasEncryption(
		admodel.InternalServiceAccountComputerProperties(properties),
	) {
		attributes["msds-supportedencryptiontypes"] = []admodel.RawValue{
			admodel.NewRawValue(
				[]byte(
					admodel.InternalComputerEncryptionValues(0, admodel.InternalServiceAccountComputerProperties(properties)).
						LDAPString(),
				),
			),
		}
	}
	if request.Kind == admodel.ServiceAccountGroupManaged {
		days := uint32(30)
		if request.ManagedPasswordIntervalDays != nil {
			days = *request.ManagedPasswordIntervalDays
		}
		attributes["msds-managedpasswordinterval"] = []admodel.RawValue{
			admodel.NewRawValue([]byte(strconv.FormatUint(uint64(days), 10))),
		}
	}
	if _, err = admodel.InternalCreateObjectAttributes(attributes); err != nil {
		return
	}
	password := request.InitialPassword
	if request.Kind == admodel.ServiceAccountStandalone {
		if password == nil {
			random := make([]byte, 48)
			if _, err = rand.Read(random); err != nil {
				return
			}
			password = make([]byte, 4+base64.RawStdEncoding.EncodedLen(len(random)))
			copy(password, "Aa1!")
			base64.RawStdEncoding.Encode(password[4:], random)
			clear(random)
			defer clear(password)
		}
		if err = admodel.InternalValidatePasswordBytes(password); err != nil {
			return
		}
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	err = adengine.InternalClientRead(c.engine(), bounded, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		result.Prerequisites, e = admodel.InternalServiceAccountPrerequisites(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			request.Kind,
			request.Options.Partition,
		)
		if e != nil {
			return e
		}
		request.Options.Partition = result.Prerequisites.Domain.Partition
		request.Parent, e = admodel.InternalServiceAccountDefaultParent(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			request.Parent,
			request.Options,
		)
		if e != nil {
			return e
		}
		if request.Kind == admodel.ServiceAccountStandalone {
			session, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalPasswordSession)
			if !ok {
				return admodel.ErrUnsupported
			}
			protection, e := session.InternalPasswordProtection(
				ctx,
				adengine.InternalClientConfig(c.engine()).Transport,
			)
			if e != nil {
				return e
			}
			if protection.Transport != adengine.InternalClientConfig(c.engine()).Transport ||
				protection.CipherBits < 128 {
				return admodel.ErrPasswordProtection
			}
		} else {
			sids, e := admodel.InternalResolveServiceAccountReaders(
				ctx,
				adengine.InternalClientSession(c.engine()),
				adengine.InternalClientConfig(c.engine()),
				root,
				request.PasswordReaders,
				result.Prerequisites.Domain.Partition,
			)
			if e != nil {
				return e
			}
			factory, ok := adengine.InternalClientSession(c.engine()).(interface{ InternalNewDirectoryDescriptor(string) ([]byte, error) })
			if !ok {
				return admodel.ErrUnsupported
			}
			raw, e := factory.InternalNewDirectoryDescriptor("O:SYG:SYD:")
			if e != nil {
				return e
			}
			raw, e = admodel.InternalReplaceServiceAccountReaders(
				adengine.InternalClientSession(c.engine()),
				raw,
				sids,
			)
			if e != nil {
				return e
			}
			attributes["msds-groupmsamembership"] = []admodel.RawValue{admodel.NewRawValue(raw)}
		}
		return nil
	})
	if err != nil {
		return
	}
	request.Options.Properties = admodel.InternalServiceAccountProperties(
		request.Options.Properties,
	)
	result.Creation, err = c.engine().
		CreateObject(bounded, admodel.CreateObjectRequest{
			Parent:     request.Parent,
			Class:      admodel.InternalServiceAccountClassName(request.Kind),
			Name:       request.Name,
			Attributes: attributes,
			Options:    request.Options,
		})
	if result.Creation.After != nil {
		account, e := admodel.InternalDecodeServiceAccount(*result.Creation.After)
		result.Account = &account
		err = errors.Join(err, e)
	}
	if err != nil {
		return result, admodel.InternalCreationIncomplete(
			admodel.ErrServiceAccountCreationIncomplete,
			result.Creation,
			err,
		)
	}
	if result.Creation.TargetGUID == nil || !result.Creation.Verified {
		return result, errors.Join(
			admodel.ErrServiceAccountCreationIncomplete,
			admodel.ErrObjectVerification,
		)
	}
	identity := admodel.InternalObjectGUIDIdentity(*result.Creation.TargetGUID)
	partition := result.Creation.Partition
	if request.Kind == admodel.ServiceAccountStandalone {
		stage, e := adservice_accounts.New(c.engine()).
			ResetAccountPassword(bounded, admodel.PasswordResetRequest{Identity: identity, Partition: partition, NewPassword: password})
		result.Password = &stage
		if e != nil || stage.State != admodel.ObjectWriteAccepted {
			return result, errors.Join(admodel.ErrServiceAccountCreationIncomplete, e)
		}
		if wantEnabled {
			enabled := true
			update, e := c.UpdateServiceAccount(
				bounded,
				admodel.UpdateServiceAccountRequest{
					Identity: identity,
					Control:  admodel.AccountControlPatch{Enabled: &enabled},
					Options: admodel.ObjectMutationOptions{
						Partition:  partition,
						Properties: request.Options.Properties,
					},
				},
			)
			result.Enable = &update.Mutation
			result.Account = update.Account
			if e != nil || !update.Mutation.Verified {
				return result, errors.Join(admodel.ErrServiceAccountCreationIncomplete, e)
			}
		} else {
			observation, e := c.ServiceAccount(
				bounded,
				identity,
				admodel.ResolveIdentityOptions{
					Partition:  partition,
					Properties: request.Options.Properties,
				},
			)
			result.Observation = &observation
			result.Account = observation.Account
			if e != nil {
				return result, errors.Join(admodel.ErrServiceAccountCreationIncomplete, e)
			}
		}
	}
	result.Complete = true
	return result, nil
}
