package service_accounts

import (
	"context"
	"errors"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// AddComputerServiceAccounts associates the requested managed service accounts with a computer.
// Request selects strict or permissive linked-value handling; this directory change does not install
// an account on the local host.
//
// Related cmdlet: Add-ADComputerServiceAccount.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adcomputerserviceaccount?view=windowsserver2025-ps
func (c *Service) AddComputerServiceAccounts(
	ctx context.Context,
	request ComputerServiceAccountRequest,
) (ComputerServiceAccountMutationResult, error) {
	return internalServiceChangeComputerServiceAccounts(c, ctx, request, true)
}

// RemoveComputerServiceAccounts removes managed-service-account associations from a computer without
// deleting the accounts or uninstalling them locally. The result retains account observations and the
// computer mutation outcome.
//
// Related cmdlet: Remove-ADComputerServiceAccount.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adcomputerserviceaccount?view=windowsserver2025-ps
func (c *Service) RemoveComputerServiceAccounts(
	ctx context.Context,
	request ComputerServiceAccountRequest,
) (ComputerServiceAccountMutationResult, error) {
	return internalServiceChangeComputerServiceAccounts(c, ctx, request, false)
}

// internalServiceChangeComputerServiceAccounts resolves managed accounts before changing a computer's
// service-account links.
func internalServiceChangeComputerServiceAccounts(c *Service,
	ctx context.Context,
	request admodel.ComputerServiceAccountRequest,
	add bool,
) (result admodel.ComputerServiceAccountMutationResult, err error) {
	if len(request.Accounts) == 0 ||
		len(request.Accounts) > admodel.InternalServiceAccountMaxLinks {
		return result, admodel.ErrInvalidServiceAccount
	}
	if err = admodel.InternalValidateServiceAccountProjection(
		request.Options.Properties,
	); err != nil {
		return
	}
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Computer,
		request.Options,
		admodel.InternalComputerIdentityOptions(request.Computer, request.Options.Partition, nil),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if e := root.Capabilities().RequireADDS("ComputerServiceAccounts"); e != nil {
				return e
			}
			if e := admodel.InternalComputerClass(*observed.Object); e != nil {
				return e
			}
			if root.Capabilities().Has("1.2.840.113556.1.4.1920") {
				return admodel.ErrObjectWriteTarget
			}
			controls, e := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
				*mutation.TargetGUID,
				false,
			)
			if e != nil {
				return e
			}
			if request.Permissive {
				const oid = "1.2.840.113556.1.4.1413"
				if !slices.Contains(root.SupportedControls, oid) {
					return admodel.ErrObjectControlUnsupported
				}
				controls = append(
					controls,
					admodel.InternalLdapWriteControl{InternalOid: oid, InternalCritical: true},
				)
			}
			values := []admodel.RawValue{}
			seen := map[string]bool{}
			for _, identity := range request.Accounts {
				if e := context.Cause(ctx); e != nil {
					return e
				}
				observation, e := admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					identity,
					admodel.InternalServiceAccountIdentityOptions(
						identity,
						mutation.Partition,
						nil,
					),
				)
				result.Accounts = append(result.Accounts, observation)
				if e != nil {
					return e
				}
				if _, e = admodel.InternalServiceAccountClass(*observation.Object); e != nil {
					return e
				}
				dn := observation.Object.DistinguishedName
				value, e := observation.Object.Values("objectGUID").Single()
				if e != nil {
					return e
				}
				guid, e := value.GUID()
				if e != nil {
					return e
				}
				key := guid.String()
				if seen[key] {
					return admodel.ErrInvalidServiceAccount
				}
				seen[key] = true
				values = append(values, admodel.NewRawValue([]byte(dn)))
			}
			kind := admodel.AttributeAddValues
			if !add {
				kind = admodel.AttributeRemoveValues
			}
			mods, e := admodel.InternalObjectChanges(
				[]admodel.AttributeChange{
					{Attribute: "msDS-HostServiceAccount", Kind: kind, Values: values},
				},
			)
			if e != nil {
				return e
			}
			if e = admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation:     admodel.InternalLdapWriteModify,
					InternalDn:            admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
					InternalModifications: mods,
					InternalControls:      controls,
				},
				false,
				mutation,
			); e != nil {
				return e
			}
			if e = admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				append(
					slices.Clone(request.Options.Properties),
					"objectGUID",
					"uSNChanged",
					"objectClass",
				),
				false,
			); e != nil {
				return e
			}
			guid, usn, e := admodel.InternalServiceAccountLinkVersion(*mutation.After)
			if e != nil {
				return errors.Join(admodel.ErrObjectReadback, e)
			}
			links := admodel.ComputerServiceAccountsResult{
				Version: &admodel.ObjectVersion{
					Source:     adengine.InternalClientConfigPointer(c.engine()).Endpoint,
					GUID:       guid,
					USNChanged: usn,
				},
			}
			result.Links = &links
			reader, ok := session.(admodel.InternalServiceAccountRangeReader)
			if !ok {
				return errors.Join(admodel.ErrObjectReadback, admodel.ErrUnsupported)
			}
			if e = admodel.InternalCollectComputerServiceAccountLinks(
				ctx,
				reader,
				admodel.ComputerServiceAccountsOptions{
					MaxValues: admodel.InternalServiceAccountMaxLinks,
					MaxRanges: admodel.InternalServiceAccountMaxRanges,
					MaxBytes:  admodel.InternalServiceAccountMaxBytes,
				},
				&links,
			); e != nil {
				return errors.Join(admodel.ErrObjectReadback, e)
			}
			if !links.AttributeReturned {
				return admodel.ErrObjectVerification
			}
			present := map[string]bool{}
			for _, link := range links.Links {
				if e := context.Cause(ctx); e != nil {
					return errors.Join(admodel.ErrObjectReadback, e)
				}
				dn, e := admodel.InternalParseIdentityDN(link.DistinguishedName)
				if e != nil {
					return errors.Join(admodel.ErrObjectVerification, e)
				}
				present[admodel.InternalIdentityDNKey(dn)] = true
			}
			for _, value := range values {
				if e := context.Cause(ctx); e != nil {
					return errors.Join(admodel.ErrObjectReadback, e)
				}
				text, e := value.Text()
				if e != nil {
					return e
				}
				dn, e := admodel.InternalParseIdentityDN(text)
				if e != nil {
					return e
				}
				if present[admodel.InternalIdentityDNKey(dn)] != add {
					return admodel.ErrObjectVerification
				}
			}
			mutation.Verified = true
			return nil
		},
	)
	return
}

// ComputerServiceAccounts reads the managed service accounts associated with a computer. Options bound
// linked-value reads and select account properties; partial associations and decoding errors remain
// visible.
//
// Related cmdlet: Get-ADComputerServiceAccount.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputerserviceaccount?view=windowsserver2025-ps
func (c *Service) ComputerServiceAccounts(
	ctx context.Context,
	identity adshared.Identity,
	options ComputerServiceAccountsOptions,
) (result ComputerServiceAccountsResult, err error) {
	if options.MaxValues < 0 || options.MaxRanges < 0 || options.MaxBytes < 0 ||
		options.MaxValues > admodel.InternalServiceAccountMaxLinks ||
		options.MaxRanges > admodel.InternalServiceAccountMaxRanges ||
		options.MaxBytes > admodel.InternalServiceAccountMaxBytes {
		return result, admodel.ErrInvalidServiceAccount
	}
	if options.MaxValues == 0 {
		options.MaxValues = admodel.InternalServiceAccountMaxLinks
	}
	if options.MaxRanges == 0 {
		options.MaxRanges = admodel.InternalServiceAccountMaxRanges
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = admodel.InternalServiceAccountMaxBytes
	}
	resolve := admodel.InternalComputerIdentityOptions(
		identity,
		options.Partition,
		[]string{"uSNChanged"},
	)
	if err = admodel.InternalValidateIdentityOperation(identity, resolve); err != nil {
		return
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		if e = root.Capabilities().RequireADDS("ComputerServiceAccounts"); e != nil {
			return e
		}
		if adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3268 ||
			adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3269 {
			return admodel.ErrObjectWriteTarget
		}
		result.Computer, e = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			resolve,
		)
		if e != nil {
			return e
		}
		if e = admodel.InternalComputerClass(*result.Computer.Object); e != nil {
			return e
		}
		guid, usn, e := admodel.InternalServiceAccountLinkVersion(*result.Computer.Object)
		if e != nil {
			return e
		}
		result.Version = &admodel.ObjectVersion{
			Source:     adengine.InternalClientConfigPointer(c.engine()).Endpoint,
			GUID:       guid,
			USNChanged: usn,
		}
		reader, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalServiceAccountRangeReader)
		if !ok {
			return admodel.ErrUnsupported
		}
		if e = admodel.InternalCollectComputerServiceAccountLinks(
			ctx,
			reader,
			options,
			&result,
		); e != nil {
			return e
		}
		for i := range result.Links {
			if cause := context.Cause(ctx); cause != nil {
				return errors.Join(e, cause)
			}
			link := &result.Links[i]
			id, x := admodel.IdentityByDN(link.DistinguishedName)
			if x == nil {
				link.Observation, x = admodel.InternalResolveIdentitySession(
					ctx,
					adengine.InternalClientSession(c.engine()),
					adengine.InternalClientConfig(c.engine()),
					root,
					id,
					admodel.InternalServiceAccountIdentityOptions(
						id,
						result.Computer.Partition,
						nil,
					),
				)
				if link.Observation.Object != nil {
					account, decodeErr := admodel.InternalDecodeServiceAccount(
						*link.Observation.Object,
					)
					link.Account = &account
					x = errors.Join(x, decodeErr)
				}
			}
			link.Error = x
			e = errors.Join(e, x)
		}
		return e
	})
	if err != nil {
		result.Complete = false
	}
	return
}
