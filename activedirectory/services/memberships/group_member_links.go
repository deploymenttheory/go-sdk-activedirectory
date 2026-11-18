package memberships

import (
	"context"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// GroupMemberLinks follows every member range, retaining each raw response on
// failure. Primary-group membership, nested expansion, FSP resolution, referral
// chasing and principal-to-group discovery are deliberately separate operations.
//
// Related cmdlet: Get-ADGroupMember.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember?view=windowsserver2025-ps
func (c *Service) GroupMemberLinks(
	ctx context.Context,
	identity adshared.Identity,
	options GroupMemberLinksOptions,
) (result GroupMemberLinksResult, err error) {
	options, err = admodel.InternalNormalizeGroupMemberLinks(options)
	if err != nil {
		return result, err
	}
	resolve := admodel.InternalGroupIdentityOptions(
		identity,
		options.Partition,
		[]string{"uSNChanged"},
	)
	if err = admodel.InternalValidateIdentityOperation(identity, resolve); err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, readErr := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if readErr != nil {
			return readErr
		}
		if root.Capabilities().Type == admodel.DirectoryADDS &&
			(adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3268 || adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3269) {
			return admodel.ErrGroupMembershipTarget
		}
		if options.IncludeTTL &&
			!slices.Contains(root.SupportedControls, admodel.InternalGroupLinkTTL) {
			return admodel.ErrGroupMembershipTTLUnsupported
		}
		result.Observation, readErr = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			resolve,
		)
		if readErr != nil {
			return readErr
		}
		if err := admodel.InternalGroupClass(*result.Observation.Object); err != nil {
			return err
		}
		guid, usn, err := admodel.InternalGroupMemberVersion(*result.Observation.Object)
		if err != nil {
			return err
		}
		result.Version = &admodel.ObjectVersion{
			Source:     adengine.InternalClientConfigPointer(c.engine()).Endpoint,
			GUID:       guid,
			USNChanged: usn,
		}
		reader, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalGroupMemberReader)
		if !ok {
			return admodel.ErrUnsupported
		}
		return admodel.InternalCollectGroupMemberLinks(ctx, reader, options, &result)
	})
	if err != nil {
		result.Complete = false
	}
	return result, err
}
