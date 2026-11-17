package engine

import (
	"context"
	"errors"
	"slices"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalRodcPasswordServer(
	ctx context.Context,
	c *Client,
	session admodel.InternalDirectorySession,
	root admodel.RootDSE,
	partition string,
	write bool,
) error {
	if err := root.Capabilities().RequireADDS("RODCPasswordReplication"); err != nil {
		return err
	}
	if root.DefaultNamingContext == nil ||
		!admodel.InternalMembershipSameDN(partition, *root.DefaultNamingContext) ||
		c.config.Endpoint.Port == 3268 ||
		c.config.Endpoint.Port == 3269 {
		return admodel.ErrRODCPasswordPolicyTarget
	}
	server, err := admodel.InternalReadObjectSyncServer(ctx, session)
	if err != nil {
		return errors.Join(admodel.ErrRODCPasswordPolicyCapability, err)
	}
	attribute := "msDS-hasMasterNCs"
	if server.InternalRodc {
		attribute = "msDS-hasFullReplicaNCs"
	}
	values, state := server.InternalDsa.Attribute(attribute)
	if state != admodel.AttributePresent ||
		!slices.ContainsFunc(
			values,
			func(value []byte) bool { return admodel.InternalMembershipSameDN(string(value), partition) },
		) {
		return admodel.ErrRODCPasswordPolicyTarget
	}
	if write && server.InternalRodc {
		return admodel.ErrRODCPasswordPolicyTarget
	}
	return nil
}
