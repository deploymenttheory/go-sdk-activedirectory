package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// SyncObject invokes documented rootDSE replicateSingleObject exactly once.
// It first validates source/destination DSA, configuration and NC identities,
// the source object and destination parent. PasswordOnly requires a writable
// AD DS source, an RODC destination, and an allowed policy/control-access check.
// Permissions are ultimately checked by the server when executing the write.
// No referral, reconnect, automatic replay or forest synchronization is used.
// Cancellation/loss of response after submission is uncertain, even if abandon
// succeeds. Accepted remains accepted when later readback or cleanup fails.
func (c *Client) SyncObject(
	ctx context.Context,
	request admodel.SyncObjectRequest,
) (result admodel.SyncObjectResult, err error) {
	return InternalClientSyncObjectDial(c, ctx, request, Dial)
}

func InternalClientSyncObjectDial(c *Client,
	ctx context.Context,
	request admodel.SyncObjectRequest,
	dial func(context.Context, admodel.Config) (*Client, error),
) (result admodel.SyncObjectResult, err error) {
	if err = request.Validate(); err != nil {
		return result, err
	}
	request.Object.ObjectGUID = slices.Clone(request.Object.ObjectGUID)
	request.Properties = slices.Clone(request.Properties)
	err = InternalClientRead(c, ctx, func(bounded context.Context) error {
		writer, ok := c.session.(admodel.InternalLdapModifySession)
		if !ok {
			return admodel.ErrUnsupported
		}
		source, openErr := dial(bounded, request.Source)
		if openErr != nil {
			return fmt.Errorf("source preflight: %w", openErr)
		}
		operationErr := InternalClientRead(
			source,
			bounded,
			func(sourceContext context.Context) error {
				return admodel.InternalSynchronizeObject(
					sourceContext,
					writer,
					source.session,
					request,
					&result,
				)
			},
		)
		return errors.Join(operationErr, source.Close())
	})
	return result, admodel.InternalObjectSyncError(err)
}
