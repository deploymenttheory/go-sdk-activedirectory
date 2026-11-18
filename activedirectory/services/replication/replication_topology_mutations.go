package replication

import (
	"context"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// internalServiceTopologyMutationRoot validates the writable AD DS topology target and selects its
// configuration partition.
func internalServiceTopologyMutationRoot(c *Service,
	ctx context.Context,
	options admodel.ObjectMutationOptions,
) (admodel.RootDSE, admodel.ObjectMutationOptions, error) {
	root, err := c.engine().RootDSE(ctx, admodel.RootDSEOptions{})
	if err != nil {
		return root, options, err
	}
	configuration, err := admodel.InternalTopologyConfiguration(
		root,
		adengine.InternalClientConfig(c.engine()),
		options.Partition,
	)
	options.Partition = configuration
	return root, options, err
}

// internalServiceTopologyModify validates a topology object's class and parent before applying and
// verifying prepared modifications.
func internalServiceTopologyModify(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	parent, class string,
	properties []string,
	prepare func(admodel.Object) ([]admodel.InternalLdapAttributeModification, error),
) (admodel.ObjectMutationResult, error) {
	return adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		admodel.ResolveIdentityOptions{Properties: properties},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if _, err := admodel.InternalTopologyConfiguration(
				root,
				adengine.InternalClientConfig(c.engine()),
				options.Partition,
			); err != nil {
				return err
			}
			if err := admodel.InternalTopologyDirectChild(
				*observed.Object,
				parent,
				class,
			); err != nil {
				return err
			}
			mods, err := prepare(*observed.Object)
			if err != nil {
				return err
			}
			if len(mods) == 0 {
				if options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				result.After = result.Before
				result.ReadbackComplete = true
				result.Verified = true
				return nil
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*result.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation:     admodel.InternalLdapWriteModify,
					InternalDn:            admodel.InternalObjectGUIDTarget(*result.TargetGUID),
					InternalModifications: mods,
					InternalControls:      controls,
				},
				false,
				result,
			); err != nil {
				return err
			}
			options.Properties = append(slices.Clone(options.Properties), properties...)
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				admodel.InternalObjectWriteProperties(options, mods),
				false,
			); err != nil {
				return err
			}
			return admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, result, mods, "")
		},
	)
}

// internalServiceTopologyDelete validates a topology object's class and parent before a leaf deletion.
func internalServiceTopologyDelete(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	parent, class string,
) (admodel.ObjectMutationResult, error) {
	return adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		admodel.ResolveIdentityOptions{},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if _, err := admodel.InternalTopologyConfiguration(
				root,
				adengine.InternalClientConfig(c.engine()),
				options.Partition,
			); err != nil {
				return err
			}
			if err := admodel.InternalTopologyDirectChild(
				*observed.Object,
				parent,
				class,
			); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*result.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteDelete,
					InternalDn:        admodel.InternalObjectGUIDTarget(*result.TargetGUID),
					InternalControls:  controls,
				},
				false,
				result,
			); err != nil {
				return err
			}
			return admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				[]string{"objectGUID"},
				true,
			)
		},
	)
}

// internalServiceTopologyLinkedSite resolves and validates a site reference within the selected
// configuration partition.
func internalServiceTopologyLinkedSite(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	configuration string,
) (admodel.IdentityResult, error) {
	var result admodel.IdentityResult
	options := admodel.ResolveIdentityOptions{
		Partition:  configuration,
		Properties: admodel.InternalTopologySiteProperties(nil),
	}
	if err := admodel.InternalTopologyIdentity(identity, options); err != nil {
		return result, err
	}
	result, err := c.engine().ResolveIdentity(ctx, identity, options)
	if err != nil {
		return result, err
	}
	return result, admodel.InternalTopologyDirectChild(
		*result.Object,
		"CN=Sites,"+configuration,
		"site",
	)
}
