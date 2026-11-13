package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

func topologyMutationContext(ctx context.Context, c *Client) (context.Context, context.CancelFunc, error) {
	if c == nil || c.session == nil {
		return ctx, func() {}, ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	return bounded, cancel, nil
}
func (c *Client) topologyMutationRoot(ctx context.Context, options ObjectMutationOptions) (RootDSE, ObjectMutationOptions, error) {
	root, err := c.RootDSE(ctx, RootDSEOptions{})
	if err != nil {
		return root, options, err
	}
	configuration, err := topologyConfiguration(root, c.config, options.Partition)
	options.Partition = configuration
	return root, options, err
}
func topologyMutationInput(identity Identity, options ObjectMutationOptions) error {
	if err := topologyIdentity(identity, ResolveIdentityOptions{Partition: options.Partition, Properties: options.Properties}); err != nil {
		return err
	}
	return validateObjectOptions(identity, options)
}
func topologyTextChange(name string, value *string) []AttributeChange {
	if value == nil {
		return nil
	}
	return []AttributeChange{{Attribute: name, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*value))}}}
}
func topologyValidateChanges(changes []AttributeChange, managed []string) ([]ldapAttributeModification, error) {
	for _, change := range changes {
		for _, name := range managed {
			if strings.EqualFold(change.Attribute, name) {
				return nil, ErrReplicationTopology
			}
		}
	}
	return objectChanges(changes)
}
func (c *Client) topologyModify(ctx context.Context, identity Identity, options ObjectMutationOptions, parent, class string, properties []string, prepare func(Object) ([]ldapAttributeModification, error)) (ObjectMutationResult, error) {
	return c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{Properties: properties}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if _, err := topologyConfiguration(root, c.config, options.Partition); err != nil {
			return err
		}
		if err := topologyDirectChild(*observed.Object, parent, class); err != nil {
			return err
		}
		mods, err := prepare(*observed.Object)
		if err != nil {
			return err
		}
		if len(mods) == 0 {
			if options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			result.After = result.Before
			result.ReadbackComplete = true
			result.Verified = true
			return nil
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: mods, controls: controls}, false, result); err != nil {
			return err
		}
		options.Properties = append(slices.Clone(options.Properties), properties...)
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(options, mods), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, mods, "")
	})
}
func (c *Client) topologyDelete(ctx context.Context, identity Identity, options ObjectMutationOptions, parent, class string) (ObjectMutationResult, error) {
	return c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if _, err := topologyConfiguration(root, c.config, options.Partition); err != nil {
			return err
		}
		if err := topologyDirectChild(*observed.Object, parent, class); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}, false, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
}
func (c *Client) topologyLinkedSite(ctx context.Context, identity Identity, configuration string) (IdentityResult, error) {
	var result IdentityResult
	options := ResolveIdentityOptions{Partition: configuration, Properties: topologySiteProperties(nil)}
	if err := topologyIdentity(identity, options); err != nil {
		return result, err
	}
	result, err := c.ResolveIdentity(ctx, identity, options)
	if err != nil {
		return result, err
	}
	return result, topologyDirectChild(*result.Object, "CN=Sites,"+configuration, "site")
}
func topologyStep(result *ReplicationSiteMutationResult, name string, mutation ObjectMutationResult, err error) error {
	result.Steps = append(result.Steps, ReplicationTopologyStep{Name: name, Mutation: mutation, Error: err})
	return err
}
func topologyAfterMutationError(mutation ObjectMutationResult, err error) error {
	if err != nil && mutation.State == ObjectWriteAccepted {
		return errors.Join(ErrObjectReadback, err)
	}
	return err
}
