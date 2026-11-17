package groups

import (
	"context"
	"errors"
	"slices"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// Group supports explicit DN/GUID identities in AD DS and AD LDS. AD DS also
// supports SID and literal unqualified SAM account names. The resolved object's
// class is checked, including when its identity matches another account type.
func (c *Service) Group(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (GroupResult, error) {
	if options.Target > admodel.IdentityTargetAccount {
		return admodel.GroupResult{}, admodel.ErrInvalidIdentity
	}
	options = admodel.InternalGroupIdentityOptions(identity, options.Partition, options.Properties)
	observation, err := c.engine().ResolveIdentity(ctx, identity, options)
	result := admodel.GroupResult{Observation: observation}
	if observation.Object != nil {
		group, decodeErr := admodel.InternalDecodeGroup(*observation.Object)
		result.Group = &group
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// Groups intersects the caller's typed or raw LDAP filter with the group class.
// Empty Base uses Config.Partition or the server's default naming context.
// Scope, paging and caller limits retain SearchOptions semantics. Partial raw
// results and decode failures are returned; group membership is not expanded.
func (c *Service) Groups(
	ctx context.Context,
	options adshared.SearchOptions,
) (GroupsResult, error) {
	var result admodel.GroupsResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	options.Properties = admodel.InternalGroupProperties(options.Properties)
	class := admodel.FilterEqual("objectClass", admodel.FilterText("group"))
	if !admodel.InternalFilterUnset(options.TypedFilter) {
		options.TypedFilter = admodel.FilterAnd(class, options.TypedFilter)
	} else if options.Filter != "" {
		options.Filter = "(&(objectClass=group)" + options.Filter + ")"
	} else {
		options.TypedFilter = class
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == admodel.DirectoryUnknown {
			return admodel.ErrUnsupported
		}
		if options.Base == "" {
			options.Base = adengine.InternalClientConfig(c.engine()).Partition
			if options.Base == "" && root.DefaultNamingContext != nil {
				options.Base = *root.DefaultNamingContext
			}
			if options.Base == "" {
				return admodel.ErrNoDefaultPartition
			}
		}
		identity, err := admodel.IdentityByDN(options.Base)
		if err != nil {
			return err
		}
		if _, _, err := admodel.InternalIdentityPartition(
			identity,
			adengine.InternalClientConfig(c.engine()).Partition,
			root,
		); err != nil {
			return err
		}
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			options,
		)
		for _, object := range result.Observation.Objects {
			group, decodeErr := admodel.InternalDecodeGroup(object)
			result.Groups = append(result.Groups, group)
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

func (c *Service) CreateGroup(
	ctx context.Context,
	request CreateGroupRequest,
) (GroupMutationResult, error) {
	if err := admodel.InternalValidateAccountCreationOptions(
		request.Parent,
		request.Options,
	); err != nil {
		return admodel.GroupMutationResult{}, err
	}
	if request.Options.ExpectedVersion != nil {
		return admodel.GroupMutationResult{}, admodel.ErrObjectControlUnsupported
	}
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) {
		return admodel.GroupMutationResult{}, admodel.ErrInvalidGroup
	}
	flags, err := admodel.InternalGroupFlags(request.Category, request.Scope)
	if err != nil {
		return admodel.GroupMutationResult{}, err
	}
	fields := admodel.InternalGroupTextFields(
		request.SAMAccountName,
		request.Description,
		request.DisplayName,
		request.HomePage,
		request.ManagedByDN,
	)
	if err := admodel.InternalValidateGroupText(fields); err != nil {
		return admodel.GroupMutationResult{}, err
	}
	attributes := make(map[string][]admodel.RawValue, len(request.Attributes)+len(fields)+1)
	for name, values := range request.Attributes {
		key := strings.ToLower(name)
		if key == "grouptype" {
			return admodel.GroupMutationResult{}, admodel.ErrInvalidGroup
		}
		if _, exists := attributes[key]; exists {
			return admodel.GroupMutationResult{}, admodel.ErrInvalidGroup
		}
		attributes[key] = values
	}
	for _, field := range fields {
		key := strings.ToLower(field.Attribute)
		if _, exists := attributes[key]; exists {
			return admodel.GroupMutationResult{}, admodel.ErrInvalidGroup
		}
		attributes[key] = field.Values
	}
	attributes["groupType"] = []admodel.RawValue{admodel.NewRawValue([]byte(flags.LDAPString()))}
	if _, err := admodel.InternalCreateObjectAttributes(attributes); err != nil {
		return admodel.GroupMutationResult{}, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return admodel.GroupMutationResult{}, admodel.ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	if request.Parent.Form() == 0 {
		err := adengine.InternalClientRead(c.engine(), bounded, func(ctx context.Context) error {
			root, err := admodel.InternalReadIdentityRoot(
				ctx,
				adengine.InternalClientSession(c.engine()),
			)
			if err != nil {
				return err
			}
			request.Parent, err = admodel.InternalAccountCreationParent(
				ctx,
				adengine.InternalClientSession(c.engine()),
				adengine.InternalClientConfig(c.engine()),
				root,
				request.Parent,
				request.Options,
				admodel.InternalWellKnownUsers,
			)
			return err
		})
		if err != nil {
			return admodel.GroupMutationResult{}, err
		}
	}
	request.Options.Properties = admodel.InternalGroupProperties(request.Options.Properties)
	return admodel.InternalGroupMutationResult(
		c.engine().
			CreateObject(bounded, admodel.CreateObjectRequest{Parent: request.Parent, Class: "group", Name: request.Name, Attributes: attributes, Options: request.Options}),
	)
}

// UpdateGroup submits one Modify. Scope/category changes delete the exact old
// groupType value then add its replacement in that same request, retaining
// unrelated bits and rejecting a concurrently changed value. Server scope and
// membership constraints are authoritative; no intermediate conversion occurs.
func (c *Service) UpdateGroup(
	ctx context.Context,
	request UpdateGroupRequest,
) (GroupMutationResult, error) {
	if err := admodel.InternalValidateGroupMutation(request.Identity, request.Options); err != nil {
		return admodel.GroupMutationResult{}, err
	}
	if request.Category != nil && *request.Category != admodel.GroupSecurity &&
		*request.Category != admodel.GroupDistribution {
		return admodel.GroupMutationResult{}, admodel.ErrInvalidGroup
	}
	if request.Scope != nil &&
		(*request.Scope < admodel.GroupGlobal || *request.Scope > admodel.GroupUniversal) {
		return admodel.GroupMutationResult{}, admodel.ErrInvalidGroup
	}
	fields := admodel.InternalGroupTextFields(
		request.SAMAccountName,
		request.Description,
		request.DisplayName,
		request.HomePage,
		request.ManagedByDN,
	)
	if err := admodel.InternalValidateGroupText(fields); err != nil {
		return admodel.GroupMutationResult{}, err
	}
	for _, change := range request.Changes {
		if strings.EqualFold(change.Attribute, "groupType") {
			return admodel.GroupMutationResult{}, admodel.ErrInvalidGroup
		}
	}
	changes := append(slices.Clone(request.Changes), fields...)
	var mods []admodel.InternalLdapAttributeModification
	if len(changes) != 0 {
		var err error
		mods, err = admodel.InternalObjectChanges(changes)
		if err != nil {
			return admodel.GroupMutationResult{}, err
		}
	} else if request.Category == nil && request.Scope == nil {
		return admodel.GroupMutationResult{}, admodel.ErrInvalidGroup
	}
	request.Options.Properties = admodel.InternalGroupProperties(request.Options.Properties)
	mutation, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalGroupIdentityOptions(
			request.Identity,
			request.Options.Partition,
			request.Options.Properties,
		),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalGroupClass(*observed.Object); err != nil {
				return err
			}
			writes := slices.Clone(mods)
			verification := slices.Clone(mods)
			if request.Category != nil || request.Scope != nil {
				value, err := observed.Object.Values("groupType").Single()
				if err != nil {
					return err
				}
				flags, err := value.Flags32()
				if err != nil {
					return err
				}
				next := flags
				if request.Category != nil {
					next = next.With(
						admodel.InternalGroupSecurityBit,
						*request.Category == admodel.GroupSecurity,
					)
				}
				if request.Scope != nil {
					scope, _ := admodel.InternalGroupFlags(
						admodel.GroupDistribution,
						*request.Scope,
					)
					next = (next &^ admodel.InternalGroupScopeBits) | scope
				}
				if next != flags {
					writes = append(
						writes,
						admodel.InternalLdapAttributeModification{
							InternalOperation: 1,
							InternalAttribute: "groupType",
							InternalValues:    [][]byte{value.Bytes()},
						},
						admodel.InternalLdapAttributeModification{
							InternalOperation: 0,
							InternalAttribute: "groupType",
							InternalValues:    [][]byte{[]byte(next.LDAPString())},
						},
					)
				}
				verification = append(
					verification,
					admodel.InternalLdapAttributeModification{
						InternalOperation: 2,
						InternalAttribute: "groupType",
						InternalValues:    [][]byte{[]byte(next.LDAPString())},
					},
				)
			}
			if len(writes) == 0 {
				// No server operation would enforce this precondition.
				if request.Options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				result.After, result.ReadbackComplete = observed.Object, observed.Complete
				return admodel.InternalVerifyObjectWrite(result, verification, "")
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
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
					InternalModifications: writes,
					InternalControls:      controls,
				},
				false,
				result,
			); err != nil {
				return err
			}
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				admodel.InternalObjectWriteProperties(request.Options, writes),
				false,
			); err != nil {
				return err
			}
			return admodel.InternalVerifyObjectWrite(result, verification, "")
		},
	)
	return admodel.InternalGroupMutationResult(mutation, err)
}

func (c *Service) DeleteGroup(
	ctx context.Context,
	request DeleteGroupRequest,
) (GroupMutationResult, error) {
	if err := admodel.InternalValidateGroupMutation(request.Identity, request.Options); err != nil {
		return admodel.GroupMutationResult{}, err
	}
	mutation, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalGroupIdentityOptions(request.Identity, request.Options.Partition, nil),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalGroupClass(*observed.Object); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
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
	return admodel.InternalGroupMutationResult(mutation, err)
}
