package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrNotUser                = errors.New("directory object is not a supported user")
	ErrInvalidUser            = errors.New("invalid user request")
	ErrUserCapability         = errors.New("requested user property is unsupported for this directory type")
	ErrUserCreationIncomplete = errors.New("user creation did not complete all requested stages; inspect stage results before further writes")
)

// UserProperties contains optional typed properties. Nil omits an update;
// non-nil text (including empty text) is an explicit value. Use AttributeClear
// in UpdateUserRequest.Changes to clear an attribute. AccountExpires preserves
// raw FILETIME sentinels; it is not a locale-dependent expiration date string.
type UserProperties struct {
	SAMAccountName, UserPrincipalName, GivenName, Surname                      *string
	DisplayName, Description, EmailAddress, OfficePhone, MobilePhone           *string
	Department, Company, Title, Office, City, State, StreetAddress, PostalCode *string
	HomeDirectory, HomeDrive, ProfilePath, ScriptPath, ManagerDN               *string
	AccountExpires                                                             *FileTime
	Enabled, PasswordNotRequired, PasswordNeverExpires, SmartcardLogonRequired *bool
}

type User struct {
	UserProperties
	DistinguishedName              string
	GUID                           *GUID
	SID                            *SID
	Name                           *string
	UserAccountControl             *Flags32
	PasswordLastSet, LastLogonDate *FileTime
	// These copied raw projections retain missing/unloaded/ranged states.
	ServicePrincipalNames, Certificates AttributeValues
	Raw                                 Object
}

type UserResult struct {
	User        *User
	Observation IdentityResult
}
type UsersResult struct {
	Users       []User
	Observation SearchResult
}
type UserMutationResult struct {
	User     *User
	Mutation ObjectMutationResult
}

// CreateUserRequest requires an explicit parent. Class defaults to user;
// inetOrgPerson is also supported when installed in the selected schema.
// InitialPassword is caller-owned UTF-8 and follows PasswordResetRequest's
// lifetime rules. Nil omits password setup; an explicit empty slice does not.
type CreateUserRequest struct {
	Parent          Identity
	Name, Class     string
	Properties      UserProperties
	InitialPassword []byte `json:"-"`
	Attributes      map[string][]RawValue
	Options         ObjectMutationOptions
}

func (CreateUserRequest) String() string               { return "CreateUserRequest{redacted}" }
func (CreateUserRequest) GoString() string             { return "CreateUserRequest{redacted}" }
func (CreateUserRequest) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (CreateUserRequest) MarshalText() ([]byte, error) {
	return []byte("CreateUserRequest{redacted}"), nil
}

// UserCreationResult preserves independent stage outcomes. Nil Password/Enable
// means that stage was not entered. Complete means all requested stages and
// observations completed, not a transaction or proof of successful logon.
// An accepted Add is never automatically deleted when a later stage fails.
type UserCreationResult struct {
	Creation    ObjectMutationResult
	Password    *PasswordResult
	Enable      *ObjectMutationResult
	User        *User
	Observation *UserResult
	Complete    bool
}

type UpdateUserRequest struct {
	Identity   Identity
	Properties UserProperties
	Changes    []AttributeChange
	Options    ObjectMutationOptions
}
type DeleteUserRequest struct {
	Identity Identity
	Options  ObjectMutationOptions
}

func userProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectClass", "objectGUID", "objectSid", "name", "sAMAccountName", "userPrincipalName", "givenName", "sn", "displayName", "description", "mail", "telephoneNumber", "mobile", "department", "company", "title", "physicalDeliveryOfficeName", "l", "st", "streetAddress", "postalCode", "homeDirectory", "homeDrive", "profilePath", "scriptPath", "manager", "accountExpires", "pwdLastSet", "lastLogonTimestamp", "userAccountControl", "msDS-UserAccountDisabled", "ms-DS-UserPasswordNotRequired", "msDS-UserDontExpirePassword", "servicePrincipalName", "userCertificate")
}

func userIdentityOptions(identity Identity, partition string, properties []string) ResolveIdentityOptions {
	target := IdentityTargetObject
	if identity.Form() == IdentityFormSID || identity.Form() == IdentityFormAccountName {
		target = IdentityTargetAccount
	}
	return ResolveIdentityOptions{Target: target, Partition: partition, Properties: userProperties(properties)}
}

func userClass(object Object) error {
	values, state := object.Attribute("objectClass")
	if state != AttributePresent {
		return errors.Join(ErrNotUser, ErrAttributeUnavailable)
	}
	found := false
	for _, value := range values {
		name, err := NewRawValue(value).Text()
		if err != nil {
			return errors.Join(ErrNotUser, err)
		}
		if strings.EqualFold(name, "computer") {
			return ErrNotUser
		}
		if strings.EqualFold(name, "user") || strings.EqualFold(name, "inetOrgPerson") {
			found = true
		}
	}
	if !found {
		return ErrNotUser
	}
	return nil
}

func decodeUser(object Object) (User, error) {
	user := User{DistinguishedName: object.DistinguishedName, Raw: object, ServicePrincipalNames: object.Values("servicePrincipalName"), Certificates: object.Values("userCertificate")}
	if err := userClass(object); err != nil {
		return user, err
	}
	decoder := rootDSEDecoder{attributes: object.Attributes}
	user.Name = decoder.text("name")
	for _, field := range userTextFields(&user.UserProperties) {
		*field.value = decoder.text(field.attribute)
	}
	for attribute, destination := range map[string]**FileTime{"accountExpires": &user.AccountExpires, "pwdLastSet": &user.PasswordLastSet, "lastLogonTimestamp": &user.LastLogonDate} {
		values := object.Values(attribute)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			decoder.errors = append(decoder.errors, err)
			continue
		}
		stamp, err := value.FileTime()
		if err != nil {
			decoder.errors = append(decoder.errors, err)
		} else {
			*destination = &stamp
		}
	}
	for _, attribute := range []string{"objectGUID", "objectSid", "userAccountControl"} {
		values := object.Values(attribute)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			decoder.errors = append(decoder.errors, err)
			continue
		}
		switch attribute {
		case "objectGUID":
			v, e := value.GUID()
			err = e
			if e == nil {
				user.GUID = &v
			}
		case "objectSid":
			v, e := value.SID()
			err = e
			if e == nil {
				user.SID = &v
			}
		case "userAccountControl":
			v, e := value.Flags32()
			err = e
			if e == nil {
				user.UserAccountControl = &v
			}
		}
		decoder.errors = append(decoder.errors, err)
	}
	if flags := user.UserAccountControl; flags != nil {
		enabled, notRequired, neverExpires, smartcard := !flags.Has(2), flags.Has(32), flags.Has(65536), flags.Has(262144)
		user.Enabled, user.PasswordNotRequired, user.PasswordNeverExpires, user.SmartcardLogonRequired = &enabled, &notRequired, &neverExpires, &smartcard
	} else {
		disabled := decodeScalar(&decoder, "msDS-UserAccountDisabled", parseLDAPBool)
		if disabled != nil {
			enabled := !*disabled
			user.Enabled = &enabled
		}
		user.PasswordNotRequired = decodeScalar(&decoder, "ms-DS-UserPasswordNotRequired", parseLDAPBool)
		user.PasswordNeverExpires = decodeScalar(&decoder, "msDS-UserDontExpirePassword", parseLDAPBool)
	}
	return user, errors.Join(decoder.errors...)
}

func (c *Client) User(ctx context.Context, identity Identity, options ResolveIdentityOptions) (UserResult, error) {
	if options.Target > IdentityTargetAccount {
		return UserResult{}, ErrInvalidIdentity
	}
	options = userIdentityOptions(identity, options.Partition, options.Properties)
	observed, err := c.ResolveIdentity(ctx, identity, options)
	result := UserResult{Observation: observed}
	if observed.Object != nil {
		user, decodeErr := decodeUser(*observed.Object)
		result.User = &user
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// Users searches user/inetOrgPerson objects while excluding computer subclasses.
// Typed and raw filters retain SearchOptions' mutual exclusion and bounds.
func (c *Client) Users(ctx context.Context, options SearchOptions) (UsersResult, error) {
	var result UsersResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	options.Properties = userProperties(options.Properties)
	class := FilterAnd(FilterOr(FilterEqual("objectClass", FilterText("user")), FilterEqual("objectClass", FilterText("inetOrgPerson"))), FilterNot(FilterEqual("objectClass", FilterText("computer"))))
	if !options.TypedFilter.unset() {
		options.TypedFilter = FilterAnd(class, options.TypedFilter)
	} else if options.Filter != "" {
		encoded, _ := class.LDAP()
		options.Filter = "(&" + encoded + options.Filter + ")"
	} else {
		options.TypedFilter = class
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == DirectoryUnknown {
			return ErrUserCapability
		}
		if options.Base == "" {
			options.Base = c.config.Partition
			if options.Base == "" && root.DefaultNamingContext != nil {
				options.Base = *root.DefaultNamingContext
			}
			if options.Base == "" {
				return ErrNoDefaultPartition
			}
		}
		identity, err := IdentityByDN(options.Base)
		if err != nil {
			return err
		}
		if _, _, err := identityPartition(identity, c.config.Partition, root); err != nil {
			return err
		}
		result.Observation, err = searchIdentitySession(ctx, c.session, options)
		for _, object := range result.Observation.Objects {
			user, decodeErr := decodeUser(object)
			result.Users = append(result.Users, user)
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

func userMutationResult(mutation ObjectMutationResult, err error) (UserMutationResult, error) {
	result := UserMutationResult{Mutation: mutation}
	if mutation.After != nil {
		user, decodeErr := decodeUser(*mutation.After)
		result.User = &user
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func (c *Client) UpdateUser(ctx context.Context, request UpdateUserRequest) (UserMutationResult, error) {
	if err := validateUserMutation(request.Identity, request.Options); err != nil {
		return UserMutationResult{}, err
	}
	changes, err := userAttributeChanges(request.Properties, request.Changes)
	if err != nil {
		return UserMutationResult{}, err
	}
	var mods []ldapAttributeModification
	if len(changes) > 0 {
		mods, err = objectChanges(changes)
		if err != nil {
			return UserMutationResult{}, err
		}
	} else if !userHasFlags(request.Properties) {
		return UserMutationResult{}, ErrInvalidUser
	}
	request.Options.Properties = userProperties(request.Options.Properties)
	mutation, err := c.objectMutationIdentity(ctx, request.Identity, request.Options, userIdentityOptions(request.Identity, request.Options.Partition, request.Options.Properties), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := userClass(*observed.Object); err != nil {
			return err
		}
		writes, verification := slices.Clone(mods), slices.Clone(mods)
		flagWrites, flagVerification, err := userFlagChanges(*observed.Object, root.Capabilities().Type, request.Properties)
		if err != nil {
			return err
		}
		writes = append(writes, flagWrites...)
		verification = append(verification, flagVerification...)
		if len(writes) == 0 {
			if request.Options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			result.After, result.ReadbackComplete = observed.Object, observed.Complete
			return verifyObjectWrite(result, verification, "")
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: writes, controls: controls}, false, result); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(request.Options, writes), false); err != nil {
			return err
		}
		return verifyObjectWrite(result, verification, "")
	})
	return userMutationResult(mutation, err)
}

// DeleteUser is leaf-only and never deletes group objects or their members.
func (c *Client) DeleteUser(ctx context.Context, request DeleteUserRequest) (UserMutationResult, error) {
	if err := validateUserMutation(request.Identity, request.Options); err != nil {
		return UserMutationResult{}, err
	}
	mutation, err := c.objectMutationIdentity(ctx, request.Identity, request.Options, userIdentityOptions(request.Identity, request.Options.Partition, nil), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := userClass(*observed.Object); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}, false, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
	return userMutationResult(mutation, err)
}
