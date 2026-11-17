package model

import (
	"errors"
	"slices"
	"strings"
)

var (
	ErrNotUser        = errors.New("directory object is not a supported user")
	ErrInvalidUser    = errors.New("invalid user request")
	ErrUserCapability = errors.New(
		"requested user property is unsupported for this directory type",
	)
	ErrUserCreationIncomplete = errors.New(
		"user creation did not complete all requested stages; inspect stage results before further writes",
	)
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

// CreateUserRequest uses the configured Users container when Parent is omitted.
// Class defaults to user;
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

func InternalUserProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectClass",
		"objectGUID",
		"objectSid",
		"name",
		"sAMAccountName",
		"userPrincipalName",
		"givenName",
		"sn",
		"displayName",
		"description",
		"mail",
		"telephoneNumber",
		"mobile",
		"department",
		"company",
		"title",
		"physicalDeliveryOfficeName",
		"l",
		"st",
		"streetAddress",
		"postalCode",
		"homeDirectory",
		"homeDrive",
		"profilePath",
		"scriptPath",
		"manager",
		"accountExpires",
		"pwdLastSet",
		"lastLogonTimestamp",
		"userAccountControl",
		"msDS-UserAccountDisabled",
		"ms-DS-UserPasswordNotRequired",
		"msDS-UserDontExpirePassword",
		"servicePrincipalName",
		"userCertificate",
	)
}

func InternalUserIdentityOptions(
	identity Identity,
	partition string,
	properties []string,
) ResolveIdentityOptions {
	target := IdentityTargetObject
	if identity.Form() == IdentityFormSID || identity.Form() == IdentityFormAccountName {
		target = IdentityTargetAccount
	}
	return ResolveIdentityOptions{
		Target:     target,
		Partition:  partition,
		Properties: InternalUserProperties(properties),
	}
}

func InternalUserClass(object Object) error {
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

func InternalDecodeUser(object Object) (User, error) {
	user := User{
		DistinguishedName:     object.DistinguishedName,
		Raw:                   object,
		ServicePrincipalNames: object.Values("servicePrincipalName"),
		Certificates:          object.Values("userCertificate"),
	}
	if err := InternalUserClass(object); err != nil {
		return user, err
	}
	decoder := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	user.Name = decoder.InternalText("name")
	for _, field := range InternalUserTextFields(&user.UserProperties) {
		*field.InternalValue = decoder.InternalText(field.InternalAttribute)
	}
	for attribute, destination := range map[string]**FileTime{"accountExpires": &user.AccountExpires, "pwdLastSet": &user.PasswordLastSet, "lastLogonTimestamp": &user.LastLogonDate} {
		values := object.Values(attribute)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			decoder.InternalErrors = append(decoder.InternalErrors, err)
			continue
		}
		stamp, err := value.FileTime()
		if err != nil {
			decoder.InternalErrors = append(decoder.InternalErrors, err)
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
			decoder.InternalErrors = append(decoder.InternalErrors, err)
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
		decoder.InternalErrors = append(decoder.InternalErrors, err)
	}
	if flags := user.UserAccountControl; flags != nil {
		enabled, notRequired, neverExpires, smartcard := !flags.Has(
			2,
		), flags.Has(
			32,
		), flags.Has(
			65536,
		), flags.Has(
			262144,
		)
		user.Enabled, user.PasswordNotRequired, user.PasswordNeverExpires, user.SmartcardLogonRequired = &enabled, &notRequired, &neverExpires, &smartcard
	} else {
		disabled := InternalDecodeScalar(
			&decoder,
			"msDS-UserAccountDisabled",
			InternalParseLDAPBool,
		)
		if disabled != nil {
			enabled := !*disabled
			user.Enabled = &enabled
		}
		user.PasswordNotRequired = InternalDecodeScalar(
			&decoder,
			"ms-DS-UserPasswordNotRequired",
			InternalParseLDAPBool,
		)
		user.PasswordNeverExpires = InternalDecodeScalar(
			&decoder,
			"msDS-UserDontExpirePassword",
			InternalParseLDAPBool,
		)
	}
	return user, errors.Join(decoder.InternalErrors...)
}

func InternalUserMutationResult(
	mutation ObjectMutationResult,
	err error,
) (UserMutationResult, error) {
	result := UserMutationResult{Mutation: mutation}
	if mutation.After != nil {
		user, decodeErr := InternalDecodeUser(*mutation.After)
		result.User = &user
		err = errors.Join(err, decodeErr)
	}
	return result, err
}
