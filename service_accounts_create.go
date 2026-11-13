package activedirectory

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Prerequisites are observations on the selected DC, not an authorization or
// password-retrieval guarantee. KDS contains metadata only, never root key data.
type ServiceAccountPrerequisites struct {
	RootDSE         RootDSE
	Domain          IdentityResult
	Schema          SearchResult
	KDS             SearchResult
	EligibleKDSKeys []string
	Complete        bool
}

func serviceAccountPrerequisites(ctx context.Context, session directorySession, config Config, root RootDSE, kind ServiceAccountKind, partition string) (result ServiceAccountPrerequisites, err error) {
	result.RootDSE = root
	fail := func(e error) (ServiceAccountPrerequisites, error) {
		return result, errors.Join(ErrServiceAccountPrerequisite, e)
	}
	if e := root.Capabilities().RequireADDS("CreateServiceAccount"); e != nil {
		return fail(e)
	}
	if config.Endpoint.Port == 3268 || config.Endpoint.Port == 3269 || root.Capabilities().Has("1.2.840.113556.1.4.1920") {
		return fail(ErrObjectWriteTarget)
	}
	minimum := uint32(4)
	if kind == ServiceAccountGroupManaged {
		minimum = 5
	}
	if root.DomainControllerFunctionality == nil || *root.DomainControllerFunctionality < minimum || root.SchemaNamingContext == nil || root.DefaultNamingContext == nil {
		return fail(ErrAttributeUnavailable)
	}
	if partition == "" {
		partition = config.Partition
	}
	if partition == "" {
		partition = *root.DefaultNamingContext
	}
	identity, e := IdentityByDN(partition)
	if e != nil {
		return fail(e)
	}
	result.Domain, e = resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: partition, Properties: []string{"objectClass", "instanceType", "objectGUID"}})
	if e != nil {
		return fail(e)
	}
	d := rootDSEDecoder{attributes: result.Domain.Object.Attributes}
	classes := d.texts("objectClass")
	instance := decodeScalar(&d, "instanceType", parseUint32)
	domain := false
	for _, class := range classes {
		domain = domain || strings.EqualFold(class, "domainDNS")
	}
	if !domain || instance == nil || *instance&4 == 0 {
		return fail(errors.Join(ErrObjectWriteTarget, errors.Join(d.errors...)))
	}
	result.Schema, e = searchIdentitySession(ctx, session, SearchOptions{Base: *root.SchemaNamingContext, Scope: ScopeOneLevel, TypedFilter: FilterAnd(FilterEqual("objectClass", FilterText("classSchema")), FilterEqual("ldapDisplayName", FilterText(serviceAccountClassName(kind)))), Properties: []string{"ldapDisplayName", "isDefunct", "objectClassCategory"}, ResultLimit: 2})
	if e != nil {
		return fail(e)
	}
	if !result.Schema.Complete || len(result.Schema.Objects) != 1 {
		return fail(ErrInvalidResult)
	}
	d = rootDSEDecoder{attributes: result.Schema.Objects[0].Attributes}
	defunct := decodeScalar(&d, "isDefunct", parseLDAPBool)
	category := decodeScalar(&d, "objectClassCategory", parseUint32)
	if (defunct != nil && *defunct) || category == nil || *category != 1 || len(d.errors) > 0 {
		return fail(errors.Join(ErrInvalidResult, errors.Join(d.errors...)))
	}
	if kind == ServiceAccountGroupManaged {
		if root.ConfigurationNamingContext == nil || root.CurrentTime == nil {
			return fail(ErrAttributeUnavailable)
		}
		result.KDS, e = searchIdentitySession(ctx, session, SearchOptions{Base: "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services," + *root.ConfigurationNamingContext, Scope: ScopeOneLevel, TypedFilter: FilterEqual("objectClass", FilterText("msKds-ProvRootKey")), Properties: []string{"cn", "msKds-UseStartTime", "msKds-CreateTime"}, ResultLimit: 128})
		if e != nil {
			return fail(e)
		}
		if !result.KDS.Complete {
			return fail(ErrIncompleteResult)
		}
		now, e := FileTimeFromTime(*root.CurrentTime)
		if e != nil {
			return fail(e)
		}
		// GKDI uses 10-hour intervals. A future key within the current interval
		// cannot authorize its start; compare against the current interval start.
		const cycle = uint64(360000000000)
		start := uint64(now) / cycle * cycle
		for _, key := range result.KDS.Objects {
			value, e := key.Values("msKds-UseStartTime").Single()
			if e != nil {
				return fail(e)
			}
			ticks, e := value.Int64()
			if e != nil || ticks < 0 {
				return fail(errors.Join(ErrInvalidResult, e))
			}
			if uint64(ticks) <= start {
				result.EligibleKDSKeys = append(result.EligibleKDSKeys, key.DistinguishedName)
			}
		}
		if len(result.EligibleKDSKeys) == 0 {
			return fail(ErrAttributeUnavailable)
		}
	}
	result.Complete = true
	return result, nil
}

func serviceAccountDefaultParent(ctx context.Context, session directorySession, config Config, root RootDSE, parent Identity, options ObjectMutationOptions) (Identity, error) {
	if parent.Form() != 0 {
		return parent, nil
	}
	partition := options.Partition
	if partition == "" {
		partition = config.Partition
	}
	if partition == "" && root.DefaultNamingContext != nil {
		partition = *root.DefaultNamingContext
	}
	identity, err := IdentityByDN(partition)
	if err != nil {
		return Identity{}, err
	}
	observed, err := resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: partition, Properties: []string{"objectGUID", "otherWellKnownObjects"}})
	fail := func(e error) (Identity, error) {
		return Identity{}, &AccountCreationParentError{Observation: observed, Cause: e}
	}
	if err != nil {
		return fail(err)
	}
	if observed.Object.Values("otherWellKnownObjects").State != AttributePresent {
		return fail(ErrAttributeUnavailable)
	}
	// Reuse the bounded DN-binary decoder with the other-well-known projection.
	d := rootDSEDecoder{attributes: map[string][][]byte{"wellknownobjects": observed.Object.Attributes["otherwellknownobjects"]}}
	containers := wellKnownContainers(&d)
	if err = errors.Join(d.errors...); err != nil {
		return fail(err)
	}
	parent, err = IdentityByDN(containers["1EB93889E40C45DF9F0C64D23BBB6237"])
	if err != nil {
		return fail(err)
	}
	if _, _, err = identityPartition(parent, partition, root); err != nil {
		return fail(err)
	}
	return parent, nil
}

func (c *Client) CreateServiceAccount(ctx context.Context, request CreateServiceAccountRequest) (result ServiceAccountCreationResult, err error) {
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	if ctx == nil {
		return result, ErrInvalidServiceAccount
	}
	if serviceAccountClassName(request.Kind) == "" || request.Name == "" || !validDirectoryText(request.Name) {
		return result, ErrInvalidServiceAccount
	}
	if err = validateAccountCreationOptions(request.Parent, request.Options); err != nil {
		return
	}
	if err = validateServiceAccountProjection(request.Options.Properties); err != nil {
		return
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if err = validateServiceAccountControl(request.Control); err != nil {
		return
	}
	if request.Kind == ServiceAccountStandalone && (request.ManagedPasswordIntervalDays != nil || request.PasswordReaders != nil) {
		return result, ErrInvalidServiceAccount
	}
	if request.Kind == ServiceAccountGroupManaged && request.InitialPassword != nil {
		return result, ErrInvalidServiceAccount
	}
	if request.OutboundAuthenticationOnly && (request.Kind != ServiceAccountGroupManaged || request.Properties.DNSHostName != nil || request.ManagedPasswordIntervalDays != nil || request.PasswordReaders != nil || request.Properties.CompoundIdentitySupported != nil) {
		return result, ErrInvalidServiceAccount
	}
	if request.ManagedPasswordIntervalDays != nil && (*request.ManagedPasswordIntervalDays == 0 || *request.ManagedPasswordIntervalDays > 2147483647) {
		return result, ErrInvalidServiceAccount
	}
	if request.Kind == ServiceAccountGroupManaged && !request.OutboundAuthenticationOnly && (request.Properties.DNSHostName == nil || *request.Properties.DNSHostName == "") {
		return result, ErrInvalidServiceAccount
	}
	for name := range request.Attributes {
		if serviceAccountManaged(name) || (request.OutboundAuthenticationOnly && strings.EqualFold(name, "dNSHostName")) {
			return result, ErrInvalidServiceAccount
		}
	}
	properties := request.Properties
	if properties.SAMAccountName == nil {
		properties.SAMAccountName = &request.Name
	}
	changes, err := serviceAccountChanges(properties, nil)
	if err != nil {
		return result, err
	}
	attributes := make(map[string][]RawValue, len(request.Attributes)+len(changes)+3)
	for name, values := range request.Attributes {
		key := strings.ToLower(name)
		if _, ok := attributes[key]; ok {
			return result, ErrInvalidServiceAccount
		}
		attributes[key] = values
	}
	for _, change := range changes {
		key := strings.ToLower(change.Attribute)
		if _, ok := attributes[key]; ok {
			return result, ErrInvalidServiceAccount
		}
		if change.Kind == AttributeClear {
			continue
		}
		attributes[key] = change.Values
	}
	wantEnabled := request.Control.Enabled == nil || *request.Control.Enabled
	control := request.Control
	disabled := false
	if request.Kind == ServiceAccountStandalone {
		control.Enabled = &disabled
	}
	flags := accountControlValues(0x1000, control)
	attributes["useraccountcontrol"] = []RawValue{NewRawValue([]byte(flags.LDAPString()))}
	if computerHasEncryption(serviceAccountComputerProperties(properties)) {
		attributes["msds-supportedencryptiontypes"] = []RawValue{NewRawValue([]byte(computerEncryptionValues(0, serviceAccountComputerProperties(properties)).LDAPString()))}
	}
	if request.Kind == ServiceAccountGroupManaged {
		days := uint32(30)
		if request.ManagedPasswordIntervalDays != nil {
			days = *request.ManagedPasswordIntervalDays
		}
		attributes["msds-managedpasswordinterval"] = []RawValue{NewRawValue([]byte(strconv.FormatUint(uint64(days), 10)))}
	}
	if _, err = createObjectAttributes(attributes); err != nil {
		return
	}
	password := request.InitialPassword
	if request.Kind == ServiceAccountStandalone {
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
		if err = validatePasswordBytes(password); err != nil {
			return
		}
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	err = c.read(bounded, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		result.Prerequisites, e = serviceAccountPrerequisites(ctx, c.session, c.config, root, request.Kind, request.Options.Partition)
		if e != nil {
			return e
		}
		request.Options.Partition = result.Prerequisites.Domain.Partition
		request.Parent, e = serviceAccountDefaultParent(ctx, c.session, c.config, root, request.Parent, request.Options)
		if e != nil {
			return e
		}
		if request.Kind == ServiceAccountStandalone {
			session, ok := c.session.(passwordSession)
			if !ok {
				return ErrUnsupported
			}
			protection, e := session.passwordProtection(ctx, c.config.Transport)
			if e != nil {
				return e
			}
			if protection.Transport != c.config.Transport || protection.CipherBits < 128 {
				return ErrPasswordProtection
			}
		} else {
			sids, e := resolveServiceAccountReaders(ctx, c.session, c.config, root, request.PasswordReaders, result.Prerequisites.Domain.Partition)
			if e != nil {
				return e
			}
			factory, ok := c.session.(interface{ newDirectoryDescriptor(string) ([]byte, error) })
			if !ok {
				return ErrUnsupported
			}
			raw, e := factory.newDirectoryDescriptor("O:SYG:SYD:")
			if e != nil {
				return e
			}
			raw, e = replaceServiceAccountReaders(c.session, raw, sids)
			if e != nil {
				return e
			}
			attributes["msds-groupmsamembership"] = []RawValue{NewRawValue(raw)}
		}
		return nil
	})
	if err != nil {
		return
	}
	request.Options.Properties = serviceAccountProperties(request.Options.Properties)
	result.Creation, err = c.CreateObject(bounded, CreateObjectRequest{Parent: request.Parent, Class: serviceAccountClassName(request.Kind), Name: request.Name, Attributes: attributes, Options: request.Options})
	if result.Creation.After != nil {
		account, e := decodeServiceAccount(*result.Creation.After)
		result.Account = &account
		err = errors.Join(err, e)
	}
	if err != nil {
		return result, errors.Join(ErrServiceAccountCreationIncomplete, err)
	}
	if result.Creation.TargetGUID == nil || !result.Creation.Verified {
		return result, errors.Join(ErrServiceAccountCreationIncomplete, ErrObjectVerification)
	}
	identity := objectGUIDIdentity(*result.Creation.TargetGUID)
	partition := result.Creation.Partition
	if request.Kind == ServiceAccountStandalone {
		stage, e := c.ResetAccountPassword(bounded, PasswordResetRequest{Identity: identity, Partition: partition, NewPassword: password})
		result.Password = &stage
		if e != nil || stage.State != ObjectWriteAccepted {
			return result, errors.Join(ErrServiceAccountCreationIncomplete, e)
		}
		if wantEnabled {
			enabled := true
			update, e := c.UpdateServiceAccount(bounded, UpdateServiceAccountRequest{Identity: identity, Control: AccountControlPatch{Enabled: &enabled}, Options: ObjectMutationOptions{Partition: partition, Properties: request.Options.Properties}})
			result.Enable = &update.Mutation
			result.Account = update.Account
			if e != nil || !update.Mutation.Verified {
				return result, errors.Join(ErrServiceAccountCreationIncomplete, e)
			}
		} else {
			observation, e := c.ServiceAccount(bounded, identity, ResolveIdentityOptions{Partition: partition, Properties: request.Options.Properties})
			result.Observation = &observation
			result.Account = observation.Account
			if e != nil {
				return result, errors.Join(ErrServiceAccountCreationIncomplete, e)
			}
		}
	}
	result.Complete = true
	return result, nil
}
