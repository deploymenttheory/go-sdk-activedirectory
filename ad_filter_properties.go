package activedirectory

import "strings"

// Direct aliases are from ADObject/ADPrincipal/ADAccount/ADUser/ADComputer/
// ADGroup factory metadata. Date wire syntaxes are explicit schema facts,
// not inferred from names or the variable's Go type. See docs/ad-filters.md.
func adFilterProperties(profile ADFilterProfile) map[string]adFilterProperty {
	properties := make(map[string]adFilterProperty)
	add := func(syntax ADFilterSyntax, pairs ...string) {
		for i := 0; i < len(pairs); i += 2 {
			properties[strings.ToLower(pairs[i])] = adFilterProperty{ADFilterProperty: ADFilterProperty{Attribute: pairs[i+1], Syntax: syntax}}
		}
	}
	add(ADFilterString, "DistinguishedName", "distinguishedName", "ObjectClass", "objectClass", "CanonicalName", "canonicalName", "CN", "cn", "Description", "description", "DisplayName", "displayName", "LastKnownParent", "lastKnownParent", "ObjectCategory", "objectCategory", "Name", "name")
	add(ADFilterGUID, "ObjectGUID", "objectGUID")
	add(ADFilterSID, "objectSid", "objectSid", "sIDHistory", "sIDHistory")
	add(ADFilterBoolean, "Deleted", "isDeleted", "isDeleted", "isDeleted")
	add(ADFilterGeneralizedTime, "Created", "createTimeStamp", "Modified", "modifyTimeStamp", "createTimeStamp", "createTimeStamp", "modifyTimeStamp", "modifyTimeStamp", "whenCreated", "whenCreated", "whenChanged", "whenChanged")
	for _, name := range []string{"ProtectedFromAccidentalDeletion"} {
		properties[strings.ToLower(name)] = adFilterProperty{computed: "unsupported"}
	}
	if profile == ADFilterObject {
		return properties
	}
	add(ADFilterString, "SamAccountName", "sAMAccountName", "HomePage", "wWWHomePage", "MemberOf", "memberOf")
	add(ADFilterSID, "SID", "objectSid", "SIDHistory", "sIDHistory")
	if profile == ADFilterGroup {
		add(ADFilterString, "Members", "member")
		properties["groupcategory"] = adFilterProperty{ADFilterProperty: ADFilterProperty{Attribute: "groupType"}, computed: "category"}
		properties["groupscope"] = adFilterProperty{ADFilterProperty: ADFilterProperty{Attribute: "groupType"}, computed: "scope"}
		properties["managedby"] = adFilterProperty{computed: "unsupported"}
		return properties
	}
	add(ADFilterString, "UserPrincipalName", "userPrincipalName", "ServicePrincipalNames", "servicePrincipalName")
	add(ADFilterInteger, "BadLogonCount", "badPwdCount")
	add(ADFilterFileTime, "AccountLockoutTime", "lockoutTime", "LastBadPasswordAttempt", "badPasswordTime", "LastLogonDate", "lastLogonTimestamp", "PasswordLastSet", "pwdLastSet", "lastLogon", "lastLogon", "lastLogonTimestamp", "lastLogonTimestamp", "pwdLastSet", "pwdLastSet", "badPasswordTime", "badPasswordTime", "lockoutTime", "lockoutTime", "accountExpires", "accountExpires")
	for _, flag := range []struct {
		name   string
		mask   uint64
		invert bool
	}{
		{"Enabled", 2, true}, {"PasswordNeverExpires", 65536, false}, {"PasswordNotRequired", 32, false}, {"AllowReversiblePasswordEncryption", 128, false}, {"AccountNotDelegated", 1048576, false}, {"TrustedForDelegation", 524288, false}, {"TrustedToAuthForDelegation", 16777216, false}, {"DoesNotRequirePreAuth", 4194304, false}, {"HomedirRequired", 8, false}, {"UseDESKeyOnly", 2097152, false}, {"MNSLogonAccount", 131072, false},
	} {
		properties[strings.ToLower(flag.name)] = adFilterProperty{ADFilterProperty: ADFilterProperty{Attribute: "userAccountControl"}, computed: "flag", mask: flag.mask, invert: flag.invert}
	}
	for _, name := range []string{"AccountExpirationDate", "CannotChangePassword", "Certificates", "LockedOut", "PasswordExpired", "PrimaryGroup", "KerberosEncryptionType", "CompoundIdentitySupported", "PrincipalsAllowedToDelegateToAccount", "AuthenticationPolicy", "AuthenticationPolicySilo"} {
		properties[strings.ToLower(name)] = adFilterProperty{computed: "unsupported"}
	}
	if profile == ADFilterComputer {
		properties["samaccountname"] = adFilterProperty{ADFilterProperty: ADFilterProperty{Attribute: "sAMAccountName", Syntax: ADFilterString}, computed: "computer-sam"}
		add(ADFilterString, "DNSHostName", "dNSHostName", "ServiceAccount", "msDS-HostServiceAccount", "Location", "location", "OperatingSystem", "operatingSystem", "OperatingSystemHotfix", "operatingSystemHotfix", "OperatingSystemServicePack", "operatingSystemServicePack", "OperatingSystemVersion", "operatingSystemVersion")
		for _, name := range []string{"IPv4Address", "IPv6Address", "ManagedBy"} {
			properties[strings.ToLower(name)] = adFilterProperty{computed: "unsupported"}
		}
		return properties
	}
	add(ADFilterString, "GivenName", "givenName", "Surname", "sn", "HomeDirectory", "homeDirectory", "HomeDrive", "homeDrive", "OtherName", "middleName", "LogonWorkstations", "userWorkstations", "ProfilePath", "profilePath", "ScriptPath", "scriptPath", "OfficePhone", "telephoneNumber", "Company", "company", "Department", "department", "Fax", "facsimileTelephoneNumber", "Initials", "initials", "MobilePhone", "mobile", "HomePhone", "homePhone", "Office", "physicalDeliveryOfficeName", "PostalCode", "postalCode", "POBox", "postOfficeBox", "State", "st", "StreetAddress", "streetAddress", "Title", "title", "Division", "division", "Country", "c", "City", "l", "EmployeeID", "employeeID", "EmployeeNumber", "employeeNumber", "Organization", "o", "EmailAddress", "mail")
	properties["smartcardlogonrequired"] = adFilterProperty{ADFilterProperty: ADFilterProperty{Attribute: "userAccountControl"}, computed: "flag", mask: 262144}
	properties["manager"] = adFilterProperty{computed: "unsupported"}
	return properties
}

func (b *adFilterBinder) computed(node *adExpressionNode, property adFilterProperty, value any) (Filter, error) {
	if property.computed == "computer-sam" {
		// The reference converter accepts explicit computer account names and
		// wildcard patterns directly. Other names require directory resolution;
		// an offline compiler must not guess or silently append a dollar sign.
		text, ok := value.(string)
		if !ok {
			return Filter{}, ErrADFilterConversion
		}
		pattern, err := adDecodePattern(text, node.value.kind == 's', node.op == "-like" || node.op == "-notlike")
		if err != nil {
			return Filter{}, err
		}
		if len(pattern) == 1 && !strings.HasSuffix(string(pattern[0].value), "$") {
			return Filter{}, ErrADFilterProperty
		}
		return b.comparison(node, property, value, node.value.kind == 's')
	}
	if node.op != "-eq" && node.op != "-ne" {
		return Filter{}, ErrADFilterConversion
	}
	mask, invert := property.mask, property.invert
	switch property.computed {
	case "flag":
		v, err := adBool(value)
		if err != nil {
			return Filter{}, err
		}
		if !v {
			invert = !invert
		}
	case "category":
		s, ok := value.(string)
		if !ok {
			return Filter{}, ErrADFilterConversion
		}
		mask = 2147483648
		switch strings.ToLower(s) {
		case "security":
		case "distribution":
			invert = true
		default:
			return Filter{}, ErrADFilterConversion
		}
	case "scope":
		s, ok := value.(string)
		if !ok {
			return Filter{}, ErrADFilterConversion
		}
		switch strings.ToLower(s) {
		case "domainlocal":
			mask = 4
		case "global":
			mask = 2
		case "universal":
			mask = 8
		default:
			return Filter{}, ErrADFilterConversion
		}
	default:
		return Filter{}, ErrADFilterProperty
	}
	if node.op == "-ne" {
		invert = !invert
	}
	filter := FilterBitAnd(property.Attribute, mask)
	if property.computed == "category" {
		filter = FilterExtensible(ExtensibleFilter{Attribute: property.Attribute, Rule: MatchingRuleBitAnd, Value: FilterInteger(-2147483648)})
	}
	if invert {
		filter = FilterNot(filter)
	}
	return filter, nil
}
