package activedirectory

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// Claim transformation policies store their rules as a fixed XML envelope
// containing a CDATA section, not as bare rule text. The envelope and the
// shorthand expansions below are byte-for-byte what the reference module wrote
// in an isolated lab; see docs/research/claims-transformation.md and the
// captured evidence beside it.

var (
	ErrClaimTransformPolicy = errors.New("invalid claim transformation policy definition")
	ErrClaimTransformRule   = errors.New("claim transformation rule text is not acceptable")
	ErrClaimTransformLink   = errors.New("invalid claim transformation link operation")
)

const (
	claimTransformClass = "msDS-ClaimsTransformationPolicyType"
	claimTransformRules = "msDS-TransformationRules"
	// Compiled rules are server-generated and were absent on every policy the
	// reference run created. They are read for observation and never written.
	claimTransformCompiled = "msDS-TransformationRulesCompiled"
)

// claimTransformEnvelope reproduces the observed stored form exactly, including
// its irregular whitespace. Correctness here is byte equality with the
// reference, not readability, so this string must not be tidied.
const claimTransformEnvelope = " <ClaimsTransformationPolicy>     <Rules version=\"1\">         <![CDATA[%s]]>    </Rules></ClaimsTransformationPolicy>"

// claimTransformRuleMaxBytes bounds rule text before any write. The directory
// remains authoritative for the real limit; this only stops an unbounded value.
const claimTransformRuleMaxBytes = 1 << 20

func claimTransformParent(configuration string) string {
	return "CN=Claims Transformation Policies,CN=Claims Configuration,CN=Services," + configuration
}

func claimTransformProperties(extra []string) []string {
	return append(append([]string(nil), extra...), "objectGUID", "uSNChanged", "objectClass", "name",
		"displayName", "description", claimTransformRules, claimTransformCompiled)
}

// ClaimTransformRuleSet selects which rules a policy stores. Exactly one form
// applies; the zero value writes nothing and leaves an existing policy alone.
type ClaimTransformRuleSet struct {
	// AllowAll issues every claim. DenyAll issues none.
	AllowAll, DenyAll bool
	// AllowAllExcept issues every claim except the named claim type IDs;
	// DenyAllExcept issues only those. IDs are ad://ext/ claim identifiers.
	AllowAllExcept, DenyAllExcept []string
	// Rule is explicit inner rule text, wrapped in the same envelope verbatim.
	// It is never parsed or rewritten.
	Rule *string
}

func (s ClaimTransformRuleSet) empty() bool {
	return !s.AllowAll && !s.DenyAll && len(s.AllowAllExcept) == 0 && len(s.DenyAllExcept) == 0 && s.Rule == nil
}

func (s ClaimTransformRuleSet) forms() int {
	count := 0
	for _, set := range []bool{s.AllowAll, s.DenyAll, len(s.AllowAllExcept) != 0, len(s.DenyAllExcept) != 0, s.Rule != nil} {
		if set {
			count++
		}
	}
	return count
}

// render produces the stored attribute value, or reports that no rule applies.
//
// The spacing in each expansion is the reference module's own and is
// deliberately inconsistent between forms: AllowAllExcept emits a space before
// "!=" while DenyAllExcept emits none around "==". Both were observed.
func (s ClaimTransformRuleSet) render() (string, bool, error) {
	if s.empty() {
		return "", false, nil
	}
	if s.forms() != 1 {
		return "", false, ErrClaimTransformPolicy
	}
	var inner string
	switch {
	case s.AllowAll:
		inner = "C1:[]=>Issue(claim=C1);"
	case s.DenyAll:
		inner = `C1:[Type !~ "*"]=>Issue(claim=C1);`
	case len(s.AllowAllExcept) != 0:
		clause, err := claimTransformTypeClause(s.AllowAllExcept, ` !=`)
		if err != nil {
			return "", false, err
		}
		inner = "C1:[" + clause + "]=>Issue(claim=C1);"
	case len(s.DenyAllExcept) != 0:
		clause, err := claimTransformTypeClause(s.DenyAllExcept, "==")
		if err != nil {
			return "", false, err
		}
		inner = "C1:[" + clause + "]=>Issue(claim=C1);"
	default:
		if err := validateClaimTransformRule(*s.Rule); err != nil {
			return "", false, err
		}
		inner = *s.Rule
	}
	return claimTransformEnvelopeFor(inner), true, nil
}

func claimTransformEnvelopeFor(inner string) string {
	return strings.Replace(claimTransformEnvelope, "%s", inner, 1)
}

// claimTransformTypeClause renders the Type comparison for the *Except forms.
//
// Only the single-identifier shape has been observed. How the reference chains
// several identifiers into one rule is not established, so more than one is
// refused rather than guessed at with an invented separator.
func claimTransformTypeClause(ids []string, operator string) (string, error) {
	if len(ids) != 1 {
		return "", errors.Join(ErrClaimTransformRule, errClaimTransformMultipleTypes)
	}
	id := ids[0]
	if err := validateClaimID(id); err != nil {
		return "", errors.Join(ErrClaimTransformPolicy, err)
	}
	// A claim ID cannot contain a quote: validateClaimID rejects it, so the
	// rendered clause cannot be escaped out of.
	if strings.ContainsAny(id, `"\`) {
		return "", ErrClaimTransformPolicy
	}
	return "Type" + operator + `"` + id + `"`, nil
}

var errClaimTransformMultipleTypes = errors.New("multi-identifier AllowAllExcept/DenyAllExcept has not been qualified against the reference")

// claimTransformForbidden rejects rule text that would break out of the CDATA
// section or smuggle in a second envelope.
var claimTransformForbidden = regexp.MustCompile(`]]>|<!\[CDATA\[|(?i)</?ClaimsTransformationPolicy|(?i)</?Rules\b`)

func validateClaimTransformRule(rule string) error {
	if rule == "" || len(rule) > claimTransformRuleMaxBytes {
		return ErrClaimTransformRule
	}
	if !validDirectoryText(rule) {
		return ErrClaimTransformRule
	}
	if claimTransformForbidden.MatchString(rule) {
		return ErrClaimTransformRule
	}
	return nil
}

// claimTransformInner extracts the rule text from a stored envelope. A stored
// value that does not match the observed envelope is reported rather than
// reinterpreted, so an unexpected shape never looks like a rule.
var claimTransformCDATA = regexp.MustCompile(`(?s)<!\[CDATA\[(.*?)]]>`)

func claimTransformInner(stored string) (string, error) {
	match := claimTransformCDATA.FindStringSubmatch(stored)
	if match == nil {
		return "", ErrClaimTransformPolicy
	}
	return match[1], nil
}

// ClaimTransformPolicy is one msDS-ClaimsTransformationPolicyType.
type ClaimTransformPolicy struct {
	Raw                          Object
	GUID                         *GUID
	ID, DisplayName, Description *string
	// StoredRules is the complete attribute value including the XML envelope.
	// Rule is the inner text; it is nil when the stored value does not match
	// the observed envelope, and StoredRules still reports what was read.
	StoredRules, Rule *string
	// CompiledPresent reports whether the server-generated compiled rules were
	// returned. Their meaning is not interpreted.
	CompiledPresent                 bool
	ProtectedFromAccidentalDeletion *bool
}

type ClaimTransformPolicyReadOptions struct {
	ResolveIdentityOptions
	IncludeProtection bool
}

type ClaimTransformPolicyResult struct {
	Policy      *ClaimTransformPolicy
	Observation IdentityResult
	Protection  OUProtectionResult
}

type ClaimTransformPoliciesResult struct {
	Policies    []ClaimTransformPolicyResult
	Observation SearchResult
}

func decodeClaimTransformPolicy(object Object) (result ClaimTransformPolicy, err error) {
	result.Raw = object
	d := rootDSEDecoder{attributes: object.Attributes}
	result.ID = d.text("name")
	result.DisplayName = d.text("displayName")
	result.Description = d.text("description")
	result.StoredRules = d.text(claimTransformRules)
	_, result.CompiledPresent = object.Attributes[strings.ToLower(claimTransformCompiled)]
	if result.StoredRules != nil {
		if inner, innerErr := claimTransformInner(*result.StoredRules); innerErr == nil {
			result.Rule = &inner
		} else {
			err = innerErr
		}
	}
	guid, guidErr := centralAccessGUID(object)
	if guidErr == nil {
		result.GUID = &guid
	}
	return result, errors.Join(err, guidErr, errors.Join(d.errors...), centralAccessClassCheck(object, claimTransformClass))
}

func claimTransformLocation(object Object, configuration string) error {
	if err := centralAccessClassCheck(object, claimTransformClass); err != nil {
		return errors.Join(ErrClaimTransformPolicy, err)
	}
	parent, err := parentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	if !centralSameDN(parent, claimTransformParent(configuration)) {
		return ErrIdentityScope
	}
	return nil
}

// ClaimTransformPolicy reads one policy by identity.
func (c *Client) ClaimTransformPolicy(ctx context.Context, identity Identity, options ClaimTransformPolicyReadOptions) (ClaimTransformPolicyResult, error) {
	var result ClaimTransformPolicyResult
	if err := centralAccessIdentity(identity, options.ResolveIdentityOptions); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		configuration, e := centralAccessConfiguration(root, c.config, options.Partition)
		if e != nil {
			return e
		}
		resolve := options.ResolveIdentityOptions
		resolve.Partition = configuration
		resolve.Properties = claimTransformProperties(resolve.Properties)
		result.Observation, e = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if e != nil {
			return e
		}
		if e := claimTransformLocation(*result.Observation.Object, configuration); e != nil {
			return e
		}
		value, decodeErr := decodeClaimTransformPolicy(*result.Observation.Object)
		result.Policy = &value
		if options.IncludeProtection && value.GUID != nil {
			protection, protectErr := readOUProtection(ctx, c.session, root, c.config, OrganizationalUnit{DistinguishedName: result.Observation.Object.DistinguishedName, GUID: value.GUID}, configuration)
			result.Protection = protection
			value.ProtectedFromAccidentalDeletion = protection.ProtectedFromAccidentalDeletion
			result.Policy = &value
			decodeErr = errors.Join(decodeErr, protectErr)
		}
		return decodeErr
	})
	return result, err
}

// ClaimTransformPolicies lists policies in the Claims Transformation Policies
// container, restricting any caller filter to that container and class.
func (c *Client) ClaimTransformPolicies(ctx context.Context, options SearchOptions) (ClaimTransformPoliciesResult, error) {
	var result ClaimTransformPoliciesResult
	query, err := options.normalized()
	if err != nil {
		return result, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		configuration, e := centralAccessConfiguration(root, c.config, "")
		if e != nil {
			return e
		}
		container := claimTransformParent(configuration)
		if query.Base != "" && !centralSameDN(query.Base, container) {
			return ErrIdentityScope
		}
		query.Base = container
		query.Scope = ScopeOneLevel
		query.Filter = "(&(objectClass=" + claimTransformClass + ")" + query.Filter + ")"
		query.Properties = claimTransformProperties(options.Properties)
		result.Observation, e = searchIdentitySession(ctx, c.session, query)
		for _, object := range result.Observation.Objects {
			value, decodeErr := decodeClaimTransformPolicy(object)
			result.Policies = append(result.Policies, ClaimTransformPolicyResult{Policy: &value, Observation: IdentityResult{Object: &object, Complete: true}})
			e = errors.Join(e, decodeErr)
		}
		return e
	})
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
