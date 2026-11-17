package model

import (
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
	InternalClaimTransformClass = "msDS-ClaimsTransformationPolicyType"
	InternalClaimTransformRules = "msDS-TransformationRules"
	// Compiled rules are server-generated and were absent on every policy the
	// reference run created. They are read for observation and never written.
	InternalClaimTransformCompiled = "msDS-TransformationRulesCompiled"
)

// claimTransformEnvelope reproduces the observed stored form exactly, including
// its irregular whitespace. Correctness here is byte equality with the
// reference, not readability, so this string must not be tidied.
const InternalClaimTransformEnvelope = " <ClaimsTransformationPolicy>     <Rules version=\"1\">         <![CDATA[%s]]>    </Rules></ClaimsTransformationPolicy>"

// claimTransformRuleMaxBytes bounds rule text before any write. The directory
// remains authoritative for the real limit; this only stops an unbounded value.
const InternalClaimTransformRuleMaxBytes = 1 << 20

func InternalClaimTransformParent(configuration string) string {
	return "CN=Claims Transformation Policies,CN=Claims Configuration,CN=Services," + configuration
}

func InternalClaimTransformProperties(extra []string) []string {
	return append(
		append([]string(nil), extra...),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"displayName",
		"description",
		InternalClaimTransformRules,
		InternalClaimTransformCompiled,
	)
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

func InternalClaimTransformRuleSetEmpty(s ClaimTransformRuleSet) bool {
	return !s.AllowAll && !s.DenyAll && len(s.AllowAllExcept) == 0 && len(s.DenyAllExcept) == 0 &&
		s.Rule == nil
}

func InternalClaimTransformRuleSetForms(s ClaimTransformRuleSet) int {
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
func InternalClaimTransformRuleSetRender(s ClaimTransformRuleSet) (string, bool, error) {
	if InternalClaimTransformRuleSetEmpty(s) {
		return "", false, nil
	}
	if InternalClaimTransformRuleSetForms(s) != 1 {
		return "", false, ErrClaimTransformPolicy
	}
	var inner string
	switch {
	case s.AllowAll:
		inner = "C1:[]=>Issue(claim=C1);"
	case s.DenyAll:
		inner = `C1:[Type !~ "*"]=>Issue(claim=C1);`
	case len(s.AllowAllExcept) != 0:
		clause, err := InternalClaimTransformTypeClause(s.AllowAllExcept, ` !=`)
		if err != nil {
			return "", false, err
		}
		inner = "C1:[" + clause + "]=>Issue(claim=C1);"
	case len(s.DenyAllExcept) != 0:
		clause, err := InternalClaimTransformTypeClause(s.DenyAllExcept, "==")
		if err != nil {
			return "", false, err
		}
		inner = "C1:[" + clause + "]=>Issue(claim=C1);"
	default:
		if err := InternalValidateClaimTransformRule(*s.Rule); err != nil {
			return "", false, err
		}
		inner = *s.Rule
	}
	return InternalClaimTransformEnvelopeFor(inner), true, nil
}

func InternalClaimTransformEnvelopeFor(inner string) string {
	return strings.Replace(InternalClaimTransformEnvelope, "%s", inner, 1)
}

// claimTransformTypeClause renders the Type comparison for the *Except forms.
//
// Only the single-identifier shape has been observed. How the reference chains
// several identifiers into one rule is not established, so more than one is
// refused rather than guessed at with an invented separator.
func InternalClaimTransformTypeClause(ids []string, operator string) (string, error) {
	if len(ids) != 1 {
		return "", errors.Join(ErrClaimTransformRule, errClaimTransformMultipleTypes)
	}
	id := ids[0]
	if err := InternalValidateClaimID(id); err != nil {
		return "", errors.Join(ErrClaimTransformPolicy, err)
	}
	// A claim ID cannot contain a quote: validateClaimID rejects it, so the
	// rendered clause cannot be escaped out of.
	if strings.ContainsAny(id, `"\`) {
		return "", ErrClaimTransformPolicy
	}
	return "Type" + operator + `"` + id + `"`, nil
}

var errClaimTransformMultipleTypes = errors.New(
	"multi-identifier AllowAllExcept/DenyAllExcept has not been qualified against the reference",
)

// claimTransformForbidden rejects rule text that would break out of the CDATA
// section or smuggle in a second envelope.
var InternalClaimTransformForbidden = regexp.MustCompile(
	`]]>|<!\[CDATA\[|(?i)</?ClaimsTransformationPolicy|(?i)</?Rules\b`,
)

func InternalValidateClaimTransformRule(rule string) error {
	if rule == "" || len(rule) > InternalClaimTransformRuleMaxBytes {
		return ErrClaimTransformRule
	}
	if !InternalValidDirectoryText(rule) {
		return ErrClaimTransformRule
	}
	if InternalClaimTransformForbidden.MatchString(rule) {
		return ErrClaimTransformRule
	}
	return nil
}

// claimTransformInner extracts the rule text from a stored envelope. A stored
// value that does not match the observed envelope is reported rather than
// reinterpreted, so an unexpected shape never looks like a rule.
var InternalClaimTransformCDATA = regexp.MustCompile(`(?s)<!\[CDATA\[(.*?)]]>`)

func InternalClaimTransformInner(stored string) (string, error) {
	match := InternalClaimTransformCDATA.FindStringSubmatch(stored)
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

func InternalDecodeClaimTransformPolicy(object Object) (result ClaimTransformPolicy, err error) {
	result.Raw = object
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.ID = d.InternalText("name")
	result.DisplayName = d.InternalText("displayName")
	result.Description = d.InternalText("description")
	result.StoredRules = d.InternalText(InternalClaimTransformRules)
	_, result.CompiledPresent = object.Attributes[strings.ToLower(InternalClaimTransformCompiled)]
	if result.StoredRules != nil {
		if inner, innerErr := InternalClaimTransformInner(*result.StoredRules); innerErr == nil {
			result.Rule = &inner
		} else {
			err = innerErr
		}
	}
	guid, guidErr := InternalCentralAccessGUID(object)
	if guidErr == nil {
		result.GUID = &guid
	}
	return result, errors.Join(
		err,
		guidErr,
		errors.Join(d.InternalErrors...),
		InternalCentralAccessClassCheck(object, InternalClaimTransformClass),
	)
}

func InternalClaimTransformLocation(object Object, configuration string) error {
	if err := InternalCentralAccessClassCheck(object, InternalClaimTransformClass); err != nil {
		return errors.Join(ErrClaimTransformPolicy, err)
	}
	parent, err := InternalParentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	if !InternalCentralSameDN(parent, InternalClaimTransformParent(configuration)) {
		return ErrIdentityScope
	}
	return nil
}
