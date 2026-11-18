# Portable conditional expressions and policy conversion

Issue [173](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/173) reuses the
portable `conditions` codec introduced by SDK06, merged in PR192. No Windows process,
runtime gateway or second expression compiler is involved. The codec's existing independent
[Windows vectors](../../conditions/testdata/README.md) retain source, accepted binary/canonical
outputs, rejected inputs and native quirks. Native conversion is a reference for the observed
host, not evidence of directory storage or effective access.

The integration gaps were the portable session's missing central-access syntax interface
and the typed builders' decimal-only SID checks. Both central-access backends now use
`conditions.NormalizeSDDL` and `conditions.Compile`. Typed trustee and membership validation
reuse the existing numeric SID parser, including canonical 48-bit hexadecimal authorities.
Public compile/conversion tests compare independent wire bytes; a separate Windows test
converts literal SDDL through Advapi32 directly, avoiding the shared typed-builder validator.

## Boundaries and checks

The [MS-DTYP precedence rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/d1a8392f-3f54-4fea-8233-44ede9eb198c)
and [conditional ACE syntax](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)
define the local language. Compilation validates supported syntax, numeric/encoding limits
and binary structure. It does not resolve names, discover claims, evaluate effective access,
or determine whether a condition is appropriate for an authentication-policy context.
Raw expression rendering alone does not establish syntax validity. Unknown operators and
unsupported descriptor forms return actionable errors without a partial policy.

Owned TLS/LDAP fixtures call the actual portable session and public resource services.
They inspect binary values for all five authentication-policy descriptor properties and
Unicode text for central-rule ACLs/resource conditions. Creation, exact-old current/previous
ACL updates, real fixture LDAP refusals, partial preflight/readback, cancellation and
malformed/lost submitted-write responses preserve their distinct outcomes. Interrupted
sessions retire; no write is automatically retried. Invalid expressions and missing SID
context never produce an approximate directory write. These are protocol fixture tests,
not AD acceptance claims.

The authentication-policy fixture binary expectation derives from the retained native
`relation-eq` vector, changing only its documented access mask from Generic Read to Control
Access. Central-access expectations retain literal submitted text, consistent with
[Set-ADCentralAccessRule's separate ACL and resource-condition inputs](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adcentralaccessrule?view=windowsserver2025-ps).

## Qualification remaining

Fresh public portable Windows/Linux directory qualification is required against each
Server 2016/2019/2022/2025 profile. The planned fixtures are marker/GUID-owned audit-only
authentication policies and unlinked central rules, with a dedicated actor allowed to
write only their descriptor/condition attributes and separate readable denial targets.
No policy assignment, account enforcement or global claims/central-policy changes are
needed. Both-DC cleanup and private-credential retirement must be independently recorded.
No live SDK08 cell is claimed yet. Historical native policy/editor checks remain historical.

The opt-in collector is `TestPortablePolicyConditionsLab` in the acceptance package.
Build its test executable with `-X` setting
`github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/acceptance.portablePolicyLabBuildRevision`
to the actual frozen source commit. Select only this test and set the public nonsecret
`ADSDK_POLICY_LAB_INPUT=stdin`; credentials belong in bounded JSON process stdin.
The input has `credential_source` (`password` or `cache`, mutually exclusive),
`password_base64` or `cache_path`, `endpoint`, `realm`, `spn`, `username`, `run_id`,
`source_revision`, `result`, and four `targets` objects with `role`, `dn`, and `guid`.
Endpoints are explicit lab DC FQDNs on LDAP389, realm `AD.SDK.TEST`, with exact
`ldap/<FQDN>` SPN and measured mutual AES SASL Seal. There is no ambient credential
lookup, backend/authentication fallback or test authentication wrapper.

Roles are `auth`, `auth-denied`, `rule`, `rule-denied`. Names must be exactly
`CN=sdk08-<run_id>-<role>,<standard configuration-NC parent>`, with the description
`sdk08-condition:<run_id>:<role>` and four distinct nonzero recorded GUIDs. `run_id`
contains at most 40 ASCII letters, digits or hyphens. The fresh result file uses
exclusive creation. Reports contain only public observations and descriptor/text
bytes; input formatting/JSON hooks redact credentials. Caller-owned cache files are
not modified by the collector. The outer runner retains build inputs/binary hashes,
the actor's credential lifecycle and independent pre/post cleanup evidence.

The functions-only [policy fixture helper](../../scripts/lab/policy-conditions-fixture.ps1)
reuses the separately retained descriptor lab helper's native Kerberos+Sign/Seal
connection and controlled DACL read functions. Both exact helper sources must be
hashed and copied before execution. An outer actor fixture creates the dedicated
AES account and protected credential; policy preparation never creates/resets an
administrator or changes server authentication policy. It resolves each allowed
attribute's actual schema GUID, adds only ReadProperty plus exact per-attribute
WriteProperty allow/deny ACEs on the four new objects, and verifies the grants.
Provisioning is exclusive new-fixture setup, not a production atomic ACL strategy.
Cleanup checks all target GUIDs/markers, rejects assignment/linkage/enforcement or
foreign objects before deletion, deletes individual GUID targets without recursion,
and independently searches the configuration NC on both DCs. Domain actor deletion
and all private client/host credential retirement remain the outer fixture's duty.

The [authentication-policy schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/df2ed14b-c69d-4680-86ac-2e0c3d9c78af)
has four reference backlinks: direct account assignment plus user/computer/service
policy links from silos. Cleanup requests all four, checks their actual schema
forward/backlink linkIDs, and separately searches the forward attributes in both
the domain and configuration NCs. Central-rule membership is checked in the
configuration NC. Missing requested reader properties, failed/partial queries or
any observed association stop cleanup; no reference is automatically removed.

SDK06's unresolved atomic `nTSecurityDescriptor` write route is outside this integration:
policy binary values and central-rule text are ordinary attributes. Deletion-protection
and other ACL workflows retain their existing capability guards and separate follow-ups.
