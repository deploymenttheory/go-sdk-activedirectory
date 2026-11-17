# Active Directory SDK

Language for the SDK's approved operation surface, directory observations, and
qualification programme.

## Language

**Operation**:
One approved ActiveDirectory cmdlet's capability expressed through the SDK's
Go interface, including documented Go equivalents of shell conventions.
_Avoid_: endpoint, method (when referring to coverage).

**Behavioral scenario**:
A named behavior of an operation with defined prerequisites, expected outcomes,
and success and failure cases.
_Avoid_: parameter set, passing test (when referring to a planned scenario).

**Parameter-set variant**:
One documented combination of an operation's parameters, with its own success
and failure cases.
_Avoid_: behavioral scenario, server variant.

**Qualification evidence**:
A retained observation of an executed acceptance case, tied to the tested
implementation and its directory, module, and host environment.
_Avoid_: planned test identifier, implementation claim.

**Reconciliation**:
Establishing the directory's observable state after a requested change and
determining what, if anything, remains to reach the intended state.
_Avoid_: blind retry, rollback.

**Provider readiness**:
The evidenced suitability of the approved SDK operation surface for repeatable
resource management, including reconciliation and explicit observation limits.
_Avoid_: operation coverage state, implementation completeness.
