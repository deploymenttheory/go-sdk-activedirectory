# WinLDAP paging contracts and cleanup evidence

Checked 2026-11-12 for issue #12. Local native execution used Windows
10.0.26300.0 amd64 and Go 1.26.5. The test LDAP endpoint was a loopback responder,
not an AD server. No PowerShell or directory credentials are used by these tests.

## Native contract

[RFC2696 section 3](https://www.rfc-editor.org/rfc/rfc2696.html#section-3)
defines completion by an empty cookie, treats cookies as opaque, allows the page
size to change, and requires other search parameters to remain stable. A client
releases a completed page sequence early by sending the last cookie with page
size zero. Abandoning an outstanding request can invalidate the previous cookie.

Microsoft's [create-page-control contract](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_create_page_controlw)
supports a critical control with asynchronous `ldap_search_extW`; the request
control is released with `ldap_control_freeW`. The SDK requests critical paging
so an unsupported server cannot silently downgrade to an unpaged search.

[ldap_parse_page_controlW](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_parse_page_controlw)
extracts the response cookie, which must be released with `ber_bvfree`.
`ldap_parse_resultW` returns the response controls; they are released with
`ldap_controls_freeW`. Every received message chain is released with
`ldap_msgfree`, including native failures that supply partial messages.

[ldap_result](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_result)
supports bounded asynchronous polling. The SDK uses 50 ms polls under a context
deadline and never starts a replacement request after an uncertain submission.
The server time-limit field is fixed across the sequence while the native send
timeout follows the remaining context budget.

## Why the high-level paging helper is not used

The initial implementation used `ldap_search_init_pageW`, `ldap_get_next_page`
and `ldap_search_abandon_page`. Microsoft documents the latter as both cleanup
and abandonment, but does not expose a timeout argument.

A controlled native test returned three objects over two pages, then withheld
the response to the zero-size cleanup request. With a one-second operation
deadline, one-second native send/time limits, and automatic reconnect/referrals
disabled, `ldap_search_abandon_page` remained blocked until the responder's
ten-second socket deadline. It then returned LDAP status 82. The observed test
duration was 10.01 s. A separate 15-second timeout run captured this stack:

```text
ldap.Ldap_search_abandon_page
(*ldapSearch).close
collectSearch.func1
(*Client).Search
TestNativePagedSearchWireResultsAndOwnership/limit_in_page
```

This observation is specific to the tested Windows build and fixture. It is
enough to reject the helper for this SDK's bounded-cleanup contract. The final
implementation uses explicit controls, a bounded asynchronous zero-size request,
and connection retirement when cleanup cannot be confirmed. The retained
`TestNativePagedSearchCleanupWaitIsBounded` reproduces the withheld response and
asserts an error and closed session within one second; local observation is
approximately 100 ms. `TestNativePagedSearchRepeatedCallsReleaseEveryAllocation`
checks all externally owned native allocations over 100 searches.

The investigation also found an independent generated binding defect: a NULL
`ldap_search_init_pageW` handle could return a nil Go error. This was fixed in
the upstream generator and all three emitted variants in
[go-bindings-win32 PR #70](https://github.com/deploymenttheory/go-bindings-win32/pull/70),
with native amd64/arm64 and generator regressions. The SDK contains no manual
syscall wrappers or edited generated bindings.

## Qualification still required

The owned permission fixture uses an object-specific deny ACE with the
description attribute's `schemaIDGUID`, `ReadProperty`, the ordinary user's SID,
and no inheritance, following Microsoft's
[specific-property permissions contract](https://learn.microsoft.com/en-us/windows/win32/ad/setting-permissions-to-a-specific-property).
The [ActiveDirectoryAccessRule constructor](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor)
represents that exact scope. The fixture commits only the target DACL using
[DirectoryEntry SecurityMasks](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentryconfiguration.securitymasks),
verifies that removing the new ACE from an in-memory readback restores the
original DACL, and verifies the replicated ACE before comparing ordinary-user
reads. Only the owned target's ACL changes; deletion of that marked object
removes the test ACE. This fixture is implemented but has not yet run in AD.

Real AD DS versions and AD LDS need native/differential artifacts before issue
#12 can be qualified. The repository's `reference-search.ps1` harness records
server/module versions, object projection comparisons and fixture cleanup.
Loopback status 50/12 tests establish error handling, not live AD ACL or capability
parity. Sorting, ranged-value continuation, deleted objects, PowerShell filter
language and GUID identity resolution are outside this search slice.
