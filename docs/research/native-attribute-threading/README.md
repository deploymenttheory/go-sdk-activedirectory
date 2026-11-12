# Native attribute enumeration thread affinity

Issue [#82](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/82)
was observed while rereading the cloning PDC's RootDSE: valid attribute data was
followed by `LDAP attribute enumeration: LDAP status 82`. The SDK now pins only
`readRawAttributes` to its current OS thread, through value copying, the final
error query and deferred cursor release. Existing caller thread locks remain
nested. Callers need no workaround or binding dependency change.

These are host-only Windows/amd64 experiments against the existing
`127.0.0.1` BER responder. They perform no authentication, directory mutation,
VM command, or external directory connection. The baseline is
`1f9d4b1615227b541911e03bcd1a82453eff092f`; host/toolchain versions and raw report
hashes are recorded in [manifest.json](manifest.json).

Validation passed: `go test ./...`, `go vet ./...`, repository-configured lint
(zero issues), Windows/arm64 test compilation, and Linux/amd64 and Darwin/arm64
package builds.

The [scheduler regression](../../../native_attribute_thread_windows_test.go)
uses one processor and a temporary thread holder to make the same Go reader
goroutine resume on another OS thread unless the SDK pins it. All LDAP returns
come from real WinLDAP. It failed three times before the fix and passed three
times afterward; the already-pinned caller control passed throughout. All seven
native allocation counters returned to zero.

```powershell
go test . -run '^TestNativeAttributeEnumerationSurvivesSchedulerHandoff$' -count=3 -v
```

| Evidence | Observation |
| --- | --- |
| [Scheduler RED](scheduler-red.txt) / [GREEN](scheduler-green.txt) | The production reader's actual thread migration causes status 82; the scoped lock prevents it. |
| [Direct DLL control](direct-thread.txt) | Generated binding and direct `WLDAP32` dispatch both fail on another thread. Immediate `LdapGetLastError` and the operation-thread session query both report 82. Both same-thread controls succeed. |
| [Preexisting error control](seed-error.txt) | A native session error of 82 seeded before first/next enumeration is cleared normally. |
| [Wire/thread matrix](wire-thread-matrix.txt) | Zero/one/32-attribute controls include binary, empty and multivalue data. Same-thread, seeded-error and distinct-handle-error cases pass 100 reads each. Cross-thread cursor use fails after the first attribute. |
| [Adjacent API audit](adjacent-api.txt) | First/next entry traversal, value retrieval and the session error query succeed on another thread. No broader locking change was made. |

The cross-thread diagnostic is intentionally a negative control; it is separate
from the committed regression and is not an always-failing suite test. These
experiments establish native cursor affinity on the recorded host. They do not
replace the Server 2025 collision recheck, cleanup proof, or broader issues #12
and #55 qualification.

Microsoft documents that normal end-of-attribute enumeration clears the session
error, while failure returns NULL with an error. The fix therefore retains the
error check instead of suppressing status 82 or retrying the operation. See
[ldap_next_attributeW](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_next_attributew),
[ldap_first_attributeW](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_first_attributew),
[session error options](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/session-options),
and the [thread-local last-error contract](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldapgetlasterror).
