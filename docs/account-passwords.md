# Account password changes and resets

`ChangeAccountPassword` requires old and new password bytes. `ResetAccountPassword` requests an administrator reset using only the new password. Both use the existing authenticated connection and a single native WinLDAP Modify. Neither falls back to the other operation, retries an uncertain request, performs a test login, submits extra account-flag changes, or reads back password values. The server's password processing controls password timestamps and other derived state.

```go
// oldPassword and newPassword are caller-owned UTF-8 []byte from a secret source.
// Clear those buffers after the call; do not put passwords in source or logs.
result, err := client.ChangeAccountPassword(ctx, ad.PasswordChangeRequest{
    Identity: account, OldPassword: oldPassword, NewPassword: newPassword,
})
// Administrative reset is a distinct call:
result, err = client.ResetAccountPassword(ctx, ad.PasswordResetRequest{
    Identity: account, NewPassword: newPassword,
})
```

Use explicit DN/GUID identities for AD DS or applicable AD LDS user/inetOrgPerson objects. SID and unqualified sAMAccountName identities are AD DS-only. Resolution rejects ambiguity, incomplete results, unknown directory types, and out-of-partition identities. AD DS GC ports and RODCs are rejected before writing; inability to establish the selected DSA's writable status also fails closed. AD LDS arbitrary instance ports remain supported. Server schema, account type, rights, and policy are authoritative, including computer/service-account subclasses. The SDK addresses the resolved GUID to avoid selecting a different object after reuse of its old DN.

The change request contains delete(old unicodePwd) followed by add(new unicodePwd) in one Modify. Reset contains one replace(new unicodePwd). Each value is quoted UTF-16LE without a terminator, with surrogate pairs for supplementary Unicode. WinLDAP adds the BER OCTET STRING wrapper; the SDK does not double-encode it. Nil password slices mean omitted and are rejected. Explicit empty slices remain empty-password requests subject to server policy. Invalid UTF-8 and embedded NUL are rejected. Quotes within a password remain literal characters. These distinctions follow the [unicodePwd protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2).

Protection is checked before resolution and again immediately before encoding/submission. TLS requires the SDK's certificate validation policy, negotiated TLS 1.2/1.3, and cipher strength of at least 128 bits. Sealed Negotiate LDAP requires `LDAP_OPT_ENCRYPT`, the actual SSPI context's confidentiality flag, and an effective key size of at least 128 bits. Unsupported or unavailable measurements fail closed. No protection is inferred from a port number, and the AD LDS insecure-password heuristic is never used. The SDK borrows the LDAP-owned security context, reads only metadata, and frees SSP-allocated algorithm-name buffers; it never exports a session key. See [WinLDAP SSL information](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/example-code-for-establishing-a-session-over-ssl), [Negotiate context attributes](https://learn.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--negotiate), and [effective key size](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_keyinfow).

`PasswordResult.State` retains not-attempted, accepted, rejected, or uncertain status, including when later native cleanup/cancellation reports an error. Accepted means server acknowledgement, not successful future authentication or completed replication. `ErrPasswordUncertain` requires caller reconciliation; automatically repeating a change can use the wrong old password, and repeating a reset can overwrite a later intentional change. No automatic rollback occurs.

LDAP credential, access, constraint, and confidentiality codes have broad typed errors while `errors.As(err, *LDAPError)` preserves native status, matched DN, and diagnostic text. Wrong-old-password and policy failures can use different native codes across servers; the SDK does not guess causes from localized diagnostic prose or classify every unwilling-to-perform error as a policy failure. Ordinary error strings omit native diagnostic text. Treat explicitly inspected diagnostics as sensitive directory information.

Password request types redact ordinary Go formatting and JSON/text serialization. Temporary quoted UTF-16 buffers are created only after preflight, cleared after the bounded write returns on every result path, and are not retained in the client/result. Caller buffers are not modified. Clearing Go buffers is best effort: this does not promise erasure of compiler/runtime copies, caller copies, JSON parser storage, Windows request buffers, swap, or crash dumps.

The runnable example accepts bounded JSON on redirected stdin, refuses interactive console input to avoid echo, defaults to validated LDAPS, and requires `-operation change|reset -apply`. Password fields are base64-encoded UTF-8 bytes, as required by Go JSON `[]byte`; base64 is transport encoding, not encryption. Obtain the JSON from a secret provider through a pipe without placing password material in command arguments or shell history:

```text
secret-provider | go run ./examples/passwords -server dc.example.test -dn "CN=Fixture,OU=Lab,DC=example,DC=test" -operation change -apply
```

Input shape is `{"oldPassword":"<base64 UTF-8>","newPassword":"<base64 UTF-8>"}` for change; omit oldPassword for reset. The example reports only write state and measured cipher strength and never prints input or parser errors containing input.

Local tests cover public synthetic Unicode values, exact operations, temporary-buffer clearing, request redaction, protection failures, scope/capability/RODC checks, diagnostic retention, and uncertain outcomes. Native injection tests cover TLS/SSPI metadata and ownership; actual WinLDAP loopback tests verify single BER wrapping and operation order using public synthetic passwords. No live account changes, login-after-change checks, or PowerShell differential mutations were executed. Server 2016/2019/2022/2025 and AD LDS live qualification, rights/policy outcomes, and module/version evidence remain open for issue #24.
