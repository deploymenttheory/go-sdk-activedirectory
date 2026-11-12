# Current-identity connection and RootDSE

The current-identity connection slice has passed the
[Server 2025 reference qualification](../coverage/lab/server2025/connection/README.md).
The module pins
`go-bindings-win32 v0.6.1-0.20261112134443-9f51cb95639f`, an immutable development
commit containing the merged native LDAP memory and credential-pointer fixes.
It is not a published release. Explicit credential qualification is in progress
under #10. TLS, AD LDS, and the older-server matrix remain separate delivery
work. This is a first connection API, not complete `Get-ADRootDSE` parity.

Construct and validate `Config` on any Go platform. Execute the native client on
Windows amd64 or arm64, under an identity authorized to contact the directory.
The SDK has no PowerShell, RSAT, or remote-agent runtime dependency.

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

client, err := activedirectory.Dial(ctx, activedirectory.Config{
    Endpoint: activedirectory.Endpoint{Host: "dc1.example.test"},
})
if err != nil {
    return err
}
root, readErr := client.RootDSE(ctx, activedirectory.RootDSEOptions{
    Properties: []string{"supportedExtension"},
})
closeErr := client.Close()
if err := errors.Join(readErr, closeErr); err != nil {
    return err
}
fmt.Println(root.NamingContexts)
```

Run the complete example with:

```powershell
go run ./examples/rootdse -server ADSDK25DC1.ad.sdk.test
```

The endpoint names one FQDN or IP address. Port defaults to 389; it specifies an
LDAP endpoint and does not enable LDAPS. Current-identity Negotiate requests
signing and sealing. Negotiate does not guarantee Kerberos. TLS remains a
separate delivery ticket. Automatic reconnect, referral chasing,
credential prompts, and the native RootDSE cache are disabled. An impersonating
caller must keep its goroutine locked to the impersonated Windows thread; the
SDK keeps authentication on that calling thread.

On the #10 development branch, pass `Config.Credentials` to select an explicit
Negotiate identity:

```go
config.Credentials = &activedirectory.Credentials{
    Username: "alice",
    Domain:   "EXAMPLE",
    Password: passwordBytes, // caller-owned UTF-8 obtained from your secret source
}
client, err := activedirectory.Dial(ctx, config)
clear(passwordBytes)
```

Nil credentials preserve current-identity authentication. A present value
requires a username and always supplies a native identity structure, even with
an empty password. Authentication failure never triggers a retry under the
current identity. Credential fields must be valid UTF-8 without NUL; passwords
are not trimmed or normalized. An omitted domain is passed as NULL with zero
length. The native authentication provider determines accepted account forms.

The client does not retain credentials. Temporary Unicode buffers are pinned
through bind and native password erasure, then cleared and unpinned. This does
not erase caller-owned bytes, caller-created strings, or copies held by Windows.
Ordinary formatting and serialization redact `Credentials`; callers can still
deliberately access its exported fields. The SDK does not log credential values.

The RootDSE example also accepts `-username alice -domain EXAMPLE`. Supply exact
UTF-8 password bytes through redirected standard input from your secret source;
the example does not trim a newline and refuses an interactive console input.
It accepts no password command-line argument and clears its input after Dial.
See [the explicit credential contract audit](research/winldap-explicit-credentials.md)
for lifetime evidence and the remaining live qualification cases.

`Config.Timeout` defaults to 30 seconds. Connect and send waits are finite;
synchronous Negotiate applies its timeout to each response round trip. A context
deadline cannot interrupt an already-running synchronous native call. RootDSE
receives results in short bounded waits and abandons its message ID on
cancellation. An unsuccessful abandon retires the session. The SDK never
detaches a native call and frees its handle while it is still running.

Calls on one client are serialized. `Close` rejects new calls, cancels an active
read, waits for native use to finish, and unbinds once. Repeated calls return the
same cleanup result. Always inspect cleanup errors alongside operation errors.
Missing native exports return `ErrUnsupported`, preserving the loader error.

RootDSE scalar fields use pointers to distinguish absent values from zero,
false, and empty strings. Multivalued attributes remain multivalued. Numeric
functional levels are separate from OS and schema versions; capabilities are
server advertisements, not proof of permission or negotiated authentication.
`Attributes` contains copied bytes under lowercase names, including unknown
binary and zero-length values. `RequestedProperties` records the requested
projection. Absence does not establish whether an attribute is unsupported,
empty, or hidden by access control.

`Properties` adds names to the stable default projection. `"*"` additionally
requests server-returned user attributes; operational attributes can still
require explicit names. Ranged attributes return `ErrIncompleteResult` instead
of silently truncating. Malformed typed values return `ErrInvalidResult` while
preserving raw values. Error returns may include partial data; inspect the error
before treating a result as complete. `LDAPError` retains native LDAP codes and
available result diagnostics; its default string omits server diagnostic text.

For isolated reference testing, use the lab's `TestConnection` action. It builds
from a retained source snapshot and records source/binary hashes, guest versions,
native test output, and PowerShell comparisons. PowerShell is used only by that
test harness. See [the native contract audit](research/winldap-connection.md).

The recorded run compares 21 stable properties with `Get-ADRootDSE`, checks time
and USN against before/after reads, exercises ten open/read/close cycles, and
checks invalid endpoints, a one-second connection wait, and authentication
denial under a temporary local identity. Account removal is verified before the
run passes. The observed timeout validates a connect wait; it does not establish
a hard aggregate deadline for synchronous Negotiate.
