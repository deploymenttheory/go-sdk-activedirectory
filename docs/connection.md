# Connection, credentials, partitions, and RootDSE

Current-identity and explicit Negotiate authentication have passed their
[connection](../coverage/lab/server2025/connection/README.md) and
[credential](../coverage/lab/server2025/credentials/README.md) reference
qualification on Server 2025.
The module pins
`go-bindings-win32 v0.6.1-0.20261112134443-9f51cb95639f`, an immutable development
commit containing the merged native LDAP memory and credential-pointer fixes.
It is not a published release. TLS and AD LDS support is implemented with native
boundary tests; live TLS/AD LDS fixture qualification is still pending in
[ticket #11](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/11).
Older-server explicit credential qualification remains separate work. This is a first connection API,
not complete `Get-ADRootDSE` parity.

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

The endpoint names one FQDN or IP address. `TransportLDAP` is the default and
uses port 389 with Negotiate signing and sealing. `TransportLDAPS` defaults to
port 636; `TransportStartTLS` defaults to 389. An explicit port overrides those
defaults without selecting a transport. Negotiate does not guarantee Kerberos.
Automatic reconnect, referral chasing,
credential prompts, and the native RootDSE cache are disabled. An impersonating
caller must keep its goroutine locked to the impersonated Windows thread; the
SDK keeps authentication on that calling thread.

Pass `Config.Credentials` to select an explicit
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

With Negotiate, nil credentials preserve current-identity authentication. A present value
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
for lifetime evidence and the [recorded credential results](../coverage/lab/server2025/credentials/README.md)
for the qualified cases and limits.

`Config.Timeout` defaults to 30 seconds. Connect and send waits are finite;
synchronous Negotiate applies its timeout to each response round trip. A context
deadline cannot interrupt an already-running synchronous native call. StartTLS
has a native default wait of approximately 30 seconds, and certificate retrieval
can add waits; the SDK does not promise a strict aggregate TLS deadline. RootDSE
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

## AD LDS and validated TLS

Select the instance's actual port and its certificate hostname. Both TLS modes
use Windows Schannel automatic certificate validation and the Windows trust
store, with no certificate-validation bypass setting. Credentials are sent only
after a successful TLS handshake, policy inspection, and negotiated TLS 1.2 or
1.3 with at least 128-bit cipher strength. SIMPLE requires explicit nonempty
credentials and an empty `Domain`; `Username` is the server-accepted bind name,
normally an LDS user DN. The SDK rejects cleartext SIMPLE and empty-password
SIMPLE locally, including on a server that would accept an unauthenticated bind.
Negotiate supports current or explicit Windows identities over either TLS mode.
TLS sessions do not request a second layer of SASL signing/sealing.

```go
config := activedirectory.Config{
    Endpoint: activedirectory.Endpoint{Host: "lds.example.test", Port: 51301},
    Transport: activedirectory.TransportLDAPS,
    Authentication: activedirectory.AuthenticationSimple,
    Partition: "CN=Application,DC=example,DC=test",
    Credentials: &activedirectory.Credentials{
        Username: "CN=reader,CN=Application,DC=example,DC=test",
        Password: passwordBytes,
    },
}
client, err := activedirectory.Dial(ctx, config)
clear(passwordBytes)
if err != nil {
    return err
}
partition, readErr := client.Partition(ctx)
closeErr := client.Close()
if err := errors.Join(readErr, closeErr); err != nil {
    return err
}
fmt.Println(partition.DistinguishedName)
```

`Dial` connects and authenticates. `Partition` separately resolves and validates
the configured naming context, preserving RootDSE access on LDS instances with
no default. With empty `Config.Partition`, it reads only the advertised
`defaultNamingContext`; a missing or empty default returns
`ErrNoDefaultPartition`. It never chooses the first naming context or substitutes
configuration/schema. An explicit selection takes precedence even when no
default exists.

The server resolves the selected DN in a base-object search and returns its
`distinguishedName` and `instanceType`. This accepts server-recognized equivalent
DN spellings without implementing string-based DN equality. The SDK checks
`instanceType` bit `0x1`, which identifies a naming-context head in AD DS and
AD LDS. An existing subtree returns `ErrNotNamingContext`; nonexistent, denied,
or referred selections retain their native LDAP status. Missing required
attributes return `ErrInvalidResult`, and partial raw attributes remain
available with the error. [Microsoft's instanceType definition](https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype).

`client.Capabilities(ctx)` and `root.Capabilities()` expose a `DirectoryType`
and all advertised OIDs. The LDS OID takes precedence over the generic Active
Directory OID, since LDS can advertise both. Unknown directories remain unknown.
`client.RequireADDS(ctx, "operation name")` returns a
`DirectoryCapabilityError` for LDS or unknown servers; it matches
`ErrUnsupportedDirectory` and exposes the required/actual types. This is a
prerequisite guard, not an implementation of an AD DS-only operation or proof of
access rights. Check the read error before using any partial capabilities.

The runnable example accepts exact UTF-8 password bytes on redirected stdin:

```powershell
go run ./examples/lds -server lds.example.test -port 51301 -transport ldaps `
    -partition "CN=Application,DC=example,DC=test" `
    -bind-dn "CN=reader,CN=Application,DC=example,DC=test"
```

Connect your secret source to that command's standard input; the example refuses
interactive console input and accepts no password argument. It does not trim
newlines. For StartTLS, use `-transport starttls` and the instance's LDAP port.
Omit `-partition` only when the instance advertises a usable default. Native LDS
users use SIMPLE; a Windows domain account alone is not a native LDS SIMPLE
principal.

TLS failures match `ErrTLSNegotiation` and preserve available LDAP and numeric
Win32 server statuses. StartTLS also retains extended-operation server statuses
and available diagnostics. A generic connection failure does not identify a
specific certificate defect. The SDK sets no mandatory online revocation policy;
do not infer guaranteed fail-closed CRL retrieval from automatic trust validation.
See the [TLS contract audit](research/winldap-tls-lds.md) for policy and native
ownership details.

Ordinary tests cover configuration, partition selection, directory guards,
credential sequencing, cancellation, partial/native failures, and native-memory
cleanup. The injected TLS boundary tests do not prove real certificate validation.
`TestADLDSLab` is opt-in (`ADSDK_LDS_LAB=1`), consumes its disposable fixture via
redirected stdin, and writes only observations to `ADSDK_LDS_RESULT`. It exercises
direct LDAPS/StartTLS SIMPLE reads, current-identity TLS Negotiate, wrong password,
missing/subtree partitions, and an LDS replica without a default. It skips normal
test runs. Certificate-negative peers and PowerShell comparisons are separate
live-fixture gates; no parity claim follows from compiling or skipping them.
