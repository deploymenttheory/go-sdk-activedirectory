# KDS timing and descriptor qualification prerequisites

Reviewed 2026-11-18 for [SDK-06's remaining qualification](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/195).
This is primary-source research, not a lab observation or permission to modify
keys. No key material was requested.

Microsoft's multi-DC deployment guidance says to allow ten hours after
`Add-KdsRootKey -EffectiveImmediately` before relying on gMSA availability.
Its backdating procedure is explicitly limited to single-DC test environments.
The current lab has two DCs. A creation at 2026-11-18T20:56:27Z reaches that
conservative safety window at **2026-11-19T06:56:27Z**. Reaching the time does
not itself prove that a fresh fixture can be created or that an SDK operation
passes. [Microsoft container gMSA guidance](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts).

Do not conflate that operational waiting guidance with a proven universal
`creation + 10 hours` activation test. The cmdlet reference says
`EffectiveImmediately` selects immediate use; the root-key creation article
also says the originating DC can use the key immediately and other DCs need
successful replication. That article separately describes an up-to-ten-hour
safety interval. These descriptions alone do not establish which server check
caused a particular `Key does not exist` refusal.
[Cmdlet parameters](https://learn.microsoft.com/en-us/powershell/module/kds/add-kdsrootkey?view=windowsserver2025-ps),
[root-key creation guidance](https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key).

The normative selection rule is more precise: for a time-indexed GetKey request,
the writable DC considers root keys whose `msKds-UseStartTime` is no later than
the requested `KeyStartTime`; it derives that time from the requested group-key
indices. The indices advance in ten-hour intervals. Therefore replicated object
presence, current wall-clock time and eligibility for the requested key interval
are distinct observations. **Inference:** comparing the actual nonsecret start
metadata with the requested interval can explain some early refusals, but is not
a substitute for observing the server's response.
[MS-GKDI GetKey §3.1.4.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39).

An authorized metadata inventory can select only the key CN/identifier,
objectGUID, whenCreated, `msKds-CreateTime` and `msKds-UseStartTime` from the
Configuration naming context on each DC, then compare replication metadata and
relevant KDS event 4004. Do not request `msKds-RootKeyData`, wildcard properties or
serialize the result of `Get-KdsRootKey`: that cmdlet returns the root-key value.
`Test-KdsRootKey -KeyId <existing-id>` returns a Boolean but exercises key
derivation; it is a separate active diagnostic, not an ordinary metadata read or
proof of successful gMSA fixture creation. This audit executes neither command.
[Get-KdsRootKey](https://learn.microsoft.com/en-us/powershell/module/kds/get-kdsrootkey),
[Test-KdsRootKey](https://learn.microsoft.com/en-us/powershell/module/kds/test-kdsrootkey?view=windowsserver2025-ps).

Keep the existing key and actual refusal evidence unchanged. No extra key,
backdated effective time, clock/ticket change, cache reset, restart or managed
password retrieval is implied by this note. Missing infrastructure remains
blocked qualification, not passing evidence or a declaration that the server
version is unsupported.
