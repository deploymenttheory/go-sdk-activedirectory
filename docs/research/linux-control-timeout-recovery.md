# Linux lab control timeout recovery

The Server2016 qualification attempt started at 2026-11-18T20:33:35Z reached the independent Linux credential-digest check and stalled while staging the public SSH bridge. Seven acknowledged 256 KiB chunks were present in the member's cache. No SDK case, directory policy change, or contact write had started.

A separate diagnostic runspace read only the host's function names, script paths, and line numbers. It found `Invoke-LinuxControlCommand` blocked in synchronous `Stop-Job` in its `finally` block. The 30-second `Wait-Job` deadline had expired. The guest's original transport runspace was idle, and separate PowerShell Direct probes completed. These observations establish the cleanup deadlock; they do not establish why the original PSRP transfer stalled.

After the exact guest process, creation time, VM identity, VMIC parent, unchanged public partial file, and absence of child work were rechecked, that transport process alone was stopped. The runner completed its own cleanup at 20:50:03Z with zero SDK cases, `passed=false`, and `cleanup_verified=true`. No SDK operation was replayed. The partial transfer and original diagnostics remain evidence of a failed attempt.

## Deadline behavior

On a control deadline, the helper now requests asynchronous runspace closure and retains the unconfirmed job. It does not call synchronous `Stop-Job`, force job disposal, or synchronous session removal on that timeout path. Successful requests retain normal cleanup.

[`Runspace.CloseAsync`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.runspace.closeasync) requests asynchronous closure. The [PowerShell implementation](https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/remoting/client/remoterunspace.cs) delegates to `BeginClose`; synchronous `Close` additionally waits for running pipelines. Requesting asynchronous closure does **not** prove that the guest process or an SDK operation has ended.

The helper therefore writes `StorageRoot/control-reconciliation-required.json` with public owner, member, profile, session, job, host process, and time identities. It records `guest_retirement_verified=false` and blocks subsequent control calls, including cache cleanup. It never persists commands, arguments, request bodies, keys, credentials, or output. An existing journal is never overwritten.

Before archiving that journal, an operator must independently establish that the exact old control session and any child work have ended, and reconcile the caller's actual operation outcome and fixture cleanup. An asynchronous close request alone is insufficient. Preserve the original journal and failed-run evidence. Only after that reconciliation may the operator archive the journal and explicitly clean the owned public cache. Never blindly retry an indeterminate SDK operation.

Offline guards run in Windows PowerShell 5.1 and PowerShell 7. They reproduce the formerly blocking cleanup seam with a mock synchronous stop that fails, while asynchronous close never confirms retirement. They verify the original deadline failure, no synchronous stop/disposal or retry, a public-only fail-closed journal, and input/mutex cleanup. These tests establish timeout behavior; they do not qualify a replacement bulk-transfer mechanism or complete the live 84-case matrix.

## Public-only ISO alternative

The next lab transport experiment may seed the same fully hashed public bridge using a uniquely owned read-only ISO. The ISO must contain exactly the bridge executable and a public manifest. It must contain no keys, credentials, autorun, network configuration, or private payloads.

Before attachment, capture the owned member's exact VM identity, original DVD/media/controller, disk, and NIC state and the full ISO/input hashes. Add one new DVD on a free slot of an existing SCSI controller. Never change existing media, VM power, switches, routes, or services. Inside the guest, verify the unique volume, exact member list, manifest, bridge size/hash, and local-copy size/hash before publishing the owned cache. Preserve interrupted inputs instead of appending or overwriting them. Remove only the new device by its verified ID/path/controller and independently compare the complete original device state. No lab execution or success claim follows from preparing that source.

The remaining complete authentication qualification is tracked by issue 194. This transport repair is a prerequisite, not completion of that issue.
