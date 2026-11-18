# Server 2022 Linux DNS investigation

The first two full qualification attempts stopped before Linux TCP connection:
the first after 20 completed checks, the second after 30. Both failed lookups
targeted `adsdk22dc1.ad.sdk.test` through `127.0.0.53`. Both runners independently
verified child-fixture and exact policy cleanup. Their original records remain
here and under `attempt2/`; they are not passing qualification evidence.

Direct UDP A/AAAA queries to both configured DCs answered correctly in 0–1 ms.
Eight immediate Go 1.27.4 default-resolver lookups passed. The identical lookup
paced once per second then reproduced the failure: attempt 14 timed out after
five seconds and attempt 15 took 4.133 seconds. DNS-only packet metadata shows
the DC returned the matching AAAA response at 19:02:28.326682 UTC, but the stub
returned that answer only at 19:02:38.459222 after opening another upstream TCP
connection. The A answer had arrived promptly. This identifies the local stub
path as the delayed boundary; it does not establish the underlying resolver
implementation defect. Background external DNS recursions and protocol
downgrades were observed but are not asserted as the cause.

One reversible guest-only change selected systemd's maintained direct-DNS mode:
`/etc/resolv.conf` points to `/run/systemd/resolve/resolv.conf`. Ownership and
the original symlink were checked first. The maintained file contains only the
same `10.77.23.10` and `10.77.23.11` DNS servers and `ad.sdk.test` search domain.
The same paced Go probe then passed 30/30 lookups in 0–3 ms. This is a documented
[systemd resolver mode](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html).

No SDK source, LDAP endpoint, SPN, certificate validation, operation deadline,
clock, ticket bytes or host route changed. The complete fresh qualification is
separate from these diagnostic probes. After verified outer teardown, the exact
original symlink was restored and independently read back. Both temporary DNS
probe binaries were hash-checked and removed. The restoration source and both
readback records are retained here.

The retained Go sources implement DNS lookups only. Their binaries are identified
by SHA-256 rather than committed. DNS packet captures contain protocol metadata;
LDAP/Kerberos traffic and credentials were not captured.
