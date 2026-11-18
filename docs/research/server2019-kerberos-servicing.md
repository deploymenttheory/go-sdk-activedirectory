# Server 2019 Kerberos qualification prerequisite

The owned Server 2019 DC1 reports build `17763.3650`. Fresh AES-only credentials
for run `sdk05-2019-20261118t172403169z` failed before qualification. The MIT
reference producer classified its first `password-kinit` as unsupported
encryption; the unchanged Go 1.27.4 SDK binary from
`958d4a426561bb36a5cd6104f0e253e2a7aa7b2f` independently received actual
Kerberos error 14. Neither attempt submitted an application write.

The KDC's System event 14 identifies the same owned account, requested AES
profiles `20 19 18 17` (SDK) or `18 17` (MIT), available account profiles
`23 18 17`, and missing key ID `1`. The account advertises AES128/AES256 with
`msDS-SupportedEncryptionTypes=24`; its bad-password count remains zero. Both
domain and forest are at Windows 2016 functional level. The Linux configuration
names the exact owned DC and realm, initializes successfully, and the installed
MIT 1.20.1 version check succeeds in the producer's exact environment.

Microsoft documents this precise regression in the 8 November 2022 update,
including the same event text when RC4 is removed from an account's permitted
types. The documented correction is KB5021655, build `17763.3653`, on all domain
controllers, or a superseding fixed update. This is separate from the intended
Kerberos hardening. No SDK crypto downgrade, KRBTGT reset or encryption-policy
workaround is part of the remediation.
[Affected build and known issue](https://support.microsoft.com/en-us/servicing/os/windows-10/2022/11/november-8-2022-kb5019966-os-build-17763-3650-expired),
[Microsoft correction](https://support.microsoft.com/en-us/servicing/os/windows-10/2022/11/november-17-2022-kb5021655-os-build-17763-3653-out-of-band).

The failed producer's public-only configuration directory was checked for exact
ownership, mode, filename, size and SHA-256 before being archived. No keytab or
cache existed in it. The lab wrapper now retains only allowlisted stage, exit
code and failure category; raw tool output is never retained because tools can
echo credential input.

Servicing and fresh four-server qualification remain pending. Subsequent
evidence must retain the actual package identity/signature, before/after OS
build, controlled DC reboot and replication readiness, and outcomes from the
same SDK source. Failed observations remain separate from passing captures.
