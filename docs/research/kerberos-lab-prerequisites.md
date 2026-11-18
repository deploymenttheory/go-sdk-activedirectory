# Kerberos lab prerequisites and independent MIT fixtures

Research date: 2026-11-18. This note supports SDK04/SDK05 lab preparation; it is
not a claim that a particular DC has passed channel-binding tests. MIT tools are
lab reference tools only. The SDK password, keytab and FILE-cache paths must
continue to work without invoking them.

## Windows servicing and policy

Creating a registry value is configuration evidence, not enforcement evidence.
Microsoft dates LDAP channel-binding support to CVE-2017-8563, and dates the
channel-binding GPO and events 3039–3041 to March 10, 2020. These are separate
milestones. [Microsoft KB4520412](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412).

| DC release | Verified servicing milestone | Lab consequence |
| --- | --- | --- |
| Server 2016 | Microsoft's July 2017 CVRF maps CVE-2017-8563 to KB4025339 for Server 2016/product 10816 and Server Core/product 10855. KB4025339 is July 11, 2017, build **14393.1480**, and its security-update record requires a restart. [Microsoft CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2017-Jul), [KB4025339](https://support.microsoft.com/en-us/servicing/os/windows-10/2017/07/july-11-2017-kb4025339-os-build-14393-1480). | A genuinely unserviced RTM image predates that implementation. Inventory the running build and packages before drawing that conclusion. |
| Server 2016 | March 10, 2020 is **KB4540670, build 14393.3564**. [KB4540670](https://support.microsoft.com/en-gb/servicing/os/windows-10/2020/03/march-10-2020-kb4540670-os-build-14393-3564). | This identifies the 2020 controls/events baseline; it is not the first channel-binding implementation. |
| Server 2019 | March 10, 2020 is **KB4538461, build 17763.1098**. [KB4538461](https://support.microsoft.com/en-us/servicing/os/windows-10/2020/03/march-10-2020-kb4538461-os-build-17763-1098). | Original evaluation media can predate these GPO/events. Do not infer absence of direct-registry CBT enforcement from absence of the later events. |
| Server 2022 | Basic CBT is documented for this release. Optional audit events 3074/3075 arrived August 8, 2023 (**KB5029250, 20348.1906**); the manual audit-enablement step was removed November 14, 2023 (**KB5032198, 20348.2113**). [CBT overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), [KB5029250](https://support.microsoft.com/en-gb/servicing/os/windows-server/2023/08/august-8-2023-kb5029250-os-build-20348-1906), [KB5032198](https://support.microsoft.com/en-us/servicing/os/windows-server/2023/11/november-14-2023-kb5032198-os-build-20348-2113), [audit timeline](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412). | The 2023 audit updates are not prerequisites for basic CBT enforcement. |
| Server 2019 audit extension | Audit events 3074/3075 arrived October 10, 2023 (**KB5031361, 17763.4974**); manual audit enablement was removed January 9, 2024 (**KB5034127, 17763.5329**). These historical packages are now marked expired; use an applicable current cumulative update if servicing is required. [KB5031361](https://support.microsoft.com/en-au/servicing/os/windows-10/2023/10/october-10-2023-kb5031361-os-build-17763-4974-expired), [KB5034127](https://support.microsoft.com/en-gb/topic/january-9-2024-kb5034127-os-build-17763-5329-4de58ce5-eb0d-4b9a-95d1-aa15fe30b082), [audit timeline](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412). | Do not require these newer audit events on Server 2016 or use missing audit events as an enforcement result. |
| Server 2025 | Microsoft documents CBT and new-deployment signing enforcement for this release. [CBT overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), [signing overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing). | Inventory the extra signing-enforcement policy described below. New-deployment and upgrade defaults differ. |

**Inventory boundary:** the coordinating agent reported both Server 2025 DCs
at build `26100.32230`, with `LdapEnforceChannelBinding` absent,
`LDAPServerIntegrity` DWORD `1`, and GSSAPI advertised. These are supplied
read-only observations, not this researcher's probes. The earlier Server 2016
`Environment.OSVersion` observation `10.0.14393.0` does not establish the UBR or
installed cumulative update. Collect `CurrentBuildNumber`, `UBR`, `BuildLabEx`,
installed packages, and relevant server binary versions on every DC. Record
actual negative-probe results before classifying any profile as enforcing,
unsupported, or missing servicing.

All three policy values below are under
`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`:

| Value | Type and meaning |
| --- | --- |
| `LdapEnforceChannelBinding` | `REG_DWORD`: `0` Never, `1` When supported, **`2` Always**. Always rejects applicable SASL-over-TLS authentication without a valid CBT. [Microsoft CBT policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding). |
| `LDAPServerIntegrity` | AD DS `REG_DWORD`: **`1` None**, **`2` Require signing**. Do not substitute the AD LDS documentation's `0`/`2` mapping. [Microsoft policy/registry mapping](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412). |
| `LDAPServerEnforceIntegrity` (2025) | `REG_DWORD`: Microsoft maps enforced state to **`1`**, with allowed range `0..1`; this is not a `1`/`2` setting. [Microsoft baseline reference](https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc), [Microsoft baseline source CSV](https://raw.githubusercontent.com/microsoft/osconfig/main/security/SecurityBaseline_WindowsServer_2025-2504.csv). |

For the 2025 enforcement policy, Enabled overrides the legacy signing policy;
Disabled delegates to it. Not Configured has the effect of Enabled for new
deployments. Upgrades preserve existing policies, so an absent registry value
is not universal evidence of a particular effective signing level. The safe
strict fixture is CBT DWORD `2`, legacy signing DWORD `2`, and 2025 enforcement
DWORD `1`; never disable the new policy to make a probe pass. Before relying
on a raw `0` interpretation, verify the installed policy definition in
`%SystemRoot%\inf\Sceregvl.inf` or its effective security-policy export.
[Microsoft policy precedence/defaults](https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy).

**Restart distinction:** `LdapEnforceChannelBinding` is read dynamically; its
registry change needs no computer restart. The LDAP signing policy also needs
no device restart; GPO changes must first reach the DC through policy refresh.
These sources do not require an NTDS restart for either setting. Installing a
Windows update has its own restart requirements. Probe fresh connections after
application and again after restoration. [KB4034879](https://support.microsoft.com/en-us/servicing/os/windows-server/2020/02/kb4034879-use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls),
[signing restart requirement](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements#restart-requirement).

TLS satisfies `LDAPServerIntegrity=2`; AD does not require or allow an extra
SASL confidentiality/integrity layer inside TLS. CBT applies to TLS plus SASL;
TLS simple bind and certificate authentication do not test it. Plain LDAP
SASL signing/sealing does not test it either. AD's TLS binding type is
`tls-server-endpoint`. [MS-ADTS using SASL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/284923c1-6a5b-4510-b97a-631963c0c3bd),
[MS-ADTS using SSL/TLS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2c3ea153-eff9-46a7-8614-19b677efa4e0),
[Microsoft session-security matrix](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023).

## Enforcement evidence and exact restoration

The following is a lab acceptance design derived from those policy contracts:

1. Capture a durable baseline before mutation: each value's presence, registry
   kind and exact data; all three policy values; and
   `NTDS\Diagnostics\16 LDAP Interface Events` if diagnostic logging is changed.
   Capture effective policy/provenance so GPO refresh cannot silently invalidate
   the fixture. Do not overwrite unexpected types or unowned policy changes.
2. Establish valid credentials, the explicit `ldap/<DC-FQDN>@REALM` service,
   trusted certificate chain/name and TLS handshake independently. Use the
   same dedicated principal, DC and TLS transport for each comparison.
3. Under **Always**, require a complete successful SASL Kerberos bind and LDAP
   read with the correct CBT; require bind rejection with omitted CBT and with
   a deliberately wrong CBT. Exercise LDAPS and StartTLS independently. A
   connection failure, certificate failure or invalid-password rejection is
   not CBT evidence. Do not relax either policy for any comparison.
4. Test signing separately with a fresh unsigned SASL bind on non-TLS LDAP;
   require `strongAuthRequired` under required signing. A TLS bind succeeding
   proves neither plain-LDAP signing nor CBT by itself. Microsoft's own
   verification uses rejection of an unsigned bind.
   [Signing verification](https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy).
5. Collect sanitized result codes, time, DC build, certificate thumbprint and
   server events. Event 3039 is useful corroboration when present and diagnostic
   logging is at least `2`; 3074/3075 are audit capabilities with separate
   servicing requirements. They do not replace the wire outcome.
   [Microsoft event requirements](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412).
6. Restore in `finally` and support recovery from a durable ownership manifest.
   An originally absent value must be removed, not replaced with `0` or another
   default. An existing value must regain its original kind/data. Do not lower
   a previously strict setting or modify a concurrently changed value. Verify
   exact equality after cleanup and after any relevant policy refresh. Remove
   only certificates, keys, accounts and files created by this run, identified
   by recorded thumbprints/object GUIDs/paths; preserve pre-existing resources
   and event logs. Restoration failures make the run fail and remain visible.

The exact-state restoration requirement is this lab's stronger acceptance
rule. It avoids replacing an unknown baseline with an assumed default; it also
preserves the 2025 policy whose precedence is documented above.

## MIT client fixture recipe on Noble

Ubuntu's `krb5-user` provides MIT client tools. Current Noble-updates metadata
lists `1.20.1-6ubuntu2.10`; `krb5-config` is a recommendation, not a dependency.
The coordinator reports the same version of existing guest MIT libraries,
with the four client executables absent. Resolve packages against that actual
guest state rather than hard-coding a complete dependency list.
[Ubuntu package metadata](https://packages.ubuntu.com/noble-updates/krb5-user).

Use a dedicated unprivileged AD test user whose password was set for AES keys.
After password creation/reset, read **that account's** `msDS-KeyVersionNumber`
from the exact fixture DC and keep password/KVNO stable during generation.
This attribute is the account's current Kerberos key version. The number
printed by `kvno ldap/<DC-FQDN>` belongs to the service ticket and must not be
substituted for the client-user KVNO.
[Microsoft account KVNO](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-keyversionnumber),
[MIT kvno](https://web.mit.edu/kerberos/krb5-1.20/doc/user/user_commands/kvno.html).

Create a new caller-owned directory, mode `0700`, with `umask 077`; retain
config, keytab and caches there, mode `0600`. Use a controlled single-line
fixture password without CR/LF/NUL. Read it from an inherited stdin pipe into
a non-exported shell variable with tracing disabled. Do not interpolate a
secret into an SSH command, command argument, environment, transcript or
diagnostic output. MIT's POSIX prompter reads password replies from stdin.
[MIT prompter implementation](https://raw.githubusercontent.com/krb5/krb5/krb5-1.20.1-final/src/lib/krb5/os/prompter.c).

The following is a command recipe for the fixture script owner, not a request
to create users or execute it during research. `fixture_dir`, `client` and
`client_kvno` are validated nonsecret script inputs; use a fresh path without
spaces and the actual dedicated user's principal, preserving its case.

```bash
set +x
set -euo pipefail
umask 077
IFS= read -r fixture_password  # inherited stdin, never an argument

# Example values: use the actual owned fixture directory and AD user/KVNO.
# client=sdk04-fixture-user@AD.SDK.TEST
# client_kvno=<msDS-KeyVersionNumber of that user>
# fixture_dir=<new caller-owned absolute directory>
cat > "$fixture_dir/krb5.conf" <<'KRB5CONF'
[libdefaults]
 default_realm = AD.SDK.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 dns_canonicalize_hostname = false
 rdns = false
 udp_preference_limit = 1
 forwardable = false
 proxiable = false
 renew_lifetime = 0s
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 AD.SDK.TEST = {
  kdc = adsdk25dc1.ad.sdk.test:88
 }
[domain_realm]
 .ad.sdk.test = AD.SDK.TEST
 ad.sdk.test = AD.SDK.TEST
KRB5CONF

unset KRB5_TRACE KRB5CCNAME KRB5_KTNAME KRB5_CLIENT_KTNAME
export KRB5_CONFIG="$fixture_dir/krb5.conf" LC_ALL=C TZ=UTC
spn=ldap/adsdk25dc1.ad.sdk.test@AD.SDK.TEST

# printf must be the shell builtin; its format never contains the password.
printf '%s\n' "$fixture_password" |
  /usr/bin/kinit -F -P -l 10m -c "FILE:$fixture_dir/password.ccache" "$client"
/usr/bin/kvno -c "FILE:$fixture_dir/password.ccache" "$spn"
/usr/bin/klist -c -e -f "FILE:$fixture_dir/password.ccache"

# A new ktutil process starts with an empty keylist; refuse an existing file.
test ! -e "$fixture_dir/client.keytab"
{
  printf 'add_entry -password -p %s -k %s -e aes256-cts-hmac-sha1-96 -f\n' \
    "$client" "$client_kvno"
  printf '%s\n' "$fixture_password"
  printf 'write_kt %s\nquit\n' "$fixture_dir/client.keytab"
} | /usr/bin/ktutil >/dev/null 2>&1

# Verify entries without printing key material; ktutil exit status alone is
# insufficient evidence that all interactive requests succeeded.
/usr/bin/klist -k -t -e "$fixture_dir/client.keytab"
/usr/bin/kinit -F -P -l 10m -k -t "$fixture_dir/client.keytab" \
  -c "FILE:$fixture_dir/keytab.ccache" "$client"
/usr/bin/kvno -c "FILE:$fixture_dir/keytab.ccache" "$spn"
/usr/bin/klist -c -e -f "FILE:$fixture_dir/keytab.ccache"

# Generate a distinct real short-lived cache before removing the secret.
printf '%s\n' "$fixture_password" |
  /usr/bin/kinit -F -P -l 1m -c "FILE:$fixture_dir/expired.ccache" "$client"
unset fixture_password
/usr/bin/kvno -c "FILE:$fixture_dir/expired.ccache" "$spn"
/usr/bin/klist -c -e -f "FILE:$fixture_dir/expired.ccache"
chmod 600 "$fixture_dir/krb5.conf" "$fixture_dir/client.keytab" \
  "$fixture_dir/password.ccache" "$fixture_dir/keytab.ccache" \
  "$fixture_dir/expired.ccache"
```

`KRB5_CONFIG` names one explicit file with no include directives, preventing
ambient `/etc/krb5.conf` configuration. Explicit cache/keytab options prevent
use of a user's default collection. DNS must still resolve the deliberately
chosen DC FQDN through the lab's existing DNS configuration.
[MIT configuration](https://web.mit.edu/kerberos/krb5-1.20/doc/admin/conf_files/krb5_conf.html).

Here **ktutil `-f` fetches KDC salt information** and may be combined with
`-e`; it also obtains string-to-key parameters in MIT 1.20.1. Without it,
ktutil uses a locally constructed default salt unless `-s` is provided.
Do not infer the AD salt by changing case or rebuilding a guessed UPN.
Microsoft defines case-sensitive input components for AES salt derivation;
preserve the KDC-provided bytes even if account lookup accepts other case.
In contrast, **kinit `-f` means forwardable**; the recipe uses `-F`.
[Ubuntu Noble ktutil](https://manpages.ubuntu.com/manpages/noble/man1/ktutil.mit.1.html),
[MIT ktutil salt/parameters implementation](https://raw.githubusercontent.com/krb5/krb5/krb5-1.20.1-final/src/kadmin/ktutil/ktutil_funcs.c),
[MS-KILE cryptographic material](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/7a7b081d-c0c6-46f4-acbf-a439664270b8),
[MIT kinit flags](https://manpages.ubuntu.com/manpages/noble/man1/kinit.mit.1.html).

Never use `klist -K` or `ktutil list -k`: these print key material. Verify
the client principal, AES enctype, client KVNO, TGT, exact LDAP service
principal and issued times. Save sanitized metadata separately from secrets.
The independent password-issued cache, locally generated keytab, and
keytab-issued cache then provide separate SDK input fixtures.
[MIT klist](https://web.mit.edu/kerberos/krb5-1.20/doc/user/user_commands/klist.html),
[MIT ktutil](https://web.mit.edu/kerberos/krb5-1.20/doc/admin/admin_commands/ktutil.html).

## Real expired-ticket fixture

`kinit -l 1m` requests a lifetime; the issued end time is the evidence, not
the requested value. Immediately record `TZ=UTC klist -c -e -f` output for
`expired.ccache`, confirm both TGT and LDAP ticket were issued and usable,
and record the cache SHA-256. Do not edit cache timestamps, renew it,
re-run kinit into it, change any clock, or change realm ticket policies.
[MIT kinit lifetime semantics](https://web.mit.edu/kerberos/krb5-1.20/doc/user/user_commands/kinit.html).

Wait on the real clock past the latest actual ticket end time. For a
server-side expiry test, also pass the applicable server clock-skew allowance;
RFC 4120 allows the server that margin. MIT's library default allowance is
300 seconds, but do not assume the DC's configured allowance from that.
If a DC issues a longer lifetime, wait for it or record the fixture as
pending; do not manufacture an expired ticket.
[RFC 4120 section 3.2.3](https://datatracker.ietf.org/doc/html/rfc4120#section-3.2.3),
[MIT clockskew](https://web.mit.edu/kerberos/krb5-1.20/doc/admin/conf_files/krb5_conf.html#libdefaults).

Require successful parsing/listing of that same unchanged file and expiry
of its recorded TGT; `klist -s -c FILE:<path>` must exit `1` after previously
returning `0`. Exit `1` alone also means unreadable/missing, so it is not
enough. MIT 1.20.1 checks the local TGT's issued end time when one exists.
Record `date -u +'%Y-%m-%dT%H:%M:%SZ'` and `sha256sum <cache-path>` with
the pre-expiry and post-expiry listings.
For the SDK's local-expiry path, require a typed expiry failure without
password/keytab refresh. For any claimed server rejection, capture the real
Kerberos expiry result from a cache-only attempt after the server allowance;
a DNS/TLS failure does not prove it. Preserve ownership/mode and the original
cache hash throughout.
[MIT klist status contract](https://web.mit.edu/kerberos/krb5-1.20/doc/user/user_commands/klist.html),
[MIT 1.20.1 expiry check](https://raw.githubusercontent.com/krb5/krb5/krb5-1.20.1-final/src/clients/klist/klist.c).

## Signed offline installation without guest network changes

Use the existing host-to-guest SSH path and preserve the guest's addresses,
DNS, routes and absence of a default gateway. The following is the installer
design, not a report that installation occurred.

1. Read guest OS/codename, `dpkg --print-architecture`, foreign architectures,
   `/var/lib/dpkg/status`, installed package versions, available `gpgv` and
   `/usr/share/keyrings/ubuntu-archive-keyring.gpg`. Record initial client-tool
   absence. The existing authenticated Ubuntu installation's archive keyring
   is the trust anchor; a newly downloaded unsigned keyring is not one.
2. On the networked host, fetch official Ubuntu `noble`, `noble-updates` and
   `noble-security` metadata for the needed `main` and `universe` architecture
   indexes from `archive.ubuntu.com/ubuntu` and
   `security.ubuntu.com/ubuntu`. Retain original `InRelease` files (or
   `Release` plus `Release.gpg`), index bytes and paths. Upload through SSH.
3. Authenticate each release with the installed Ubuntu archive keyring,
   for example:

   ```bash
   gpgv --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg \
     --output verified-Release InRelease
   ```

   Require success before using output. Check release suite/codename,
   architecture and freshness. Preserve APT's date/Valid-Until checks.
   Compare each downloaded index's size and **SHA-256** with its signed
   release entry, then each selected `.deb` with its authenticated Packages
   stanza's `Filename`, `Size`, `Architecture`, `Version` and **SHA256**.
   Recheck hashes after SSH transfer. This is an archive-signature chain;
   `.deb` files are not individually signed by apt-secure.
   [Ubuntu apt-secure trust chain](https://manpages.ubuntu.com/manpages/noble/man8/apt-secure.8.html),
   [gpgv keyring/output behavior](https://manpages.ubuntu.com/manpages/noble/man1/gpgv.1.html),
   [APT freshness checks](https://manpages.ubuntu.com/manpages/noble/man5/apt.conf.5.html).
4. Resolve **`krb5-user` only**, with `--no-install-recommends`, against the
   guest's actual installed status and the verified indexes. Include required
   dependency upgrades together; respect exact-version constraints. Noble's
   package includes dependencies on administration/database **libraries**;
   those do not imply a `krb5-kdc` or `krb5-admin-server` daemon installation.
   Reject unrelated removals, downgrades, held-package overrides or broad
   base-system upgrades; expose a prerequisite conflict instead.
   [Ubuntu package dependencies](https://packages.ubuntu.com/noble-updates/krb5-user),
   [APT no-recommends/simulation](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html).
5. A suitable implementation uses a temporary local `file:` mirror preserving
   Ubuntu's signed metadata and pool paths, a dedicated source file with
   `signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg`, and isolated
   lists/cache paths. `Dir::State::status` must identify the guest's status;
   solving on a host requires an exact copy of it. Do not overwrite guest
   sources or `/etc/krb5.conf`. Obtain a dry-run/URI plan, host-download only
   the missing selected packages, verify them, SSH-upload them and install
   offline from that bounded plan. `--print-uris` is useful for paths, but
   its documented hash is MD5; use the Packages **SHA256** for verification.
   [APT file sources and signed-by](https://manpages.ubuntu.com/manpages/noble/man5/sources.list.5.html),
   [APT state/cache isolation](https://manpages.ubuntu.com/manpages/noble/man5/apt.conf.5.html),
   [APT URI/download options](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html).
6. Keep unsigned-repository/unauthenticated-package overrides disabled.
   Confirm `kinit`, `ktutil`, `kvno`, `klist` provenance and installed versions,
   dependency consistency and unchanged guest network state. Use explicit
   fixture configuration, avoiding `krb5-config`'s optional global setup.
   Retain a nonsecret manifest of release signatures, package versions,
   origins, sizes and SHA-256 values for review/reproduction.

Remaining execution evidence belongs to the lab runner: full per-profile
servicing inventory, installed 2025 enforcement-policy definition, strict
CBT/signing probe outcomes, independent MIT fixture metadata, observed real
expiry and exact restoration. No lab mutation, package installation, account
creation or policy change was performed while writing this note.
