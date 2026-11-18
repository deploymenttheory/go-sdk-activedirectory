#!/usr/bin/env python3
"""Lab-only MIT credential producer. Secret input/output uses pinned SSH pipes."""
import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys


class FixtureError(Exception):
    pass


def reject(message):
    raise FixtureError(message)


def validate_request(value):
    required = {"run_id", "principal", "client_kvno", "server", "linux_owner", "password_base64"}
    if not isinstance(value, dict) or set(value) != required:
        reject("Unexpected reference fixture input fields")
    run = value["run_id"]
    if not isinstance(run, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{5,39}", run):
        reject("Invalid fixture run identity")
    sam = "sdkkrb" + hashlib.sha256(run.encode()).hexdigest()[:12]
    if value["principal"] != sam + "@AD.SDK.TEST":
        reject("Principal is not derived from this owned run")
    if not isinstance(value["server"], str) or not re.fullmatch(r"adsdk(16|19|22|25)dc1\.ad\.sdk\.test", value["server"]):
        reject("Server is outside the isolated fixture profiles")
    if type(value["client_kvno"]) is not int or not 1 <= value["client_kvno"] <= 0xFFFFFFFF:
        reject("Invalid independently observed client KVNO")
    if not isinstance(value["linux_owner"], str) or not re.fullmatch(r"[0-9a-f-]{36}", value["linux_owner"]):
        reject("Invalid isolated Linux ownership identity")
    try:
        secret = base64.b64decode(value["password_base64"], validate=True)
    except (ValueError, TypeError):
        reject("Invalid secret input encoding")
    if not 24 <= len(secret) <= 256 or any(x in secret for x in (b"\r", b"\n", b"\0")):
        reject("Reference fixture secret must be bounded and single line")
    return secret


def check_parent(path):
    for entry in [path, *path.parents]:
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            reject("Reference fixture path traverses a non-directory or symlink")
    if path.stat().st_uid != os.getuid():
        reject("Reference fixture parent is not caller-owned")


def write_private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def tool(env, step, arguments, data=None, accepted=(0,)):
    process = subprocess.run(arguments, input=data, capture_output=True, env=env, timeout=45)
    if process.returncode not in accepted:
        # ktutil can echo its input: never include tool diagnostics in errors.
        reject("MIT reference step %s failed (exit %d)" % (step, process.returncode))
    return process


def inspect_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 1024 * 1024:
        reject("Reference credential is not a bounded owned ordinary file")
    os.chmod(path, 0o600)
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "mode": "0600"}


def produce(value):
    password = validate_request(value)
    if pathlib.Path("/etc/adsdk-linux-owner").read_text().strip() != value["linux_owner"] or os.uname().nodename != "adsdklinux01":
        reject("Reference generator is not on the owned isolated Linux client")
    os.umask(0o077)
    parent = pathlib.Path("/home/adsdk/acceptance")
    check_parent(parent)
    directory = parent / ("mit-" + value["run_id"])
    directory.mkdir(mode=0o700)  # no reuse, including partial/failed runs
    principal = value["principal"]
    spn = "ldap/" + value["server"] + "@AD.SDK.TEST"
    config = """[libdefaults]
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
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 AD.SDK.TEST = {
  kdc = %s:88
 }
[domain_realm]
 .ad.sdk.test = AD.SDK.TEST
 ad.sdk.test = AD.SDK.TEST
""" % value["server"]
    write_private(directory / "krb5.conf", config.encode())
    env = {"PATH": "/usr/bin:/bin", "HOME": "/home/adsdk", "LC_ALL": "C", "TZ": "UTC", "KRB5_CONFIG": str(directory / "krb5.conf")}
    version = tool(env, "version", ["/usr/bin/klist", "-V"]).stdout.decode().strip()
    if "Kerberos 5 version 1.20.1" not in version:
        reject("Unexpected independently installed MIT version")
    evidence = {"schema_version": 1, "run_id": value["run_id"], "server": value["server"], "principal": principal,
                "client_kvno": value["client_kvno"], "linux_owner": value["linux_owner"], "directory": str(directory),
                "tool_version": version, "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "sdk_runtime_used": False, "secret_files": {}, "mit_listings": {}}
    password_cache = directory / "password.ccache"
    tool(env, "password-kinit", ["/usr/bin/kinit", "-F", "-P", "-l", "2h", "-c", "FILE:" + str(password_cache), principal], password + b"\n")
    # Preserve an actual MIT-issued TGT-only cache before requesting a service.
    write_private(directory / "tgt-only.ccache", password_cache.read_bytes())
    tool(env, "password-kvno", ["/usr/bin/kvno", "-c", "FILE:" + str(password_cache), spn])
    keytab = directory / "client.keytab"
    commands = ("add_entry -password -p %s -k %d -e aes256-cts-hmac-sha1-96 -f\n" % (principal, value["client_kvno"])).encode()
    commands += password + b"\n" + ("write_kt %s\nquit\n" % keytab).encode()
    tool(env, "ktutil", ["/usr/bin/ktutil"], commands)
    commands = None
    inspect_file(keytab)
    keytab_listing = tool(env, "keytab-list", ["/usr/bin/klist", "-k", "-t", "-e", str(keytab)]).stdout.decode()
    if principal not in keytab_listing or "aes256-cts-hmac-sha1-96" not in keytab_listing:
        reject("MIT could not independently list the expected client keytab")
    evidence["mit_listings"]["client.keytab"] = keytab_listing
    keytab_cache = directory / "keytab.ccache"
    tool(env, "keytab-kinit", ["/usr/bin/kinit", "-F", "-P", "-l", "2h", "-k", "-t", str(keytab), "-c", "FILE:" + str(keytab_cache), principal])
    tool(env, "keytab-kvno", ["/usr/bin/kvno", "-c", "FILE:" + str(keytab_cache), spn])
    for name in ("tgt-only.ccache", "password.ccache", "keytab.ccache"):
        path = directory / name
        listing = tool(env, "cache-list", ["/usr/bin/klist", "-c", "-e", "-f", "FILE:" + str(path)]).stdout.decode()
        if "Default principal: " + principal not in listing or "krbtgt/AD.SDK.TEST@AD.SDK.TEST" not in listing:
            reject("MIT cache identity/TGT readback differs")
        if name != "tgt-only.ccache" and spn not in listing:
            reject("MIT cache lacks the exact issued LDAP service ticket")
        if name == "tgt-only.ccache" and spn in listing:
            reject("TGT-only fixture unexpectedly contains a service ticket")
        evidence["mit_listings"][name] = listing
        evidence["secret_files"][name] = inspect_file(path)
    evidence["secret_files"]["client.keytab"] = inspect_file(keytab)
    expired = directory / "expiry-probe-2m.ccache"
    tool(env, "short-kinit", ["/usr/bin/kinit", "-F", "-P", "-l", "2m", "-c", "FILE:" + str(expired), principal], password + b"\n")
    password = None
    value["password_base64"] = None
    tool(env, "short-valid-immediately-after-issuance", ["/usr/bin/klist", "-s", "-c", "FILE:" + str(expired)])
    listing = tool(env, "short-list", ["/usr/bin/klist", "-c", "-e", "-f", "FILE:" + str(expired)]).stdout.decode()
    if principal not in listing or "krbtgt/AD.SDK.TEST@AD.SDK.TEST" not in listing:
        reject("Real short-lived fixture lacks the issued TGT")
    status = tool(env, "short-valid-before-expiry", ["/usr/bin/klist", "-s", "-c", "FILE:" + str(expired)])
    evidence["mit_listings"]["expiry-probe-2m.ccache"] = listing
    evidence["short_cache_before_expiry"] = {"klist_s_exit": status.returncode, "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "requested_lifetime": "2m", "clock_changed": False}
    evidence["secret_files"]["expiry-probe-2m.ccache"] = inspect_file(expired)
    evidence["expiry_scope"] = "Local FILE-cache TGT expiry; no short-lived LDAP service ticket or server-side expiry is claimed"
    evidence["producer_sha256"] = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    write_private(directory / "reference.json", json.dumps(evidence, indent=2).encode())
    return evidence


def main():
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            reject("Reference fixture stdin exceeds limit")
        value = json.loads(raw)
        result = produce(value)
        print(json.dumps(result))
    except Exception as error:
        # Unexpected exception messages may contain input; report only fixed text.
        message = str(error) if isinstance(error, FixtureError) else "Reference fixture execution failed (" + type(error).__name__ + ")"
        print(json.dumps({"success": False, "error": message}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
