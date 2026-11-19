"""Opt-in independent MIT acceptor; offline, bounded private stdin, keyless output.

ABI references: MIT src/include/krb5/krb5.hin and
src/lib/gssapi/{generic/gssapi{,_ext}.h,krb5/gssapi_krb5.h}.
Only an explicitly acquired service keytab and a new MEMORY ccache are used.
No KDC/LDAP sockets, SDK decoder, ambient credential or persistent ccache.
"""

import base64
import ctypes as C
import ctypes.util
import json
import os
import stat
import sys
import time

U32, I32, Ptr = C.c_uint32, C.c_int32, C.c_void_p


class Buffer(C.Structure):
    _fields_ = [("length", C.c_size_t), ("value", Ptr)]


class OID(C.Structure):
    _fields_ = [("length", U32), ("elements", Ptr)]


class OIDSet(C.Structure):
    _fields_ = [("count", C.c_size_t), ("elements", C.POINTER(OID))]


class KV(C.Structure):
    _fields_ = [("key", C.c_char_p), ("value", C.c_char_p)]


class Store(C.Structure):
    _fields_ = [("count", U32), ("elements", C.POINTER(KV))]


class Key(C.Structure):
    _fields_ = [("magic", I32), ("enctype", I32), ("length", U32), ("contents", Ptr)]


class Times(C.Structure):
    _fields_ = [(field, I32) for field in ("auth", "start", "end", "renew")]


class Data(C.Structure):
    _fields_ = [("magic", I32), ("length", U32), ("contents", Ptr)]


class Creds(C.Structure):
    _fields_ = [("magic", I32), ("client", Ptr), ("server", Ptr), ("key", Key),
                ("times", Times), ("is_skey", U32), ("flags", I32),
                ("addresses", Ptr), ("ticket", Data), ("second_ticket", Data), ("authdata", Ptr)]


def bind(lib, name, args, result=U32):
    function = getattr(lib, name)
    function.restype, function.argtypes = result, args
    return function


def backing(data):
    allocation = C.create_string_buffer(data)
    return allocation, Buffer(len(data), C.cast(allocation, Ptr))


def oid(data):
    allocation = C.create_string_buffer(data)
    return allocation, OID(len(data), C.cast(allocation, Ptr))


class SafeFailure(Exception):
    def __init__(self, operation, code, minor=0):
        self.operation, self.code, self.minor = operation, int(code), int(minor)


def check(operation, code):
    if code != 0:
        raise SafeFailure(operation, code)


def main():
    raw = sys.stdin.buffer.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise SafeFailure("input_bound", 1)
    request = json.loads(raw)
    if set(request) != {"token", "keytab", "service", "client", "realm", "delegate"}:
        raise SafeFailure("input_schema", 1)
    if type(request["delegate"]) is not bool or any(not isinstance(request[field], str) or
            not request[field] or len(request[field]) > 4096 for field in ("keytab", "service", "client", "realm")):
        raise SafeFailure("input_types", 1)
    keytab_info = os.stat(request["keytab"], follow_symlinks=False)
    if not stat.S_ISREG(keytab_info.st_mode) or keytab_info.st_mode & 0o077:
        raise SafeFailure("private_keytab", 1)
    token_bytes = base64.b64decode(request["token"], validate=True)
    if not token_bytes or len(token_bytes) > 65535:
        raise SafeFailure("token_bound", 1)

    gss = C.CDLL(ctypes.util.find_library("gssapi_krb5"))
    krb = C.CDLL(ctypes.util.find_library("krb5"))
    import_name = bind(gss, "gss_import_name", [Ptr, Ptr, Ptr, Ptr])
    acquire = bind(gss, "gss_acquire_cred_from", [Ptr, Ptr, U32, Ptr, C.c_int, Ptr, Ptr, Ptr, Ptr])
    accept = bind(gss, "gss_accept_sec_context", [Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr])
    display = bind(gss, "gss_display_name", [Ptr, Ptr, Ptr, Ptr])
    inquire = bind(gss, "gss_inquire_context", [Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr])
    release_buffer = bind(gss, "gss_release_buffer", [Ptr, Ptr])
    release_name = bind(gss, "gss_release_name", [Ptr, Ptr])
    release_cred = bind(gss, "gss_release_cred", [Ptr, Ptr])
    delete_context = bind(gss, "gss_delete_sec_context", [Ptr, Ptr, Ptr])
    copy_cache = bind(gss, "gss_krb5_copy_ccache", [Ptr, Ptr, Ptr])
    init = bind(krb, "krb5_init_context", [Ptr], I32)
    free_context = bind(krb, "krb5_free_context", [Ptr], None)
    cc_new = bind(krb, "krb5_cc_new_unique", [Ptr, C.c_char_p, C.c_char_p, Ptr], I32)
    cc_init = bind(krb, "krb5_cc_initialize", [Ptr, Ptr, Ptr], I32)
    cc_destroy = bind(krb, "krb5_cc_destroy", [Ptr, Ptr], I32)
    cc_type = bind(krb, "krb5_cc_get_type", [Ptr, Ptr], C.c_char_p)
    parse = bind(krb, "krb5_parse_name", [Ptr, C.c_char_p, Ptr], I32)
    unparse = bind(krb, "krb5_unparse_name", [Ptr, Ptr, Ptr], I32)
    free_principal = bind(krb, "krb5_free_principal", [Ptr, Ptr], None)
    free_name = bind(krb, "krb5_free_unparsed_name", [Ptr, Ptr], None)
    start = bind(krb, "krb5_cc_start_seq_get", [Ptr, Ptr, Ptr], I32)
    next_cred = bind(krb, "krb5_cc_next_cred", [Ptr, Ptr, Ptr, Ptr], I32)
    end = bind(krb, "krb5_cc_end_seq_get", [Ptr, Ptr, Ptr], I32)
    free_cred = bind(krb, "krb5_free_cred_contents", [Ptr, Ptr], None)

    minor = U32()
    name, credential, context, actor, target, delegated = (Ptr() for _ in range(6))
    krb_context, cache, principal, cursor = (Ptr() for _ in range(4))
    output, token_allocation = Buffer(), None
    cursor_open = False

    def display_name(value):
        result = Buffer()
        check("display_name", display(C.byref(minor), value, C.byref(result), None))
        try:
            if result.length > 4096:
                raise SafeFailure("name_bound", 1)
            return C.string_at(result.value, result.length).decode("utf-8")
        finally:
            release_buffer(C.byref(minor), C.byref(result))

    def principal_name(value):
        text = Ptr()
        check("principal_name", unparse(krb_context, value, C.byref(text)))
        try:
            return C.string_at(text).decode("utf-8")
        finally:
            free_name(krb_context, text)

    try:
        name_allocation, name_buffer = backing(request["service"].encode("ascii"))
        name_oid_allocation, name_oid = oid(bytes.fromhex("2a864886f71201020201"))
        mechanism_allocation, mechanism = oid(bytes.fromhex("2a864886f712010202"))
        mechanisms = (OID * 1)(mechanism)
        desired = OIDSet(1, mechanisms)
        elements = (KV * 1)(KV(b"keytab", os.fsencode(request["keytab"])))
        store = Store(1, elements)
        check("import_name", import_name(C.byref(minor), C.byref(name_buffer), C.byref(name_oid), C.byref(name)))
        check("acquire_explicit_keytab", acquire(C.byref(minor), name, 0, C.byref(desired), 2, C.byref(store), C.byref(credential), None, None))
        token_allocation, token = backing(token_bytes)
        flags, life, selected = U32(), U32(), C.POINTER(OID)()
        major = accept(C.byref(minor), C.byref(context), credential, C.byref(token), None, C.byref(actor),
                       C.byref(selected), C.byref(output), C.byref(flags), C.byref(life), C.byref(delegated))
        if major != 0:
            raise SafeFailure("accept_context", major, minor.value)
        if not selected or C.string_at(selected.contents.elements, selected.contents.length) != bytes.fromhex("2a864886f712010202"):
            raise SafeFailure("mechanism", 1)
        check("inquire_context", inquire(C.byref(minor), context, None, C.byref(target), None, None, None, None, None))
        actual_client, actual_service = display_name(actor), display_name(target)
        if actual_client != request["client"] or actual_service != request["service"] or flags.value & 0x3e != 0x3e:
            raise SafeFailure("authenticated_identity_or_flags", 1)
        if bool(flags.value & 1) != request["delegate"] or bool(delegated) != request["delegate"]:
            raise SafeFailure("actual_delegated_credential", 1)
        records = []
        if delegated:
            check("init_krb", init(C.byref(krb_context)))
            check("new_memory_cache", cc_new(krb_context, b"MEMORY", None, C.byref(cache)))
            if cc_type(krb_context, cache) != b"MEMORY":
                raise SafeFailure("nonmemory_cache", 1)
            check("parse_actor", parse(krb_context, request["client"].encode("ascii"), C.byref(principal)))
            check("init_memory_cache", cc_init(krb_context, cache, principal))
            major = copy_cache(C.byref(minor), delegated, cache)
            if major != 0:
                raise SafeFailure("copy_delegated_cache", major, minor.value)
            check("start_cache_cursor", start(krb_context, cache, C.byref(cursor)))
            cursor_open = True
            for _ in range(8):
                item = Creds()
                code = next_cred(krb_context, cache, C.byref(cursor), C.byref(item))
                if code == -1765328242:  # KRB5_CC_END, MIT krb5 error table.
                    break
                check("next_cache_credential", code)
                try:
                    client, server = principal_name(item.client), principal_name(item.server)
                    if client != request["client"] or server != "krbtgt/" + request["realm"] + "@" + request["realm"] or \
                            item.key.enctype not in (17, 18, 19, 20) or item.flags & 0x60000000 != 0x60000000 or item.times.end <= time.time():
                        raise SafeFailure("forwarded_ticket_metadata", 1)
                    records.append(dict(client=client, service=server, enctype=int(item.key.enctype),
                                        flags=int(item.flags), end_unix=int(item.times.end)))
                finally:
                    free_cred(krb_context, C.byref(item))
            else:
                raise SafeFailure("cache_count_bound", 1)
            if len(records) != 1:
                raise SafeFailure("credential_cardinality", 1)
        return dict(schema_version=1, complete=True, mechanism="Kerberos", client=actual_client,
                    service=actual_service, flags=int(flags.value), lifetime_seconds=int(life.value),
                    delegated_credential=bool(delegated), cache_type="MEMORY" if delegated else "none", tickets=records)
    finally:
        retirement = []
        if token_allocation is not None:
            C.memset(token_allocation, 0, C.sizeof(token_allocation))
        if output.value:
            retirement.append(release_buffer(C.byref(minor), C.byref(output)))
        if cursor_open:
            retirement.append(end(krb_context, cache, C.byref(cursor)))
        if cache:
            retirement.append(cc_destroy(krb_context, cache))
        if principal:
            free_principal(krb_context, principal)
        if krb_context:
            free_context(krb_context)
        if context:
            retirement.append(delete_context(C.byref(minor), C.byref(context), None))
        for value in (delegated, credential):
            if value:
                retirement.append(release_cred(C.byref(minor), C.byref(value)))
        for value in (target, actor, name):
            if value:
                retirement.append(release_name(C.byref(minor), C.byref(value)))
        if any(retirement):
            raise SafeFailure("retire_owned_state", next(code for code in retirement if code))


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True))
    except SafeFailure as failure:
        print(json.dumps(dict(error=failure.operation, code=failure.code, minor=failure.minor)), file=sys.stderr)
        sys.exit(1)
    except Exception as failure:
        print(json.dumps(dict(error="mit_fixture_boundary", class_name=type(failure).__name__)), file=sys.stderr)
        sys.exit(1)
