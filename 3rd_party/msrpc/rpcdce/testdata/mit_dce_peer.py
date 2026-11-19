"""Offline synthetic MIT GSS acceptor. No sockets, credentials or code from the SDK.

ABI/constants: MIT krb5 src/lib/gssapi/generic/gssapi{,_ext}.h. This fixture uses
the installed library through ctypes so it needs no dev headers or OS packages.
All protocol input/output is bounded JSON on private stdin/stdout, never logging.
"""
import base64
import ctypes as C
import ctypes.util
import json
import sys

U32=C.c_uint32
Ptr=C.c_void_p
class Buffer(C.Structure):_fields_=[("length",C.c_size_t),("value",Ptr)]
class OID(C.Structure):_fields_=[("length",U32),("elements",Ptr)]
class OIDSet(C.Structure):_fields_=[("count",C.c_size_t),("elements",C.POINTER(OID))]
class KV(C.Structure):_fields_=[("key",C.c_char_p),("value",C.c_char_p)]
class Store(C.Structure):_fields_=[("count",U32),("elements",C.POINTER(KV))]
class IOV(C.Structure):_fields_=[("type",U32),("buffer",Buffer)]

lib=C.CDLL(ctypes.util.find_library("gssapi_krb5"))
def bind(name,args):
    fn=getattr(lib,name);fn.restype=U32;fn.argtypes=args;return fn
import_name=bind("gss_import_name",[C.POINTER(U32),C.POINTER(Buffer),C.POINTER(OID),C.POINTER(Ptr)])
acquire=bind("gss_acquire_cred_from",[C.POINTER(U32),Ptr,U32,C.POINTER(OIDSet),C.c_int,C.POINTER(Store),C.POINTER(Ptr),Ptr,Ptr])
accept=bind("gss_accept_sec_context",[C.POINTER(U32),C.POINTER(Ptr),Ptr,C.POINTER(Buffer),Ptr,Ptr,C.POINTER(C.POINTER(OID)),C.POINTER(Buffer),C.POINTER(U32),Ptr,Ptr])
release_buffer=bind("gss_release_buffer",[C.POINTER(U32),C.POINTER(Buffer)])
release_name=bind("gss_release_name",[C.POINTER(U32),C.POINTER(Ptr)])
release_cred=bind("gss_release_cred",[C.POINTER(U32),C.POINTER(Ptr)])
delete_context=bind("gss_delete_sec_context",[C.POINTER(U32),C.POINTER(Ptr),Ptr])
unwrap=bind("gss_unwrap_iov",[C.POINTER(U32),Ptr,C.POINTER(C.c_int),C.POINTER(U32),C.POINTER(IOV),C.c_int])
wrap_length=bind("gss_wrap_iov_length",[C.POINTER(U32),Ptr,C.c_int,U32,C.POINTER(C.c_int),C.POINTER(IOV),C.c_int])
wrap=bind("gss_wrap_iov",[C.POINTER(U32),Ptr,C.c_int,U32,C.POINTER(C.c_int),C.POINTER(IOV),C.c_int])

def backing(data):
    allocation=C.create_string_buffer(data)
    return allocation,Buffer(len(data),C.cast(allocation,Ptr))
def oid(data):
    allocation=C.create_string_buffer(data)
    return allocation,OID(len(data),C.cast(allocation,Ptr))
def decode(value):
    data=base64.b64decode(value,validate=True)
    if len(data)>65535:raise ValueError("fixture input bound")
    return data
def encode(data):return base64.b64encode(data).decode("ascii")
def status(major,minor):
    if major not in (0,1):
        raise RuntimeError(json.dumps(dict(error="mit_gss_failure",major=int(major),minor=int(minor))))

name,credential,context=Ptr(),Ptr(),Ptr()
minor=U32()
principal=sys.argv[2].encode("ascii")
name_storage,name_buffer=backing(principal)
name_oid_storage,name_oid=oid(bytes.fromhex("2a864886f71201020201"))
mech_storage,mech=oid(bytes.fromhex("2a864886f712010202"))
mechanisms=(OID*1)(mech)
desired=OIDSet(1,mechanisms)
keytab=sys.argv[1].encode()
elements=(KV*1)(KV(b"keytab",keytab))
store=Store(1,elements)
try:
    status(import_name(C.byref(minor),C.byref(name_buffer),C.byref(name_oid),C.byref(name)),minor.value)
    status(acquire(C.byref(minor),name,0,C.byref(desired),2,C.byref(store),C.byref(credential),None,None),minor.value)
    while True:
        line=sys.stdin.buffer.readline(512*1024+1)
        if not line:break
        if len(line)>512*1024:raise ValueError("fixture message bound")
        request=json.loads(line)
        op=request["op"]
        if op=="accept":
            token_storage,token=backing(decode(request["token"]))
            output=Buffer();flags=U32();selected=C.POINTER(OID)()
            major=accept(C.byref(minor),C.byref(context),credential,C.byref(token),None,None,C.byref(selected),C.byref(output),C.byref(flags),None,None)
            status(major,minor.value)
            if selected and C.string_at(selected.contents.elements,selected.contents.length)!=bytes.fromhex("2a864886f712010202"):
                raise ValueError("unexpected mechanism")
            payload=C.string_at(output.value,output.length) if output.length else b""
            release_buffer(C.byref(minor),C.byref(output))
            result=dict(major=int(major),flags=int(flags.value),token=encode(payload))
        elif op in ("unwrap","wrap"):
            allocations=[]
            array=(IOV*4)()
            for i,(field,kind) in enumerate([("header",11),("body",1),("trailer",11),("token",2)]):
                data=b"" if op=="wrap" and field=="token" else decode(request[field])
                allocation,buffer=backing(data);allocations.append(allocation)
                array[i]=IOV(kind,buffer)
            conf=C.c_int();qop=U32()
            if op=="wrap":
                status(wrap_length(C.byref(minor),context,1,0,C.byref(conf),array,4),minor.value)
                if array[3].buffer.length>65535:raise ValueError("fixture header bound")
                allocation=C.create_string_buffer(array[3].buffer.length)
                allocations.append(allocation)
                array[3].buffer.value=C.cast(allocation,Ptr)
                major=wrap(C.byref(minor),context,1,0,C.byref(conf),array,4)
            else:
                major=unwrap(C.byref(minor),context,C.byref(conf),C.byref(qop),array,4)
            status(major,minor.value)
            result=dict(major=int(major),confidential=bool(conf.value),body=encode(C.string_at(array[1].buffer.value,array[1].buffer.length)),
                        token=encode(C.string_at(array[3].buffer.value,array[3].buffer.length)))
        elif op=="close":break
        else:raise ValueError("unknown fixture operation")
        sys.stdout.write(json.dumps(result)+"\n");sys.stdout.flush()
except Exception as failure:
    if isinstance(failure,RuntimeError):sys.stderr.write(str(failure)+"\n")
    else:sys.stderr.write(json.dumps(dict(error="mit_fixture_failure",class_name=type(failure).__name__))+"\n")
    sys.exit(1)
finally:
    if context:delete_context(C.byref(minor),C.byref(context),None)
    if credential:release_cred(C.byref(minor),C.byref(credential))
    if name:release_name(C.byref(minor),C.byref(name))
