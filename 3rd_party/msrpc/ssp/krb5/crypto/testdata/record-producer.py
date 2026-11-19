"""Synthetic RFC3961/3962 + MS-KILE WrapEx records using a separate AES provider.

This producer imports no Go SDK/candidate/Impacket implementation and contacts no
network. It is a cross-implementation primitive check, not KDC/AD interoperability.
"""
import hashlib
import hmac
import importlib.metadata
import json
import math
from pathlib import Path
from Cryptodome.Cipher import AES


def nfold(data, width):
    bits = len(data) * 8
    value = int.from_bytes(data, "big")
    mask = (1 << bits) - 1
    expanded = b""
    for i in range(math.lcm(len(data), width) // len(data)):
        shift = (13 * i) % bits
        rotated = ((value >> shift) | (value << (bits - shift))) & mask
        expanded += rotated.to_bytes(len(data), "big")
    total = sum(int.from_bytes(expanded[i:i + width], "big") for i in range(0, len(expanded), width))
    limit = (1 << (width * 8)) - 1
    while total > limit:
        total = (total & limit) + (total >> (width * 8))
    return total.to_bytes(width, "big")


def derive(key, usage, marker):
    value = nfold(usage.to_bytes(4, "big") + bytes([marker]), 16)
    out = b""
    cipher = AES.new(key, AES.MODE_ECB)
    while len(out) < len(key):
        value = cipher.encrypt(value)
        out += value
    return out[:len(key)]


def cts_encrypt(key, data):
    missing = (-len(data)) % 16
    padded = data + b"\0" * missing
    result = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(padded)
    if len(data) <= 16:
        return result
    tail_size = 16 - missing
    return result[:-32] + result[-16:] + result[-32:-16][:tail_size]


def cts_decrypt(key, data):
    if len(data) == 16:
        return AES.new(key, AES.MODE_ECB).decrypt(data)
    tail_size = (len(data) - 1) % 16 + 1
    prefix = data[:len(data) - 16 - tail_size]
    last_full = data[len(prefix):len(prefix) + 16]
    last_short = data[len(prefix) + 16:]
    dec = AES.new(key, AES.MODE_ECB).decrypt(last_full)
    stolen = last_short + dec[tail_size:]
    cbc = AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(prefix + stolen)
    tail = bytes(a ^ b for a, b in zip(dec[:tail_size], stolen))
    return cbc + tail


assert nfold(b"012345", 8).hex() == "be072631276b1955"
assert nfold(b"password", 7).hex() == "78a07b6caf85fa"
assert nfold(b"Rough Consensus, and Running Code", 8).hex() == "bb6ed30870b7f0e0"

# Published RFC3962 Appendix B controls anchor this separate CTS implementation.
for plain, ciphertext in [
    ("4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362da7ff7f97"),
    ("4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"),
]:
    key = b"chicken teriyaki"
    assert cts_encrypt(key, bytes.fromhex(plain)).hex() == ciphertext
    assert cts_decrypt(key, bytes.fromhex(ciphertext)).hex() == plain

cases = []
for etype, key_size in [(17, 16), (18, 32)]:
    for acceptor in [False, True]:
        key = bytes(range(key_size))
        seq = 0x0102030405060708
        flags = 4 | int(acceptor)
        header = bytes([5, 4, flags | 2, 255]) + (16).to_bytes(2, "big") + bytes(2) + seq.to_bytes(8, "big")
        signed_header = bytes.fromhex("050002031000000078005000010000002800000000000000")
        payload = b"synthetic RPC diagnostic reply, no directory data"
        trailer = bytes.fromhex("1006000001000000")
        confounder = bytes(range(0xa0, 0xb0))
        pad = bytes([255]) * 16
        usage = 22 if acceptor else 24
        checksum = hmac.new(derive(key, usage, 0x55), confounder + signed_header + payload + trailer + pad + header, hashlib.sha1).digest()[:12]
        plain = confounder + payload + pad + header
        encrypted = cts_encrypt(derive(key, usage, 0xaa), plain)
        assert cts_decrypt(derive(key, usage, 0xaa), encrypted) == plain
        combined = encrypted + checksum
        rotated = combined[-44:] + combined[:-44]
        outer = header[:6] + (28).to_bytes(2, "big") + header[8:]
        signature = outer + rotated[:60]
        mic_header = bytes([4, 4, flags]) + bytes([255]) * 5 + seq.to_bytes(8, "big")
        mic_usage = 23 if acceptor else 25
        mic = mic_header + hmac.new(derive(key, mic_usage, 0x99), signed_header + payload + trailer + mic_header, hashlib.sha1).digest()[:12]
        cases.append(dict(etype=etype, acceptor=acceptor, sequence=seq, key=key.hex(), header=signed_header.hex(),
                          plain=payload.hex(), trailer=trailer.hex(), signature=signature.hex(), ciphertext=rotated[60:].hex(), mic=mic.hex()))

output = dict(purpose="synthetic independent Python primitive records; no KDC or AD claim", provider="PyCryptodomex", version=importlib.metadata.version("pycryptodomex"),
              sources=["https://www.rfc-editor.org/rfc/rfc3961.html", "https://www.rfc-editor.org/rfc/rfc3962.html",
                       "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550"], cases=cases)
target = Path(__file__).parent / "rpc-qualification/3rd_party/msrpc/ssp/krb5/crypto/testdata/rpc-python-records.json"
target.parent.mkdir(exist_ok=True)
encoded = (json.dumps(output, indent=2) + "\n").encode()
if target.exists():
    assert target.read_bytes() == encoded, "existing independent fixture differs; no overwrite"
else:
    with target.open("xb") as stream:
        stream.write(encoded)
print(json.dumps(dict(cases=len(cases), provider=output["provider"], version=output["version"], sha256=hashlib.sha256(target.read_bytes()).hexdigest())))
