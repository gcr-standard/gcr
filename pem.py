"""Write an RSA private key in the ordinary PKCS#1 PEM form every tool reads."""
import base64

from keygen import RsaKey

PEM_LINE = 64


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_integer(value: int) -> bytes:
    body = value.to_bytes(value.bit_length() // 8 + 1, "big")  # leading 0 keeps it positive
    return b"\x02" + _der_length(len(body)) + body


def private_key_der(key: RsaKey) -> bytes:
    fields = [
        0,
        key.n,
        key.e,
        key.d,
        key.p,
        key.q,
        key.d % (key.p - 1),
        key.d % (key.q - 1),
        pow(key.q, -1, key.p),
    ]
    body = b"".join(_der_integer(f) for f in fields)
    return b"\x30" + _der_length(len(body)) + body


def private_key_pem(key: RsaKey) -> str:
    b64 = base64.b64encode(private_key_der(key)).decode("ascii")
    lines = [b64[i : i + PEM_LINE] for i in range(0, len(b64), PEM_LINE)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----\n"
