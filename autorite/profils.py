"""The certificate profiles of GCR-0002 section 7: sizes, lifetimes, extensions."""
from dataclasses import dataclass

ROOT_BITS = 4096
ISSUER_MIN_BITS = 3072
LEAF_MIN_BITS = 2048

# Ceilings checked by the controller (years counted with their leap days).
ROOT_MAX_DAYS = 5479  # 15 years
ISSUER_MAX_DAYS = 2192  # 6 years
LEAF_MAX_DAYS = 731  # 2 years

SERIAL_MIN_BYTES = 8
SERIAL_MAX_BYTES = 20
SIGNATURE_HASH = "sha384"
ALLOWED_HASHES = {"sha256", "sha384", "sha512"}


@dataclass(frozen=True)
class Profile:
    bits: int
    days: int


ROOT = Profile(bits=ROOT_BITS, days=5475)
ISSUER = Profile(bits=ISSUER_MIN_BITS, days=2190)
LEAF = Profile(bits=LEAF_MIN_BITS, days=365)


def root_extensions() -> str:
    return "\n".join(
        [
            "basicConstraints=critical,CA:TRUE",
            "keyUsage=critical,keyCertSign,cRLSign",
            "subjectKeyIdentifier=hash",
        ]
    )


def issuer_extensions(crl_url: str) -> str:
    return "\n".join(
        [
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "keyUsage=critical,keyCertSign,cRLSign",
            "subjectKeyIdentifier=hash",
            "authorityKeyIdentifier=keyid:always",
            f"crlDistributionPoints=URI:{crl_url}",
        ]
    )


def leaf_extensions(crl_url: str, dns_names: list[str]) -> str:
    names = ",".join(f"DNS:{name}" for name in dns_names)
    return "\n".join(
        [
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "extendedKeyUsage=serverAuth,clientAuth",
            f"subjectAltName={names}",
            "subjectKeyIdentifier=hash",
            "authorityKeyIdentifier=keyid:always",
            f"crlDistributionPoints=URI:{crl_url}",
        ]
    )
