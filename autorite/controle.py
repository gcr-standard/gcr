#!/usr/bin/env python3
"""controle — les douze contrôles de GCR-0002 section 11 sur une chaîne de certificats.

  python3 controle.py --racine ac/racine --delivrante ac/delivrante --final ac/final-serveur.exemple.test

Chaque dossier contient `certificat.pem` ; ceux de la racine et de la délivrante contiennent
aussi `fiche.json` (GCR-0001). Le contrôleur ne lit ni clé privée ni graine.
"""
import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

import profils

PUBLIC_EXPONENT = 65537


@dataclass(frozen=True)
class Chain:
    root: x509.Certificate
    issuer: x509.Certificate
    leaf: x509.Certificate
    root_fiche: dict | None
    issuer_fiche: dict | None

    @property
    def all(self) -> list[tuple[str, x509.Certificate]]:
        return [("racine", self.root), ("délivrante", self.issuer), ("final", self.leaf)]


def _extension(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None


def _signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(parent)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _authority_usage_only(cert: x509.Certificate) -> bool:
    usage = _extension(cert, ExtensionOID.KEY_USAGE)
    if usage is None or not usage.critical:
        return False
    v = usage.value
    others = [v.digital_signature, v.content_commitment, v.key_encipherment, v.data_encipherment, v.key_agreement]
    return v.key_cert_sign and v.crl_sign and not any(others)


def _named(cert: x509.Certificate) -> bool:
    """An authority's name carries country, organisation and common name (7.4)."""
    required = (NameOID.COUNTRY_NAME, NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME)
    return all(cert.subject.get_attributes_for_oid(oid) for oid in required)


def _basic(cert: x509.Certificate):
    ext = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
    return (ext.critical, ext.value.ca, ext.value.path_length) if ext else (False, None, None)


def _days(cert: x509.Certificate) -> float:
    return (cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds() / 86400


def _within(child: x509.Certificate, parent: x509.Certificate) -> bool:
    return parent.not_valid_before_utc <= child.not_valid_before_utc and child.not_valid_after_utc <= parent.not_valid_after_utc


def _key_id(cert: x509.Certificate, oid) -> bytes | None:
    ext = _extension(cert, oid)
    if ext is None:
        return None
    return ext.value.digest if oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER else ext.value.key_identifier


def _fiche_matches(cert: x509.Certificate, fiche: dict | None) -> bool:
    key = cert.public_key()
    if fiche is None or not isinstance(key, rsa.RSAPublicKey):
        return False
    n = key.public_numbers().n
    fingerprint = hashlib.sha256(n.to_bytes((n.bit_length() + 7) // 8, "big")).hexdigest()
    return fiche.get("n_hex") == format(n, "x") and fiche.get("empreinte_sha256_de_n") == fingerprint


def k1(c: Chain) -> bool:
    return all(cert.version == x509.Version.v3 for _, cert in c.all)


def k2(c: Chain) -> bool:
    return c.root.subject == c.root.issuer and _signed_by(c.root, c.root)


def k3(c: Chain) -> bool:
    critical, is_ca, _ = _basic(c.root)
    return critical and is_ca is True and _authority_usage_only(c.root) and _named(c.root)


def k4(c: Chain) -> bool:
    critical, is_ca, path_length = _basic(c.issuer)
    return (
        _signed_by(c.issuer, c.root)
        and critical
        and is_ca is True
        and path_length == 0
        and _authority_usage_only(c.issuer)
        and _named(c.issuer)
    )


def k5(c: Chain) -> bool:
    critical, is_ca, _ = _basic(c.leaf)
    usage = _extension(c.leaf, ExtensionOID.KEY_USAGE)
    return (
        _signed_by(c.leaf, c.issuer)
        and not _signed_by(c.leaf, c.root)
        and critical
        and is_ca is False
        and usage is not None
        and usage.critical
        and not usage.value.key_cert_sign
        and _extension(c.leaf, ExtensionOID.SUBJECT_ALTERNATIVE_NAME) is not None
        and _extension(c.leaf, ExtensionOID.EXTENDED_KEY_USAGE) is not None
    )


def k6(c: Chain) -> bool:
    minimums = [(c.root, profils.ROOT_BITS), (c.issuer, profils.ISSUER_MIN_BITS), (c.leaf, profils.LEAF_MIN_BITS)]
    for cert, minimum in minimums:
        key = cert.public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            return False
        if key.key_size < minimum or key.public_numbers().e != PUBLIC_EXPONENT:
            return False
    return True


def k7(c: Chain) -> bool:
    return all(
        cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.name in profils.ALLOWED_HASHES
        for _, cert in c.all
    )


def k8(c: Chain) -> bool:
    ceilings = [(c.root, profils.ROOT_MAX_DAYS), (c.issuer, profils.ISSUER_MAX_DAYS), (c.leaf, profils.LEAF_MAX_DAYS)]
    return all(0 < _days(cert) <= ceiling for cert, ceiling in ceilings) and _within(c.issuer, c.root) and _within(c.leaf, c.issuer)


def k9(c: Chain) -> bool:
    def length(cert: x509.Certificate) -> int:
        return (cert.serial_number.bit_length() + 7) // 8

    return all(cert.serial_number > 0 and profils.SERIAL_MIN_BYTES <= length(cert) <= profils.SERIAL_MAX_BYTES for _, cert in c.all)


def k10(c: Chain) -> bool:
    return all(_extension(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS) is not None for cert in (c.issuer, c.leaf))


def k11(c: Chain) -> bool:
    ski, aki = ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER
    root_id, issuer_id = _key_id(c.root, ski), _key_id(c.issuer, ski)
    return (
        root_id is not None
        and issuer_id is not None
        and _key_id(c.leaf, ski) is not None
        and _key_id(c.issuer, aki) == root_id
        and _key_id(c.leaf, aki) == issuer_id
    )


def k12(c: Chain) -> bool:
    return _fiche_matches(c.root, c.root_fiche) and _fiche_matches(c.issuer, c.issuer_fiche)


CONTROLS = [
    ("K1", "certificats X.509 version 3", k1),
    ("K2", "racine signée par elle-même", k2),
    ("K3", "racine : autorité, usage limité à la signature de certificats et de listes", k3),
    ("K4", "délivrante : signée par la racine, autorité sans sous-autorité", k4),
    ("K5", "final : signé par la délivrante, non autorité, noms et usages présents", k5),
    ("K6", "clés RSA, exposant 65537, tailles minimales", k6),
    ("K7", "signatures en SHA-256, SHA-384 ou SHA-512", k7),
    ("K8", "durées plafonnées et contenues dans celle de l'émetteur", k8),
    ("K9", "numéros de série positifs, de 8 à 20 octets", k9),
    ("K10", "adresse de liste de révocation dans la délivrante et le final", k10),
    ("K11", "identifiants de clé présents et chaînés", k11),
    ("K12", "fiches GCR-0001 de la racine et de la délivrante accordées aux certificats", k12),
]


def failures(chain: Chain) -> list[tuple[str, str]]:
    """Every control that fails, in order. An empty list means conforming."""
    return [(code, label) for code, label, check in CONTROLS if not check(chain)]


def _load_fiche(directory: Path) -> dict | None:
    path = directory / "fiche.json"
    if not path.exists():
        return None
    try:
        fiche = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    return fiche if isinstance(fiche, dict) else None


def load_chain(root: Path, issuer: Path, leaf: Path) -> Chain:
    def certificate(directory: Path) -> x509.Certificate:
        return x509.load_pem_x509_certificate((directory / "certificat.pem").read_bytes())

    return Chain(certificate(root), certificate(issuer), certificate(leaf), _load_fiche(root), _load_fiche(issuer))


def main() -> int:
    parser = argparse.ArgumentParser(description="Contrôles GCR-0002")
    for name in ("racine", "delivrante", "final"):
        parser.add_argument(f"--{name}", required=True, help="dossier contenant certificat.pem")
    args = parser.parse_args()
    try:
        chain = load_chain(Path(args.racine), Path(args.delivrante), Path(args.final))
    except (OSError, ValueError) as error:
        print(f"NON CONFORME : certificat illisible ({error})")
        return 1
    failed = failures(chain)
    if not failed:
        print("CONFORME : les douze contrôles passent")
        return 0
    for code, label in failed:
        print(f"NON CONFORME : {code} — {label}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
