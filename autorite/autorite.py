#!/usr/bin/env python3
"""autorite — une autorité de certification selon GCR-0002.

  python3 autorite.py racine     --pays CI --organisation "Exemple" --nom "Racine Exemple" --sortie ac/
  python3 autorite.py delivrante --pays CI --organisation "Exemple" --nom "Délivrante Exemple 1" \\
                                 --liste http://exemple.test/racine.crl --sortie ac/
  python3 autorite.py certificat --pays CI --organisation "Client" --nom serveur.exemple.test \\
                                 --dns serveur.exemple.test --liste http://exemple.test/d1.crl --sortie ac/

Chaque clé sort du générateur GCR-0001. Les certificats sont écrits par OpenSSL.
La racine ne signe que la délivrante ; la délivrante signe les certificats finaux.
"""
import argparse
import re
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

import profils

GENERATOR = Path(__file__).resolve().parent.parent / "rsagraine.py"
NAME_PATTERN = re.compile(r"^[\w .\-']{1,64}$")
COUNTRY_PATTERN = re.compile(r"^[A-Z]{2}$")
DNS_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
URL_PATTERN = re.compile(r"^https?://[\w.\-/:]+$")
SERIAL_BYTES = 16


class AuthorityError(Exception):
    """A step of the authority could not be completed."""


def _check(pattern: re.Pattern, value: str, what: str) -> str:
    if not pattern.match(value):
        raise AuthorityError(f"{what} refusé : {value!r}")
    return value


def subject(country: str, organisation: str, name: str) -> str:
    _check(COUNTRY_PATTERN, country, "pays")
    _check(NAME_PATTERN, organisation, "organisation")
    _check(NAME_PATTERN, name, "nom")
    return f"/C={country}/O={organisation}/CN={name}"


def new_serial() -> str:
    """A positive serial with at least 120 random bits."""
    value = secrets.randbits(8 * SERIAL_BYTES - 1) | (1 << (8 * SERIAL_BYTES - 8))
    return hex(value)


def _run(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise AuthorityError(result.stderr.strip() or f"échec de {command[0]}")


def generate_key(directory: Path, bits: int) -> None:
    _run([sys.executable, str(GENERATOR), "generer", "--bits", str(bits), "--sortie", str(directory)])


def self_sign(directory: Path, subject_name: str, extensions: str, days: int) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "ext.cnf"
        config.write_text("[req]\ndistinguished_name=dn\n[dn]\n[ext]\n" + extensions + "\n")
        _run(
            ["openssl", "req", "-x509", "-new", "-key", str(directory / "cle.pem"), f"-{profils.SIGNATURE_HASH}",
             "-days", str(days), "-subj", subject_name, "-set_serial", new_serial(),
             "-config", str(config), "-extensions", "ext", "-out", str(directory / "certificat.pem")]
        )


def sign(child: Path, parent: Path, subject_name: str, extensions: str, days: int) -> None:
    """The parent signs the child's key. The parent's seed is never read."""
    with tempfile.TemporaryDirectory() as tmp:
        request, extfile = Path(tmp) / "demande.csr", Path(tmp) / "ext.cnf"
        extfile.write_text(extensions + "\n")
        _run(["openssl", "req", "-new", "-key", str(child / "cle.pem"), "-subj", subject_name, "-out", str(request)])
        _run(
            ["openssl", "x509", "-req", "-in", str(request), "-CA", str(parent / "certificat.pem"),
             "-CAkey", str(parent / "cle.pem"), "-set_serial", new_serial(), "-days", str(days),
             f"-{profils.SIGNATURE_HASH}", "-extfile", str(extfile), "-out", str(child / "certificat.pem")]
        )


def cmd_racine(args) -> int:
    directory = Path(args.sortie) / "racine"
    generate_key(directory, profils.ROOT.bits)
    self_sign(directory, subject(args.pays, args.organisation, args.nom), profils.root_extensions(), profils.ROOT.days)
    print(f"racine écrite dans {directory}/")
    return 0


def cmd_delivrante(args) -> int:
    base = Path(args.sortie)
    directory = base / "delivrante"
    _check(URL_PATTERN, args.liste, "adresse de la liste de révocation")
    generate_key(directory, profils.ISSUER.bits)
    sign(directory, base / "racine", subject(args.pays, args.organisation, args.nom),
         profils.issuer_extensions(args.liste), profils.ISSUER.days)
    print(f"autorité délivrante écrite dans {directory}/")
    return 0


def cmd_certificat(args) -> int:
    base = Path(args.sortie)
    directory = base / f"final-{_check(DNS_PATTERN, args.nom, 'nom')}"
    names = [_check(DNS_PATTERN, name, "nom DNS") for name in args.dns]
    _check(URL_PATTERN, args.liste, "adresse de la liste de révocation")
    if not 1 <= args.jours <= profils.LEAF_MAX_DAYS:
        raise AuthorityError(f"durée refusée : 1 à {profils.LEAF_MAX_DAYS} jours")
    generate_key(directory, args.bits)
    sign(directory, base / "delivrante", subject(args.pays, args.organisation, args.nom),
         profils.leaf_extensions(args.liste, names), args.jours)
    print(f"certificat écrit dans {directory}/")
    return 0


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pays", required=True, help="code du pays, deux lettres")
    parser.add_argument("--organisation", required=True)
    parser.add_argument("--nom", required=True)
    parser.add_argument("--sortie", required=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Autorité de certification GCR-0002")
    sub = parser.add_subparsers(dest="commande", required=True)
    racine = sub.add_parser("racine")
    _common(racine)
    racine.set_defaults(run=cmd_racine)
    delivrante = sub.add_parser("delivrante")
    _common(delivrante)
    delivrante.add_argument("--liste", required=True, help="adresse de la liste de révocation de la racine")
    delivrante.set_defaults(run=cmd_delivrante)
    certificat = sub.add_parser("certificat")
    _common(certificat)
    certificat.add_argument("--dns", required=True, nargs="+")
    certificat.add_argument("--liste", required=True, help="adresse de la liste de révocation de la délivrante")
    certificat.add_argument("--bits", type=int, default=profils.LEAF.bits, choices=[2048, 3072, 4096])
    certificat.add_argument("--jours", type=int, default=profils.LEAF.days)
    certificat.set_defaults(run=cmd_certificat)
    args = parser.parse_args()
    try:
        return args.run(args)
    except (AuthorityError, OSError) as error:
        print(f"échec : {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
