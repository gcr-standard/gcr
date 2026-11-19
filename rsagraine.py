#!/usr/bin/env python3
"""rsagraine — générateur de clés RSA à graine, rejouable.

  python3 rsagraine.py generer  --bits 3072 --sortie cles/
  python3 rsagraine.py verifier --graine cles/graine.hex --fiche cles/fiche.json

`generer` écrit trois fichiers : la clé privée (cle.pem), la graine (graine.hex),
la fiche publique (fiche.json). La graine VAUT la clé privée : qui la tient refait la clé.
`verifier` refait la clé à partir de la graine et dit si elle est bien celle de la fiche.
"""
import argparse
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from keygen import DEFAULT_E, MIN_SEED_BYTES, generate
from pem import private_key_pem
from primes import PrimeGenerationFailure

SEED_BYTES = 32
STANDARD = "GCR-0001/0.1"
FICHE_FIELDS = {"norme", "bits", "e", "hash", "graine_octets", "n_hex", "empreinte_sha256_de_n"}
MAX_SEED_ATTEMPTS = 8
PRIVATE_MODE = 0o600
HASH_CHOICES = ["sha256", "sha384", "sha512"]


def _fingerprint(n: int) -> str:
    return hashlib.sha256(n.to_bytes((n.bit_length() + 7) // 8, "big")).hexdigest()


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_MODE)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)


def _generate_with_fresh_seed(bits: int, hash_name: str):
    for _ in range(MAX_SEED_ATTEMPTS):
        seed = secrets.token_bytes(SEED_BYTES)
        try:
            return seed, generate(bits, seed, DEFAULT_E, hash_name)
        except PrimeGenerationFailure:
            continue
    raise PrimeGenerationFailure("aucune graine n'a donné de clé")


def cmd_generer(args) -> int:
    out = Path(args.sortie)
    out.mkdir(parents=True, exist_ok=True)
    if args.graine:
        seed = bytes.fromhex(Path(args.graine).read_text().strip())
        if len(seed) != SEED_BYTES:
            raise ValueError(f"la graine doit compter exactement {SEED_BYTES} octets")
        key = generate(args.bits, seed, DEFAULT_E, args.hash)
    else:
        seed, key = _generate_with_fresh_seed(args.bits, args.hash)
    fiche = {
        "norme": STANDARD,
        "bits": key.bits,
        "e": key.e,
        "hash": args.hash,
        "graine_octets": len(seed),
        "n_hex": format(key.n, "x"),
        "empreinte_sha256_de_n": _fingerprint(key.n),
    }
    _write_private(out / "cle.pem", private_key_pem(key))
    if not args.graine:
        _write_private(out / "graine.hex", seed.hex() + "\n")
    (out / "fiche.json").write_text(json.dumps(fiche, indent=2) + "\n")
    print(f"clé RSA de {key.bits} bits écrite dans {out}/")
    print(f"empreinte du module : {fiche['empreinte_sha256_de_n']}")
    return 0


def cmd_verifier(args) -> int:
    fiche = json.loads(Path(args.fiche).read_text())
    seed = bytes.fromhex(Path(args.graine).read_text().strip())
    reason = _nonconformity(fiche, seed)
    if reason is None:
        print("CONFORME : la graine redonne exactement la clé de la fiche")
        return 0
    print(f"NON CONFORME : {reason}")
    return 1


def _nonconformity(fiche: dict, seed: bytes) -> str | None:
    """The controls of GCR-0001 section 10, in order. None means conforming."""
    if set(fiche) != FICHE_FIELDS:
        return "la fiche n'a pas exactement les champs de la norme"
    if fiche["norme"] != STANDARD:
        return "la fiche ne se réclame pas de cette version de la norme"
    if fiche["hash"] not in HASH_CHOICES or fiche["e"] != DEFAULT_E:
        return "paramètres non admis"
    if len(seed) != SEED_BYTES or fiche["graine_octets"] != SEED_BYTES:
        return "la graine n'a pas la longueur déclarée"
    if _fingerprint(int(fiche["n_hex"], 16)) != fiche["empreinte_sha256_de_n"]:
        return "l'empreinte ne correspond pas au module"
    try:
        key = generate(fiche["bits"], seed, fiche["e"], fiche["hash"])
    except (ValueError, PrimeGenerationFailure) as error:
        return f"la graine ne donne pas de clé ({error})"
    if format(key.n, "x") != fiche["n_hex"]:
        return "la graine ne redonne pas la clé de la fiche"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Générateur de clés RSA à graine")
    sub = parser.add_subparsers(dest="commande", required=True)
    g = sub.add_parser("generer")
    g.add_argument("--bits", type=int, default=3072, choices=sorted(MIN_SEED_BYTES))
    g.add_argument("--hash", default="sha256", choices=HASH_CHOICES)
    g.add_argument("--graine", help="fichier de graine en hexadécimal (sinon tirée du système)")
    g.add_argument("--sortie", required=True)
    g.set_defaults(run=cmd_generer)
    v = sub.add_parser("verifier")
    v.add_argument("--graine", required=True)
    v.add_argument("--fiche", required=True)
    v.set_defaults(run=cmd_verifier)
    args = parser.parse_args()
    try:
        return args.run(args)
    except (ValueError, OSError, PrimeGenerationFailure) as error:
        print(f"échec : {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
