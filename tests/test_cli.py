"""The command-line tool, and the keys as OpenSSL sees them."""
import json
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOL = [sys.executable, str(ROOT / "rsagraine.py")]
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl absent")


def run(*args):
    return subprocess.run([*TOOL, *args], capture_output=True, text=True)


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    out = tmp_path_factory.mktemp("cles")
    result = run("generer", "--bits", "2048", "--sortie", str(out))
    assert result.returncode == 0, result.stderr
    return out


def test_generer_writes_three_files_and_keeps_secrets_private(keys):
    assert {p.name for p in keys.iterdir()} == {"cle.pem", "graine.hex", "fiche.json"}
    for name in ("cle.pem", "graine.hex"):
        assert stat.S_IMODE((keys / name).stat().st_mode) == 0o600


def test_fiche_holds_no_secret(keys):
    fiche = (keys / "fiche.json").read_text()
    seed = (keys / "graine.hex").read_text().strip()

    assert seed not in fiche
    assert set(json.loads(fiche)) == {"norme", "bits", "e", "hash", "graine_octets", "n_hex", "empreinte_sha256_de_n"}


def test_generer_prints_no_secret(tmp_path):
    result = run("generer", "--bits", "2048", "--sortie", str(tmp_path))

    assert (tmp_path / "graine.hex").read_text().strip() not in result.stdout + result.stderr
    assert "PRIVATE" not in result.stdout


def test_verifier_accepts_the_right_seed(keys):
    result = run("verifier", "--graine", str(keys / "graine.hex"), "--fiche", str(keys / "fiche.json"))

    assert result.returncode == 0
    assert "CONFORME" in result.stdout


def test_verifier_rejects_another_seed(keys, tmp_path):
    wrong = tmp_path / "graine.hex"
    wrong.write_text("ab" * 32)

    result = run("verifier", "--graine", str(wrong), "--fiche", str(keys / "fiche.json"))

    assert result.returncode == 1
    assert "NON CONFORME" in result.stdout


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("norme", "AUTRE/9", "version de la norme"),
        ("hash", "md5", "paramètres non admis"),
        ("e", 3, "paramètres non admis"),
        ("graine_octets", 31, "longueur déclarée"),
        ("empreinte_sha256_de_n", "00" * 32, "empreinte"),
        ("bits", 3072, "ne redonne pas"),
    ],
)
def test_verifier_rejects_a_tampered_fiche(keys, tmp_path, field, value, reason):
    fiche = {**json.loads((keys / "fiche.json").read_text()), field: value}
    tampered = tmp_path / "fiche.json"
    tampered.write_text(json.dumps(fiche))

    result = run("verifier", "--graine", str(keys / "graine.hex"), "--fiche", str(tampered))

    assert result.returncode == 1
    assert reason in result.stdout


def test_verifier_rejects_a_fiche_with_an_extra_field(keys, tmp_path):
    fiche = {**json.loads((keys / "fiche.json").read_text()), "graine": "ab"}
    tampered = tmp_path / "fiche.json"
    tampered.write_text(json.dumps(fiche))

    result = run("verifier", "--graine", str(keys / "graine.hex"), "--fiche", str(tampered))

    assert result.returncode == 1
    assert "champs de la norme" in result.stdout


def test_generer_from_a_given_seed_rebuilds_the_same_key(keys, tmp_path):
    result = run("generer", "--bits", "2048", "--graine", str(keys / "graine.hex"), "--sortie", str(tmp_path))

    assert result.returncode == 0
    assert (tmp_path / "cle.pem").read_text() == (keys / "cle.pem").read_text()


def test_generer_refuses_a_seed_that_is_not_32_bytes(tmp_path):
    seed = tmp_path / "graine.hex"
    seed.write_text("ab" * 40)

    result = run("generer", "--bits", "2048", "--graine", str(seed), "--sortie", str(tmp_path / "out"))

    assert result.returncode == 2
    assert "32 octets" in result.stderr


def test_generer_refuses_to_overwrite_a_key(keys):
    result = run("generer", "--bits", "2048", "--sortie", str(keys))

    assert result.returncode == 2
    assert "échec" in result.stderr


@needs_openssl
def test_openssl_finds_the_key_sound(keys):
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(keys / "cle.pem"), "-check", "-noout"], capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr
    assert "RSA key ok" in result.stdout + result.stderr


@needs_openssl
def test_openssl_signs_and_verifies_with_the_key(keys, tmp_path):
    message, signature, public = tmp_path / "m.txt", tmp_path / "m.sig", tmp_path / "pub.pem"
    message.write_text("norme")
    pem = str(keys / "cle.pem")
    steps = [
        ["openssl", "pkey", "-in", pem, "-pubout", "-out", str(public)],
        ["openssl", "dgst", "-sha384", "-sign", pem, "-sigopt", "rsa_padding_mode:pss", "-out", str(signature), str(message)],
        ["openssl", "dgst", "-sha384", "-verify", str(public), "-sigopt", "rsa_padding_mode:pss", "-signature", str(signature), str(message)],
    ]

    for step in steps:
        result = subprocess.run(step, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    assert "Verified OK" in result.stdout


@needs_openssl
def test_openssl_reads_the_same_modulus_as_the_fiche(keys):
    result = subprocess.run(
        ["openssl", "rsa", "-in", str(keys / "cle.pem"), "-modulus", "-noout"], capture_output=True, text=True
    )

    assert result.stdout.strip().split("=")[1].lower().lstrip("0") == json.loads((keys / "fiche.json").read_text())["n_hex"]


@needs_openssl
def test_openssl_makes_an_ordinary_certificate_chain_from_generated_keys(keys, tmp_path):
    """A root authority signs a server certificate; OpenSSL verifies the chain."""
    leaf_dir = tmp_path / "leaf"
    assert run("generer", "--bits", "2048", "--sortie", str(leaf_dir)).returncode == 0
    root_key, leaf_key = str(keys / "cle.pem"), str(leaf_dir / "cle.pem")
    root_crt, leaf_csr, leaf_crt = (str(tmp_path / n) for n in ("racine.crt", "serveur.csr", "serveur.crt"))
    steps = [
        ["openssl", "req", "-x509", "-new", "-key", root_key, "-sha384", "-days", "30", "-subj", "/CN=Racine d epreuve",
         "-addext", "basicConstraints=critical,CA:TRUE", "-out", root_crt],
        ["openssl", "req", "-new", "-key", leaf_key, "-subj", "/CN=serveur.epreuve", "-out", leaf_csr],
        ["openssl", "x509", "-req", "-in", leaf_csr, "-CA", root_crt, "-CAkey", root_key, "-CAcreateserial",
         "-sha384", "-days", "10", "-out", leaf_crt],
        ["openssl", "verify", "-CAfile", root_crt, leaf_crt],
    ]

    for step in steps:
        result = subprocess.run(step, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("OK")
