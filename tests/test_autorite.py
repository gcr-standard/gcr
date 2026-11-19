"""The authority of GCR-0002: a conforming chain passes, each faulty chain is caught."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

AUTHORITY = Path(__file__).resolve().parent.parent / "autorite"
sys.path.insert(0, str(AUTHORITY))

import autorite  # noqa: E402
import controle  # noqa: E402
import profils  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl absent")

ROOT_CRL = "http://exemple.test/racine.crl"
ISSUER_CRL = "http://exemple.test/delivrante.crl"
HOST = "serveur.exemple.test"
LEAF_SUBJECT = "/C=CI/O=Client/CN=serveur.exemple.test"


def tool(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(AUTHORITY / script), *args], capture_output=True, text=True)


@pytest.fixture(scope="module")
def ac(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("ac")
    common = ["--pays", "CI", "--organisation", "Exemple", "--sortie", str(base)]
    steps = [
        ("racine", "--nom", "Racine Exemple", *common),
        ("delivrante", "--nom", "Délivrante Exemple 1", "--liste", ROOT_CRL, *common),
        ("certificat", "--nom", HOST, "--dns", HOST, "--liste", ISSUER_CRL, *common),
    ]
    for step in steps:
        result = tool("autorite.py", *step)
        assert result.returncode == 0, result.stderr
    return base


def failed_codes(root: Path, issuer: Path, leaf: Path) -> list[str]:
    return [code for code, _ in controle.failures(controle.load_chain(root, issuer, leaf))]


def variant(tmp_path: Path, source: Path, name: str) -> Path:
    """A copy of a certificate directory, to be re-signed wrongly."""
    target = tmp_path / name
    shutil.copytree(source, target)
    (target / "certificat.pem").unlink()
    return target


def test_conforming_chain_passes_the_twelve_controls(ac):
    result = tool("controle.py", "--racine", str(ac / "racine"), "--delivrante", str(ac / "delivrante"),
                  "--final", str(ac / f"final-{HOST}"))

    assert result.returncode == 0, result.stdout
    assert "CONFORME : les douze contrôles passent" in result.stdout


def test_openssl_verifies_the_chain(ac):
    result = subprocess.run(
        ["openssl", "verify", "-x509_strict", "-CAfile", str(ac / "racine/certificat.pem"),
         "-untrusted", str(ac / "delivrante/certificat.pem"), str(ac / f"final-{HOST}/certificat.pem")],
        capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr


def test_controller_reads_neither_key_nor_seed(ac, tmp_path):
    public = {}
    for name in ("racine", "delivrante", f"final-{HOST}"):
        public[name] = tmp_path / name
        public[name].mkdir()
        for file in ("certificat.pem", "fiche.json"):
            shutil.copy(ac / name / file, public[name] / file)

    assert failed_codes(public["racine"], public["delivrante"], public[f"final-{HOST}"]) == []


def test_leaf_signed_directly_by_the_root_is_caught(ac, tmp_path):
    leaf = variant(tmp_path, ac / f"final-{HOST}", "final")
    autorite.sign(leaf, ac / "racine", LEAF_SUBJECT, profils.leaf_extensions(ISSUER_CRL, [HOST]), 365)

    assert "K5" in failed_codes(ac / "racine", ac / "delivrante", leaf)


def test_leaf_without_alternative_name_is_caught(ac, tmp_path):
    leaf = variant(tmp_path, ac / f"final-{HOST}", "final")
    extensions = "\n".join(l for l in profils.leaf_extensions(ISSUER_CRL, [HOST]).splitlines() if "subjectAltName" not in l)
    autorite.sign(leaf, ac / "delivrante", LEAF_SUBJECT, extensions, 365)

    assert failed_codes(ac / "racine", ac / "delivrante", leaf) == ["K5"]


def test_leaf_that_is_an_authority_is_caught(ac, tmp_path):
    leaf = variant(tmp_path, ac / f"final-{HOST}", "final")
    extensions = profils.leaf_extensions(ISSUER_CRL, [HOST]).replace("CA:FALSE", "CA:TRUE")
    autorite.sign(leaf, ac / "delivrante", LEAF_SUBJECT, extensions, 365)

    assert "K5" in failed_codes(ac / "racine", ac / "delivrante", leaf)


def test_leaf_valid_too_long_is_caught(ac, tmp_path):
    leaf = variant(tmp_path, ac / f"final-{HOST}", "final")
    autorite.sign(leaf, ac / "delivrante", LEAF_SUBJECT, profils.leaf_extensions(ISSUER_CRL, [HOST]), 900)

    assert failed_codes(ac / "racine", ac / "delivrante", leaf) == ["K8"]


def test_leaf_without_revocation_address_is_caught(ac, tmp_path):
    leaf = variant(tmp_path, ac / f"final-{HOST}", "final")
    extensions = "\n".join(l for l in profils.leaf_extensions(ISSUER_CRL, [HOST]).splitlines() if "crlDistributionPoints" not in l)
    autorite.sign(leaf, ac / "delivrante", LEAF_SUBJECT, extensions, 365)

    assert failed_codes(ac / "racine", ac / "delivrante", leaf) == ["K10"]


def test_issuer_with_a_small_key_is_caught(ac, tmp_path):
    issuer = tmp_path / "delivrante"
    autorite.generate_key(issuer, 2048)
    autorite.sign(issuer, ac / "racine", "/C=CI/O=Exemple/CN=Petite", profils.issuer_extensions(ROOT_CRL), 2190)

    assert "K6" in failed_codes(ac / "racine", issuer, ac / f"final-{HOST}")


def test_issuer_allowed_to_create_sub_authorities_is_caught(ac, tmp_path):
    issuer = variant(tmp_path, ac / "delivrante", "delivrante")
    extensions = profils.issuer_extensions(ROOT_CRL).replace(",pathlen:0", "")
    autorite.sign(issuer, ac / "racine", "/C=CI/O=Exemple/CN=Délivrante Exemple 1", extensions, 2190)

    assert "K4" in failed_codes(ac / "racine", issuer, ac / f"final-{HOST}")


def test_issuer_without_country_or_organisation_is_caught(ac, tmp_path):
    issuer = variant(tmp_path, ac / "delivrante", "delivrante")
    autorite.sign(issuer, ac / "racine", "/CN=Sans pays", profils.issuer_extensions(ROOT_CRL), 2190)

    assert "K4" in failed_codes(ac / "racine", issuer, ac / f"final-{HOST}")


def test_fiche_of_another_key_is_caught(ac, tmp_path):
    root = tmp_path / "racine"
    shutil.copytree(ac / "racine", root)
    shutil.copy(ac / "delivrante/fiche.json", root / "fiche.json")

    assert failed_codes(root, ac / "delivrante", ac / f"final-{HOST}") == ["K12"]


def test_missing_fiche_is_caught(ac, tmp_path):
    root = tmp_path / "racine"
    shutil.copytree(ac / "racine", root)
    (root / "fiche.json").unlink()

    assert failed_codes(root, ac / "delivrante", ac / f"final-{HOST}") == ["K12"]


def test_authority_keys_come_from_the_generator(ac):
    for name, bits in (("racine", 4096), ("delivrante", 3072)):
        fiche = json.loads((ac / name / "fiche.json").read_text())
        check = subprocess.run(
            [sys.executable, str(AUTHORITY.parent / "rsagraine.py"), "verifier",
             "--graine", str(ac / name / "graine.hex"), "--fiche", str(ac / name / "fiche.json")],
            capture_output=True, text=True,
        )

        assert fiche["bits"] == bits
        assert check.returncode == 0, check.stdout


@pytest.mark.parametrize(
    "args,reason",
    [
        (["--pays", "Côte", "--organisation", "X", "--nom", "Racine"], "pays refusé"),
        (["--pays", "CI", "--organisation", "X/CN=Autre", "--nom", "Racine"], "organisation refusé"),
    ],
)
def test_bad_names_are_refused_before_any_key_is_made(tmp_path, args, reason):
    result = tool("autorite.py", "racine", *args, "--sortie", str(tmp_path))

    assert result.returncode == 2
    assert reason in result.stderr


def test_certificate_refuses_a_bad_dns_name(ac, tmp_path):
    result = tool("autorite.py", "certificat", "--pays", "CI", "--organisation", "Client", "--nom", HOST,
                  "--dns", "pas un nom", "--liste", ISSUER_CRL, "--sortie", str(tmp_path))

    assert result.returncode == 2
    assert "nom DNS refusé" in result.stderr


def test_serials_are_long_positive_and_distinct():
    serials = {int(autorite.new_serial(), 16) for _ in range(200)}

    assert len(serials) == 200
    assert all(s > 0 and 15 <= (s.bit_length() + 7) // 8 <= 16 for s in serials)
