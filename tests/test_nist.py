"""Official NIST vectors (ACVP, RSA key generation, FIPS 186-4, method B.3.2).

A vector gives a seed and e, and the p and q the standard must produce.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from keygen import generate  # noqa: E402

VECTORS = ROOT / "vecteurs-nist" / "internalProjection.json"
HASHES = {"SHA2-224": "sha224", "SHA2-256": "sha256", "SHA2-384": "sha384", "SHA2-512": "sha512"}


def _cases():
    if not VECTORS.exists():
        return []
    data = json.loads(VECTORS.read_text())
    return [
        (group, test)
        for group in data["testGroups"]
        if group["randPQ"] == "B.3.2"
        for test in group["tests"]
    ]


@pytest.mark.skipif(not VECTORS.exists(), reason="NIST vectors not downloaded")
@pytest.mark.parametrize("group,test", _cases(), ids=lambda v: str(v.get("tcId", v.get("tgId"))))
def test_seed_gives_the_primes_nist_expects(group, test):
    key = generate(
        group["modulo"],
        bytes.fromhex(test["seed"]),
        int(test["e"], 16),
        HASHES[group["hashAlg"]],
    )

    assert key.p == int(test["p"], 16)
    assert key.q == int(test["q"], 16)
    assert key.n == int(test["n"], 16)
    assert key.d % (key.p - 1) == int(test["dmp1"], 16)
    assert key.d % (key.q - 1) == int(test["dmq1"], 16)
    assert pow(key.q, -1, key.p) == int(test["iqmp"], 16)
