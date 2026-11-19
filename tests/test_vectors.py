"""The norm's own vectors (annex A.3), shared with the second implementation."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from keygen import generate

INDEPENDENT = Path(__file__).resolve().parent.parent / "independant"
CASES = json.loads((INDEPENDENT / "cas.json").read_text())["cas_norme"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['bits']}-{c['hash']}")
def test_reference_gives_the_published_modulus(case):
    key = generate(case["bits"], bytes.fromhex(case["graine_hex"]), case["e"], case["hash"])

    assert format(key.n, "x") == case["n_hex_attendu"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node absent")
def test_second_implementation_agrees_on_every_case():
    result = subprocess.run(["node", str(INDEPENDENT / "gcr.js")], capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    assert "DIVERGE" not in result.stdout
    assert result.stdout.count("CONCORDE") == 11
