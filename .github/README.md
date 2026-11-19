# GCR — RSA keys from a replayable seed, for African certificates

Two preliminary draft standards, and the code that proves them.

The aim: for African certification authorities to issue ordinary X.509 certificates, which serve every
purpose and are read by all software, but whose keys come from a generator mastered from end to end.
RSA does not change. One thing only is fixed: how the key is made.

**Author and maintainer:** Honoré DEMBELE

| Standard | Subject | Text | Archive (DOI) |
|---|---|---|---|
| GCR-0001 | RSA key generation from a replayable seed | [English](../normes/GCR-0001.en.md) · [français](../normes/GCR-0001.md) | [10.5281/zenodo.24356091](https://doi.org/10.5281/zenodo.24356091) |
| GCR-0002 | Certification authority with replayable keys | [English](../normes/GCR-0002.en.md) · [français](../normes/GCR-0002.md) | [10.5281/zenodo.24356095](https://doi.org/10.5281/zenodo.24356095) |

Status: preliminary drafts, version 0.1 of 18 November 2026, open for public comment. No standards body
has ratified them. The French text is authoritative; this page translates the French
[README](../README.md).

## The idea

The two primes of an RSA key are built from a **seed**, by a public computation described in full. The
same seed gives the same key, on any machine, with any program written from the text. Whoever holds a
key can therefore prove that it comes from that computation and from nothing else: they make it again
elsewhere and compare. A faulty or malicious generator does not pass that test.

The computation is not new: it is the Shawe-Taylor provable prime construction published in FIPS 186-4.
The standard makes it mandatory, describes it without cross-reference, attaches a generation record to
it and defines the conformity checks.

## What the repository holds

| Path | Role |
|---|---|
| `normes/` | The two standards (French and English), their signed PDFs, signature certificates, fingerprints and timestamp proofs. |
| `primes.py`, `keygen.py`, `pem.py` | Reference implementation of GCR-0001, in Python, with no dependency. |
| `rsagraine.py` | The command: generate a key, check that a seed gives back the key of a record. |
| `independant/gcr.js` | Second implementation, in JavaScript, written from the text of the standard alone. |
| `independant/cas.json` | Test vectors shared by both implementations (GCR-0001, annex A.3). |
| `vecteurs-nist/` | Official NIST vectors for this method. |
| `autorite/autorite.py` | Reference tool of GCR-0002: creates a root, an issuing authority, certificates. |
| `autorite/controle.py` | The twelve checks of GCR-0002 on a certificate chain. |
| `tests/` | The tests. |

File names, command names and messages are in French.

## Try it

Generate a 3072-bit key (`generer` = generate, `sortie` = output folder):

```bash
python3 rsagraine.py generer --bits 3072 --sortie cles/
```

Three files are written: the private key (`cle.pem`), the seed (`graine.hex`) and the public record
(`fiche.json`). **The seed is worth the private key.**

Check that the seed gives back the key of the record (`verifier` = verify):

```bash
python3 rsagraine.py verifier --graine cles/graine.hex --fiche cles/fiche.json
```

Run the tests (OpenSSL required; Node.js for the second implementation):

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

```bash
.venv/bin/python -m pytest -q
```

## Limits

- **The seed is worth the private key.** Replay is done by the holder or their auditor, not in public.
- **The reference implementation is not constant-time.**
- **The quality of the seed is that of the system's randomness.**
- **The authority tool does not yet produce** the revocation lists or the register that GCR-0002
  requires, and only issues server certificates.
- **RSA is not eternal**: a large enough quantum computer breaks it.
- **Read by all does not mean trusted by all**: a root must be listed in trust stores to be trusted
  without any setting.

## Comment

Both texts are open for public comment: open an issue in this repository.

## Licences

The standards are under Creative Commons Attribution 4.0 International (`LICENSE-SPEC`). The code is
under Apache 2.0 (`LICENSE`). The NIST vectors keep their own status.
