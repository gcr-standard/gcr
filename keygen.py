"""RSA key pair from a seed, after FIPS 186-4 appendix B.3.2 (provable primes).

RSA itself is untouched: the keys are ordinary RSA keys, readable by any software.
Only the way the two primes are found is ours to master.
"""
from dataclasses import dataclass
from math import gcd

from primes import PrimeGenerationFailure, SeedStream, provable_rsa_prime

# Modulus size in bits -> minimum seed length in bytes (twice the security strength).
MIN_SEED_BYTES = {2048: 28, 3072: 32, 4096: 32}
DEFAULT_E = 65537
MIN_PRIME_DISTANCE_MARGIN = 100


@dataclass(frozen=True)
class RsaKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()


def _check_inputs(nlen: int, e: int, seed: bytes) -> None:
    if nlen not in MIN_SEED_BYTES:
        raise ValueError(f"modulus size must be one of {sorted(MIN_SEED_BYTES)}")
    if e % 2 == 0 or not (1 << 16) < e < (1 << 256):
        raise ValueError("e must be odd, above 2^16 and below 2^256")
    if len(seed) < MIN_SEED_BYTES[nlen]:
        raise ValueError(f"seed too short: {MIN_SEED_BYTES[nlen]} bytes at least for {nlen} bits")


def generate(nlen: int, seed: bytes, e: int = DEFAULT_E, hash_name: str = "sha256") -> RsaKey:
    """Same seed, same size, same e, same hash: same key, everywhere, always."""
    _check_inputs(nlen, e, seed)
    half = nlen // 2
    stream = SeedStream(seed, hash_name)
    p = provable_rsa_prime(half, e, stream)
    q = provable_rsa_prime(half, e, stream)
    while abs(p - q) <= (1 << (half - MIN_PRIME_DISTANCE_MARGIN)):
        q = provable_rsa_prime(half, e, stream)

    carmichael = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    d = pow(e, -1, carmichael)
    if d <= (1 << half):
        raise PrimeGenerationFailure("private exponent too small for this seed")
    n = p * q
    if n.bit_length() != nlen:
        raise PrimeGenerationFailure("modulus has the wrong size")
    return RsaKey(n=n, e=e, d=d, p=p, q=q)
