"""Provable primes from a seed (Shawe-Taylor), after FIPS 186-4 appendix C.6 and C.10.

Every prime comes with nothing hidden: the same seed always gives the same prime,
on any machine, with any independent implementation of this text.

WARNING: Python is not constant-time. Reference implementation, for producing and
checking keys in a controlled place, not for a machine an attacker can observe.
"""
import hashlib
from math import gcd, isqrt

SMALL_PRIME_LIMIT_BITS = 33


class PrimeGenerationFailure(Exception):
    """The seed did not yield a prime within the bounds the standard allows."""


class SeedStream:
    """A seed read as a counter: each draw hashes the counter then moves it on."""

    def __init__(self, seed: bytes, hash_name: str = "sha256"):
        if not seed:
            raise ValueError("empty seed")
        self.width = len(seed)
        self.value = int.from_bytes(seed, "big")
        self.hash_name = hash_name
        self.outlen = hashlib.new(hash_name).digest_size * 8

    def hash_at(self, offset: int) -> int:
        counter = (self.value + offset) % (1 << (8 * self.width))
        digest = hashlib.new(self.hash_name, counter.to_bytes(self.width, "big")).digest()
        return int.from_bytes(digest, "big")

    def advance(self, steps: int) -> None:
        self.value += steps

    def draw(self, iterations: int) -> int:
        """Concatenate iterations+1 digests, least significant first (C.6 step 19)."""
        total = 0
        for i in range(iterations + 1):
            total += self.hash_at(i) << (i * self.outlen)
        self.advance(iterations + 1)
        return total


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def _is_prime_by_trial_division(c: int) -> bool:
    if c < 2:
        return False
    if c % 2 == 0:
        return c == 2
    divisor = 3
    while divisor * divisor <= c:
        if c % divisor == 0:
            return False
        divisor += 2
    return True


def _small_prime(length: int, stream: SeedStream) -> tuple[int, int]:
    counter = 0
    while True:
        c = stream.hash_at(0) ^ stream.hash_at(1)
        c = (1 << (length - 1)) + (c % (1 << (length - 1)))
        c = 2 * (c // 2) + 1
        counter += 1
        stream.advance(2)
        if _is_prime_by_trial_division(c):
            return c, counter
        if counter > 4 * length:
            raise PrimeGenerationFailure("no small prime for this seed")


def shawe_taylor_prime(length: int, stream: SeedStream) -> tuple[int, int]:
    """C.6: a prime of exactly `length` bits, proven prime by construction.

    Returns (prime, counter). The stream is left where the next draw must start.
    """
    if length < 2:
        raise ValueError("length must be at least 2 bits")
    if length < SMALL_PRIME_LIMIT_BITS:
        return _small_prime(length, stream)

    c0, counter = shawe_taylor_prime(_ceil_div(length, 2) + 1, stream)
    iterations = _ceil_div(length, stream.outlen) - 1
    old_counter = counter
    x = stream.draw(iterations)
    x = (1 << (length - 1)) + (x % (1 << (length - 1)))
    t = _ceil_div(x, 2 * c0)
    while True:
        if 2 * t * c0 + 1 > (1 << length):
            t = _ceil_div(1 << (length - 1), 2 * c0)
        c = 2 * t * c0 + 1
        counter += 1
        a = 2 + (stream.draw(iterations) % (c - 3))
        z = pow(a, 2 * t, c)
        if gcd(z - 1, c) == 1 and pow(z, c0, c) == 1:
            return c, counter
        if counter >= 4 * length + old_counter:
            raise PrimeGenerationFailure("no prime for this seed")
        t += 1


def provable_rsa_prime(length: int, e: int, stream: SeedStream) -> int:
    """C.10 with N1 = N2 = 1: one RSA prime of `length` bits, with gcd(p-1, e) = 1.

    The prime is at least sqrt(2) * 2^(length-1), so that p*q has exactly 2*length bits.
    """
    p0, _ = shawe_taylor_prime(_ceil_div(length, 2) + 1, stream)
    iterations = _ceil_div(length, stream.outlen) - 1
    lower = isqrt(1 << (2 * length - 1))  # floor(sqrt(2) * 2^(length-1))
    x = stream.draw(iterations)
    x = lower + (x % ((1 << length) - lower))
    # With p1 = p2 = 1 the standard's y is 1, and p = 2*(t - 1)*p0 + 1.
    t = _ceil_div(2 * p0 + x, 2 * p0)
    counter = 0
    while True:
        if 2 * (t - 1) * p0 + 1 > (1 << length):
            t = _ceil_div(2 * p0 + lower, 2 * p0)
        p = 2 * (t - 1) * p0 + 1
        counter += 1
        if gcd(p - 1, e) == 1:
            a = 2 + (stream.draw(iterations) % (p - 3))
            z = pow(a, 2 * (t - 1), p)
            if gcd(z - 1, p) == 1 and pow(z, p0, p) == 1:
                return p
        if counter >= 5 * length:
            raise PrimeGenerationFailure("no RSA prime for this seed")
        t += 1
