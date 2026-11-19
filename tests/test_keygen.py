"""Behaviour of the generator itself."""
import pytest

from keygen import generate
from primes import SeedStream, shawe_taylor_prime

SEED = bytes(range(1, 33))


def test_same_seed_gives_same_key():
    assert generate(2048, SEED) == generate(2048, SEED)


def test_one_bit_of_seed_changes_the_whole_key():
    other = bytes([SEED[0] ^ 1]) + SEED[1:]

    assert generate(2048, SEED).n != generate(2048, other).n


def test_hash_choice_changes_the_key():
    assert generate(2048, SEED, hash_name="sha256").n != generate(2048, SEED, hash_name="sha384").n


@pytest.mark.parametrize("bits", [2048, 3072, 4096])
def test_key_is_a_working_rsa_key_of_the_requested_size(bits):
    key = generate(bits, SEED)
    message = 0x1234567890ABCDEF

    assert key.bits == bits
    assert key.p.bit_length() == key.q.bit_length() == bits // 2
    assert pow(pow(message, key.e, key.n), key.d, key.n) == message


def test_primes_are_far_apart():
    key = generate(2048, SEED)

    assert abs(key.p - key.q) > 1 << (1024 - 100)


@pytest.mark.parametrize("length", [2, 5, 16, 32, 33, 64, 257])
def test_shawe_taylor_prime_has_exact_length_and_is_prime(length):
    prime, _ = shawe_taylor_prime(length, SeedStream(SEED))

    assert prime.bit_length() == length
    assert all(pow(a, prime - 1, prime) == 1 for a in (2, 3, 5, 7) if a % prime)


def test_seed_too_short_is_refused():
    with pytest.raises(ValueError, match="seed too short"):
        generate(3072, b"\x01" * 16)


def test_unknown_size_is_refused():
    with pytest.raises(ValueError, match="modulus size"):
        generate(1024, SEED)


@pytest.mark.parametrize("e", [3, 65536, 1 << 256])
def test_bad_public_exponent_is_refused(e):
    with pytest.raises(ValueError, match="e must be odd"):
        generate(2048, SEED, e=e)


def test_empty_seed_is_refused():
    with pytest.raises(ValueError):
        SeedStream(b"")
