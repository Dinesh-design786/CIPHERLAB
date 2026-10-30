import hashlib, math
import pytest
from app.crypto.elgamal import (
    P,
    G,
    Q,
    generate_keypair,
    sign,
    verify,
    fingerprint,
    public_key,
    validate_public_key,
    toy_elgamal_simulate,
    extended_gcd,
    mod_inverse_steps,
)

def test_generate_consistency():
    key, x = generate_keypair()
    assert int(key['y'], 16) == public_key(x)
    assert len(key['p']) >= 512


def test_sign_verify_unchanged_and_changed():
    key, x = generate_keypair()
    data = b'original document'
    sig = sign(data, x)
    assert verify(data, key, sig) == (True, 'valid')
    assert verify(data + b'!', key, sig) == (False, 'signature_mismatch')


def test_wrong_key_fails():
    key, x = generate_keypair()
    wrong, _ = generate_keypair()
    sig = sign(b'data', x)
    assert verify(b'data', wrong, sig)[0] is False


def test_corrupt_components_fail():
    key, x = generate_keypair()
    sig = sign(b'data', x)
    sig['s'] = '0'
    assert verify(b'data', key, sig) == (False, 'invalid_signature_component')


def test_empty_file_and_fresh_nonces():
    key, x = generate_keypair()
    a = sign(b'', x)
    b = sign(b'', x)
    assert verify(b'', key, a)[0] and verify(b'', key, b)[0]
    assert a != b
    assert math.gcd(5, Q) == 1 and pow(3, -1, 11) == 4


def test_invalid_key_and_signature_package():
    key, x = generate_keypair()
    bad = dict(key, p='23')
    assert verify(b'data', bad, {'r': '2', 's': '3'}) == (False, 'invalid_public_key_parameters')
    assert verify(b'data', key, {}) == (False, 'invalid_package')


def test_fingerprint_stable():
    key, _ = generate_keypair()
    assert fingerprint(key) == fingerprint(dict(key))


def test_single_byte_tampering():
    key, x = generate_keypair()
    data = bytearray(b"Confidential financial statement payload")
    sig = sign(bytes(data), x)
    assert verify(bytes(data), key, sig) == (True, 'valid')

    # Flip single bit in 1st byte
    tampered = bytearray(data)
    tampered[0] ^= 0x01
    assert verify(bytes(tampered), key, sig) == (False, 'signature_mismatch')

    # Flip single byte at last position
    tampered_last = bytearray(data)
    tampered_last[-1] = (tampered_last[-1] + 1) % 256
    assert verify(bytes(tampered_last), key, sig) == (False, 'signature_mismatch')


def test_toy_simulation_math():
    sim = toy_elgamal_simulate(message="Classroom Proof")
    assert sim["verification"]["equations_equal"] is True
    assert sim["verification"]["outcome"] == "VALID_SIGNATURE"
    assert sim["tamper_simulation"]["tampered_equal"] is False
    assert sim["tamper_simulation"]["outcome"] == "TAMPER_DETECTED"
    assert "avalanche" in sim["tamper_simulation"]["explanation"].lower()


def test_extended_gcd_and_inverse():
    g, x, y = extended_gcd(35, 15)
    assert g == 5
    assert 35 * x + 15 * y == 5

    inv, details = mod_inverse_steps(3, 11)
    assert inv == 4
    assert (3 * inv) % 11 == 1
