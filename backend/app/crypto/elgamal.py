from pathlib import Path
import hashlib, json, secrets, math

# RFC 3526 MODP Group 14 (2048-bit safe prime), generator 2.
# Note: RFC 3526 defines Modular Exponential (MODP) groups for Diffie-Hellman key exchange.
# This implementation uses the Group 14 safe prime and generator as the finite field group parameters
# for an academic demonstration of the classic ElGamal digital signature scheme.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603"
    "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
Q = P - 1  # Group order for the multiplicative group (Z/PZ)*; prime order q = (P-1)//2


def digest_int(data: bytes) -> int:
    """Interpret the 32-byte SHA-256 digest as an unsigned big-endian integer."""
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


def public_key(x: int) -> int:
    """Compute public key y = g^x mod p."""
    if not isinstance(x, int) or not 1 <= x <= Q - 1:
        raise ValueError("invalid_private_key")
    return pow(G, x, P)


def generate_keypair():
    """
    Generate an ElGamal keypair using Group 14 parameters.
    The generator g=2 generates the subgroup of quadratic residues of order q=(p-1)/2.
    The secret exponent x is sampled uniformly from [1, q-1].
    """
    q_subgroup = Q // 2
    x = secrets.randbelow(q_subgroup - 1) + 1
    return {"p": format(P, "x"), "g": format(G, "x"), "y": format(public_key(x), "x")}, x


def sign(data: bytes, x: int):
    """
    Classic ElGamal digital signature over SHA-256 digest:
      r = g^k mod p
      s = k^(-1) * (h - x * r) mod (p - 1)
    k is a fresh random ephemeral nonce with gcd(k, p-1) == 1.
    """
    h = digest_int(data)
    while True:
        k = secrets.randbelow(Q - 2) + 2
        if math.gcd(k, Q) != 1:
            continue
        r = pow(G, k, P)
        if r in (0, 1):
            continue
        s = (pow(k, -1, Q) * (h - x * r)) % Q
        if s == 0:
            continue
        return {"r": format(r, "x"), "s": format(s, "x")}


def validate_public_key(key):
    """Validate public key parameters against RFC 3526 Group 14 values."""
    if not isinstance(key, dict):
        raise ValueError("invalid_public_key")
    try:
        p, g, y = (
            int(key[k], 16) if isinstance(key[k], str) else int(key[k])
            for k in ("p", "g", "y")
        )
    except Exception as exc:
        raise ValueError("invalid_public_key") from exc

    if p != P or g != G or not 1 < y < p:
        raise ValueError("invalid_public_key_parameters")
    # For safe prime p=2q+1, reject values in the order-2 subgroup
    if pow(y, Q // 2, p) != 1 or y == 1:
        raise ValueError("invalid_public_key_parameters")
    return p, g, y


def verify(data: bytes, key, signature):
    """
    Verify ElGamal signature (r, s) on document data:
      Check: g^h = y^r * r^s (mod p)
    Returns:
      (True, "valid") if equation holds.
      (False, "signature_mismatch") if math fails (data was modified or key is wrong).
      (False, "invalid_signature_component") or (False, "invalid_package") for malformed data.
    """
    try:
        p, g, y = validate_public_key(key)
        r = int(signature["r"], 16) if isinstance(signature["r"], str) else int(signature["r"])
        s = int(signature["s"], 16) if isinstance(signature["s"], str) else int(signature["s"])
        if not 0 < r < p or math.gcd(r, p) != 1:
            return False, "invalid_signature_component"
        if not 0 < s < Q:
            return False, "invalid_signature_component"
        h = digest_int(data)
        v1 = pow(g, h, p)
        v2 = (pow(y, r, p) * pow(r, s, p)) % p
        is_valid = (v1 == v2)
        return is_valid, "valid" if is_valid else "signature_mismatch"
    except ValueError as exc:
        return False, str(exc) if str(exc).startswith("invalid_public_key") else "invalid_package"
    except (KeyError, TypeError, OverflowError):
        return False, "invalid_package"


def fingerprint(key):
    """Compute canonical SHA-256 fingerprint of public key (p, g, y)."""
    canonical = json.dumps(
        {
            k: (format(int(key[k], 16), "x") if isinstance(key[k], str) else format(key[k], "x"))
            for k in ("p", "g", "y")
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Educational Step-by-Step Simulation Utilities (Small Parameters)
# ---------------------------------------------------------------------------

def extended_gcd(a: int, b: int):
    """Extended Euclidean algorithm: returns (g, x, y) such that a*x + b*y = g."""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse_steps(a: int, m: int):
    """Compute modular inverse a^(-1) mod m with calculation steps."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g}")
    inv = (x % m + m) % m
    return inv, {"gcd": g, "raw_x": x, "mod_inverse": inv}


def toy_elgamal_simulate(message: str = "Hello Cypherlab", toy_p: int = 467, toy_g: int = 2):
    """
    Educational walkthrough using small toy parameters (p=467, g=2).
    Never used for real signatures; strictly for academic classroom illustration.
    """
    p = toy_p
    g = toy_g
    q = p - 1  # 466

    # Step 1: Keygen
    x = 105  # Toy private key
    y = pow(g, x, p)

    # Step 2: Digest (integer hash representation)
    msg_bytes = message.encode("utf-8")
    full_sha = hashlib.sha256(msg_bytes).hexdigest()
    # Map digest to an integer in [1, q-1]
    h = (int(full_sha, 16) % (q - 2)) + 1

    # Step 3: Nonce selection
    # Choose a valid k coprime to q
    k_candidates = [211, 213, 215, 217, 219, 221, 223]
    k = 211
    for cand in k_candidates:
        if math.gcd(cand, q) == 1:
            k = cand
            break

    # Step 4: Modular inverse of k mod (p-1)
    k_inv, inv_steps = mod_inverse_steps(k, q)

    # Step 5: Signature components
    r = pow(g, k, p)
    s = (k_inv * (h - x * r)) % q

    # Step 6: Verification equations
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    valid = (v1 == v2)

    # Step 7: Tamper demonstration (alter 1 byte)
    tampered_msg = message + "!"
    tampered_bytes = tampered_msg.encode("utf-8")
    tampered_sha = hashlib.sha256(tampered_bytes).hexdigest()
    h_tampered = (int(tampered_sha, 16) % (q - 2)) + 1
    v1_tampered = pow(g, h_tampered, p)
    tampered_valid = (v1_tampered == v2)

    return {
        "educational_disclaimer": "TOY PARAMETERS ONLY (p=467, g=2). Strictly for algorithm visualization.",
        "parameters": {"p": p, "g": g, "p_minus_1": q},
        "key_generation": {
            "private_key_x": x,
            "public_key_y_formula": f"g^x mod p = {g}^{x} mod {p}",
            "public_key_y": y,
        },
        "hashing": {
            "original_message": message,
            "sha256_hex": full_sha,
            "digest_int_h": h,
        },
        "signing": {
            "ephemeral_nonce_k": k,
            "gcd_k_q": math.gcd(k, q),
            "k_inverse_mod_q": k_inv,
            "inverse_details": inv_steps,
            "component_r_formula": f"g^k mod p = {g}^{k} mod {p}",
            "component_r": r,
            "component_s_formula": f"k^(-1) * (h - x*r) mod (p-1) = {k_inv} * ({h} - {x}*{r}) mod {q}",
            "component_s": s,
        },
        "verification": {
            "lhs_v1_formula": f"g^h mod p = {g}^{h} mod {p}",
            "lhs_v1": v1,
            "rhs_v2_formula": f"(y^r * r^s) mod p = ({y}^{r} * {r}^{s}) mod {p}",
            "rhs_v2": v2,
            "equations_equal": valid,
            "outcome": "VALID_SIGNATURE" if valid else "INVALID_SIGNATURE",
        },
        "tamper_simulation": {
            "tampered_message": tampered_msg,
            "tampered_sha256": tampered_sha,
            "tampered_digest_h": h_tampered,
            "tampered_v1": v1_tampered,
            "tampered_v2": v2,
            "tampered_equal": tampered_valid,
            "outcome": "TAMPER_DETECTED" if not tampered_valid else "ERROR",
            "explanation": "Changing a single byte altered the SHA-256 digest avalanche, yielding h_tampered != h, causing g^(h_tampered) != y^r * r^s (mod p).",
        },
    }
