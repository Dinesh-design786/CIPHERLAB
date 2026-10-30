import base64, hashlib, io, json, os, platform, secrets, sys, time, uuid, zipfile
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .db import (
    SessionLocal,
    PublicKey,
    Document,
    Signature,
    VerificationEvent,
    AuditEvent,
    BenchmarkRecord,
)
from .crypto.elgamal import (
    generate_keypair,
    sign,
    verify,
    fingerprint,
    public_key,
    validate_public_key,
    toy_elgamal_simulate,
    P,
    G,
)

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MiB limit
DATA = Path(os.getenv("APP_DATA_DIR", Path(__file__).resolve().parents[1] / "data"))
STORAGE = DATA / "uploads"
STORAGE.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="CipherLab // Zero API",
    version="2.0.0",
    description="Educational ElGamal Digital Signature Verification Lab (RFC 3526 MODP Group 14 safe prime parameter).",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174", "http://localhost:3000", "*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Document-Sha256", "X-Public-Key-Fingerprint", "Content-Disposition"],
)


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def now():
    return datetime.now(timezone.utc)


# Pydantic Schemas
class GenerateRequest(BaseModel):
    label: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=10, max_length=256)


class ImportRequest(BaseModel):
    label: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=1, max_length=256)
    private_key_export: dict


class RevokeRequest(BaseModel):
    key_id: int
    reason: str = Field(min_length=3, max_length=255)


class RotateRequest(BaseModel):
    old_key_id: int
    new_label: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=10, max_length=256)


class BenchmarkRunRequest(BaseModel):
    repetitions: int = Field(default=3, ge=1, le=10)


# Safe Private Key Encryption with scrypt and AES-256-GCM
def encrypt_private(x: int, password: str):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**15,
        r=8,
        p=1,
        dklen=32,
        maxmem=128 * 1024 * 1024,
    )
    token = AESGCM(derived).encrypt(nonce, str(x).encode("utf-8"), b"elgamal-private-v1")
    return base64.b64encode(token).decode(), salt.hex(), nonce.hex()


def decrypt_private(row: PublicKey, password: str) -> int:
    try:
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(row.salt),
            n=2**15,
            r=8,
            p=1,
            dklen=32,
            maxmem=128 * 1024 * 1024,
        )
        decrypted = AESGCM(derived).decrypt(
            bytes.fromhex(row.nonce),
            base64.b64decode(row.encrypted_private),
            b"elgamal-private-v1",
        )
        return int(decrypted)
    except Exception as exc:
        raise HTTPException(403, "Key passphrase is incorrect or key data is damaged") from exc


def key_json(k: PublicKey):
    return {"p": k.p, "g": k.g, "y": k.y}


def save_doc(db: Session, data: bytes, name: str):
    ident = str(uuid.uuid4())
    (STORAGE / ident).write_bytes(data)
    d = Document(
        storage_id=ident,
        filename=Path(name).name[:255],
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
    )
    db.add(d)
    db.flush()
    return d


# ---------------------------------------------------------------------------
# API Routes: Health & Dashboard Statistics
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "scheme": "ElGamal-SHA256",
        "parameters": "RFC 3526 MODP Group 14 safe prime (2048-bit)",
        "generator": 2,
        "max_file_bytes": MAX_FILE_SIZE,
    }


@app.get("/api/stats")
def stats(db: Session = Depends(db_session)):
    """
    Connected to actual SQLite database records.
    Accurately separates confirmed document tampering from malformed inputs.
    """
    events = db.query(VerificationEvent).order_by(VerificationEvent.created_at.desc()).all()
    signed_count = db.query(func.count(Signature.id)).scalar() or 0
    active_keys_count = db.query(PublicKey).filter(PublicKey.status == "active").count()
    revoked_keys_count = db.query(PublicKey).filter(PublicKey.status == "revoked").count()

    valid_count = sum(1 for e in events if e.result)
    tampered_count = sum(1 for e in events if not e.result and e.reason_code == "signature_mismatch")
    malformed_count = sum(1 for e in events if not e.result and e.reason_code != "signature_mismatch")

    return {
        "signed_documents": signed_count,
        "total_verifications": len(events),
        "valid": valid_count,
        "tampered_documents": tampered_count,
        "invalid": len(events) - valid_count,  # Total invalid for backwards compatibility
        "malformed_packages": malformed_count,
        "active_keys": active_keys_count,
        "revoked_keys": revoked_keys_count,
        "recent": [
            {
                "filename": e.filename,
                "valid": e.result,
                "reason_code": e.reason_code,
                "digest": e.digest,
                "fingerprint": e.fingerprint,
                "created_at": e.created_at.isoformat(),
            }
            for e in events[:5]
        ],
    }


# ---------------------------------------------------------------------------
# API Routes: Key Vault (Lifecycle, Rotation, Revocation, Export/Import)
# ---------------------------------------------------------------------------

@app.get("/api/keys")
def list_keys(db: Session = Depends(db_session)):
    """List all public keys with lifecycle status and metadata."""
    rows = db.query(PublicKey).order_by(PublicKey.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "label": r.label,
            "public_key": key_json(r),
            "fingerprint": r.fingerprint,
            "status": r.status or ("active" if r.active else "revoked"),
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            "revocation_reason": r.revocation_reason,
            "created_at": r.created_at.isoformat(),
            "active": r.active,
        }
        for r in rows
    ]


@app.post("/api/keys/generate")
def make_key(req: GenerateRequest, db: Session = Depends(db_session)):
    """Generate RFC 3526 Group 14 ElGamal keypair and encrypt private key with password."""
    pub, x = generate_keypair()
    encrypted, salt, nonce = encrypt_private(x, req.password)
    fp = fingerprint(pub)

    row = PublicKey(
        label=req.label,
        p=pub["p"],
        g=pub["g"],
        y=pub["y"],
        fingerprint=fp,
        encrypted_private=encrypted,
        salt=salt,
        nonce=nonce,
        status="active",
        active=True,
    )
    db.add(row)

    # Log to Audit Ledger
    db.add(
        AuditEvent(
            event_type="KEY_GEN",
            filename=None,
            digest=None,
            fingerprint=fp,
            result="SUCCESS",
            reason_code="key_generated",
            details=json.dumps({"label": req.label, "key_id": None}),
        )
    )
    db.commit()
    db.refresh(row)

    return {
        "id": row.id,
        "label": row.label,
        "public_key": pub,
        "fingerprint": fp,
        "status": "active",
        "created_at": row.created_at.isoformat(),
        "private_key_export": {
            "format": "elgamal-private-key",
            "version": "1",
            "encryption": "AES-256-GCM+scrypt",
            "salt": salt,
            "nonce": nonce,
            "ciphertext": encrypted,
            "public_key": pub,
            "fingerprint": fp,
        },
    }


@app.post("/api/keys/revoke")
def revoke_key(req: RevokeRequest, db: Session = Depends(db_session)):
    """Revoke a compromised or retired key with confirmation and recorded reason."""
    row = db.get(PublicKey, req.key_id)
    if not row:
        raise HTTPException(404, "Key not found")
    if row.status == "revoked":
        raise HTTPException(400, "Key is already revoked")

    row.status = "revoked"
    row.active = False
    row.revoked_at = now()
    row.revocation_reason = req.reason

    db.add(
        AuditEvent(
            event_type="KEY_REVOKE",
            filename=None,
            digest=None,
            fingerprint=row.fingerprint,
            result="SUCCESS",
            reason_code="key_revoked",
            details=json.dumps({"key_id": row.id, "reason": req.reason}),
        )
    )
    db.commit()
    return {
        "success": True,
        "key_id": row.id,
        "status": "revoked",
        "revoked_at": row.revoked_at.isoformat(),
        "reason": req.reason,
    }


@app.post("/api/keys/rotate")
def rotate_key(req: RotateRequest, db: Session = Depends(db_session)):
    """Key rotation workflow: retire old key and establish new active key."""
    old_row = db.get(PublicKey, req.old_key_id)
    if not old_row:
        raise HTTPException(404, "Previous key not found")

    # Generate new keypair
    pub, x = generate_keypair()
    encrypted, salt, nonce = encrypt_private(x, req.password)
    new_fp = fingerprint(pub)

    # Retire old key
    old_row.status = "retired"
    old_row.active = False
    old_row.revocation_reason = f"Rotated to new key (Fingerprint: {new_fp[:16]}...)"

    # Create new key
    new_row = PublicKey(
        label=req.new_label,
        p=pub["p"],
        g=pub["g"],
        y=pub["y"],
        fingerprint=new_fp,
        encrypted_private=encrypted,
        salt=salt,
        nonce=nonce,
        status="active",
        active=True,
    )
    db.add(new_row)

    db.add(
        AuditEvent(
            event_type="KEY_ROTATE",
            filename=None,
            digest=None,
            fingerprint=new_fp,
            result="SUCCESS",
            reason_code="key_rotated",
            details=json.dumps({"old_key_id": old_row.id, "old_fingerprint": old_row.fingerprint}),
        )
    )
    db.commit()
    db.refresh(new_row)

    return {
        "success": True,
        "old_key_id": old_row.id,
        "old_status": "retired",
        "new_key": {
            "id": new_row.id,
            "label": new_row.label,
            "fingerprint": new_fp,
            "created_at": new_row.created_at.isoformat(),
        },
        "private_key_export": {
            "format": "elgamal-private-key",
            "version": "1",
            "encryption": "AES-256-GCM+scrypt",
            "salt": salt,
            "nonce": nonce,
            "ciphertext": encrypted,
            "public_key": pub,
        },
    }


@app.post("/api/keys/import")
def import_key(req: ImportRequest, db: Session = Depends(db_session)):
    """Import and decrypt/validate protected JSON key export."""
    export = req.private_key_export
    try:
        if (
            export.get("format") != "elgamal-private-key"
            or export.get("version") != "1"
            or export.get("encryption") != "AES-256-GCM+scrypt"
        ):
            raise ValueError("Unsupported format or encryption metadata")
        salt = bytes.fromhex(export["salt"])
        nonce = bytes.fromhex(export["nonce"])
        ciphertext = base64.b64decode(export["ciphertext"], validate=True)
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError("Invalid salt/nonce length")

        derived = hashlib.scrypt(
            req.password.encode("utf-8"),
            salt=salt,
            n=2**15,
            r=8,
            p=1,
            dklen=32,
            maxmem=128 * 1024 * 1024,
        )
        x = int(AESGCM(derived).decrypt(nonce, ciphertext, b"elgamal-private-v1"))
        expected = public_key(x)
        pub = export["public_key"]
        validate_public_key(pub)
        if int(pub["y"], 16) != expected:
            raise ValueError("Public key does not match decrypted private key")
    except Exception as exc:
        raise HTTPException(
            400, "Protected key export is invalid or the passphrase is incorrect"
        ) from exc

    encrypted, salt_hex, nonce_hex = encrypt_private(x, req.password)
    fp = fingerprint(pub)
    row = PublicKey(
        label=req.label,
        p=pub["p"],
        g=pub["g"],
        y=pub["y"],
        fingerprint=fp,
        encrypted_private=encrypted,
        salt=salt_hex,
        nonce=nonce_hex,
        status="active",
        active=True,
    )
    db.add(row)

    db.add(
        AuditEvent(
            event_type="KEY_IMPORT",
            filename=None,
            digest=None,
            fingerprint=fp,
            result="SUCCESS",
            reason_code="key_imported",
            details=json.dumps({"label": req.label}),
        )
    )
    db.commit()
    db.refresh(row)
    return {
        "id": row.id,
        "label": row.label,
        "public_key": pub,
        "fingerprint": fp,
        "status": "active",
        "created_at": row.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# API Routes: Document Signing & Verification
# ---------------------------------------------------------------------------

@app.post("/api/sign")
def sign_document(
    file: UploadFile = File(...),
    key_id: int = Form(...),
    password: str = Form(...),
    db: Session = Depends(db_session),
):
    """
    Sign document bytes with private key unlocked in process memory.
    Returns downloadable ZIP containing signature.json and signature.txt.
    """
    data = file.file.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(413, "File exceeds 25 MiB limit")

    row = db.get(PublicKey, key_id)
    if not row or not row.active or row.status == "revoked":
        raise HTTPException(404, "Selected key is revoked or not found")

    x = decrypt_private(row, password)
    sig = sign(data, x)
    doc = save_doc(db, data, file.filename or "document")

    sig_record = Signature(
        document_id=doc.id,
        key_id=row.id,
        r=sig["r"],
        s=sig["s"],
    )
    db.add(sig_record)

    # Log signing event
    db.add(
        AuditEvent(
            event_type="SIGNING",
            filename=doc.filename,
            digest=doc.sha256,
            fingerprint=row.fingerprint,
            result="SUCCESS",
            reason_code="document_signed",
            details=json.dumps({"doc_id": doc.id, "size_bytes": doc.size}),
        )
    )
    db.commit()

    package = {
        "format": "elgamal-signature-package",
        "version": "1.0",
        "scheme": "ElGamal-SHA256",
        "parameters": "RFC 3526 MODP Group 14 safe prime (2048-bit)",
        "hash": "SHA-256",
        "filename": doc.filename,
        "document_sha256": doc.sha256,
        "public_key": key_json(row),
        "signature": sig,
        "public_key_fingerprint": row.fingerprint,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("signature.json", json.dumps(package, indent=2))
        z.writestr("signature.txt", f"r={sig['r']}\ns={sig['s']}\n")
    stream.seek(0)
    response = StreamingResponse(
        stream,
        media_type="application/zip",
        headers={
            "Content-Disposition": "attachment; filename=signature-package.zip",
            "X-Document-Sha256": doc.sha256,
            "X-Public-Key-Fingerprint": row.fingerprint,
        },
    )
    response.package_bytes = stream.getvalue()
    return response


@app.post("/api/verify")
def verify_document(
    file: UploadFile = File(...),
    package: UploadFile = File(...),
    db: Session = Depends(db_session),
):
    """
    Verify document integrity and signature mathematics.
    Checks public key revocation registry and separates confirmed tampering from malformed inputs.
    """
    data = file.file.read(MAX_FILE_SIZE + 1)
    raw = package.file.read(2 * 1024 * 1024 + 1)
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(413, "File exceeds 25 MiB limit")

    obj = {}
    fp = ""
    ok = False
    reason = "invalid_package"
    report_id = str(uuid.uuid4())
    key_trusted = True
    key_status = "active"

    try:
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("Package exceeds 2 MiB limit")

        if (package.filename or "").lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                info = z.getinfo("signature.json")
                if info.file_size > 1024 * 1024:
                    raise ValueError("signature.json inside ZIP exceeds 1 MiB")
                obj = json.loads(z.read(info))
        else:
            obj = json.loads(raw)

        if (
            obj.get("format") != "elgamal-signature-package"
            or obj.get("version") != "1.0"
            or obj.get("hash") != "SHA-256"
        ):
            raise ValueError("Unrecognized signature package format")

        key = obj["public_key"]
        fp = fingerprint(key)
        if fp != obj.get("public_key_fingerprint"):
            raise ValueError("Fingerprint mismatch in package metadata")

        # Check key status in database
        key_record = db.query(PublicKey).filter(PublicKey.fingerprint == fp).first()
        if key_record:
            key_status = key_record.status or ("active" if key_record.active else "revoked")
            if key_status == "revoked":
                key_trusted = False

        ok, reason = verify(data, key, obj["signature"])

    except Exception:
        ok = False
        reason = "invalid_package"
        fp = fp or ""

    digest = hashlib.sha256(data).hexdigest()
    name = Path(file.filename or "document").name[:255]

    # Save to legacy verification_events
    db.add(
        VerificationEvent(
            filename=name,
            result=ok,
            reason_code=reason,
            digest=digest,
            fingerprint=fp,
        )
    )

    # Save to upgraded audit_events
    audit_result = "VALID" if ok else ("TAMPERED" if reason == "signature_mismatch" else "INVALID")
    db.add(
        AuditEvent(
            event_type="VERIFICATION",
            filename=name,
            digest=digest,
            fingerprint=fp,
            result=audit_result,
            reason_code=reason,
            details=json.dumps(
                {
                    "report_id": report_id,
                    "expected_digest": obj.get("document_sha256"),
                    "key_trusted": key_trusted,
                    "key_status": key_status,
                }
            ),
        )
    )
    db.commit()

    # Detailed message
    if ok:
        if not key_trusted:
            message = "Signature equation mathematically verifies, BUT the public key has been REVOKED in the key registry."
        else:
            message = "Signature mathematically verifies for these bytes and public key (Integrity Confirmed)."
    else:
        if reason == "signature_mismatch":
            message = "Tamper Detected: Document content or signature components do not match."
        else:
            message = "Invalid Package: Signature package data is malformed or corrupted."

    return {
        "report_id": report_id,
        "valid": ok,
        "reason_code": reason,
        "digest": digest,
        "package_digest": obj.get("document_sha256"),
        "fingerprint": fp,
        "key_status": key_status,
        "key_trusted": key_trusted,
        "identity_verified": False,
        "message": message,
        "disclaimer": "Mathematical signature validity confirms mathematical alignment with the public key; it does not establish verified human identity.",
        "algorithm": "ElGamal (RFC 3526 MODP Group 14 2048-bit safe prime)",
        "hash_algorithm": "SHA-256",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# API Routes: Tamper Detection Lab
# ---------------------------------------------------------------------------

@app.post("/api/tamper-lab/run")
def tamper_lab_run(
    file: UploadFile = File(...),
    byte_offset: int = Form(0),
    new_byte_val: int = Form(65),  # 'A'
    key_id: int = Form(...),
    password: str = Form(...),
    db: Session = Depends(db_session),
):
    """
    Interactive Tamper Lab:
    1. Reads original file and signs it with unlocked key.
    2. Produces a modified copy by changing exactly one byte at byte_offset.
    3. Calculates original and modified SHA-256 digests.
    4. Evaluates verification on both and explains mathematical divergence.
    """
    orig_data = file.file.read(MAX_FILE_SIZE + 1)
    if len(orig_data) > MAX_FILE_SIZE:
        raise HTTPException(413, "File exceeds 25 MiB limit")
    if len(orig_data) == 0:
        orig_data = b"Hello, this is a sample educational document for tampering analysis."

    row = db.get(PublicKey, key_id)
    if not row or not row.active:
        raise HTTPException(404, "Key not found")

    x = decrypt_private(row, password)
    sig = sign(orig_data, x)

    # Controlled byte tampering
    tampered_bytes = bytearray(orig_data)
    target_offset = min(max(0, byte_offset), len(tampered_bytes) - 1)
    original_byte_val = tampered_bytes[target_offset]

    # Change the byte
    if new_byte_val == original_byte_val:
        new_byte_val = (original_byte_val ^ 0xFF) & 0xFF
    tampered_bytes[target_offset] = new_byte_val
    tampered_data = bytes(tampered_bytes)

    orig_sha = hashlib.sha256(orig_data).hexdigest()
    tampered_sha = hashlib.sha256(tampered_data).hexdigest()

    # Verify both
    pub_k = key_json(row)
    orig_valid, orig_reason = verify(orig_data, pub_k, sig)
    tampered_valid, tampered_reason = verify(tampered_data, pub_k, sig)

    return {
        "filename": file.filename or "sample_document.txt",
        "file_size_bytes": len(orig_data),
        "tamper_details": {
            "offset": target_offset,
            "original_byte_hex": f"0x{original_byte_val:02X}",
            "original_byte_char": chr(original_byte_val) if 32 <= original_byte_val <= 126 else ".",
            "modified_byte_hex": f"0x{new_byte_val:02X}",
            "modified_byte_char": chr(new_byte_val) if 32 <= new_byte_val <= 126 else ".",
        },
        "original_file": {
            "sha256": orig_sha,
            "verified": orig_valid,
            "reason_code": orig_reason,
        },
        "tampered_file": {
            "sha256": tampered_sha,
            "verified": tampered_valid,
            "reason_code": tampered_reason,
        },
        "signature": sig,
        "fingerprint": row.fingerprint,
        "mathematical_explanation": (
            f"Modifying offset {target_offset} produced a completely different SHA-256 digest ({tampered_sha[:16]}... vs {orig_sha[:16]}...) "
            f"due to cryptographic avalanche effect. In the verification equation g^h = y^r * r^s (mod p), the left-hand side "
            f"evaluates to g^(h_tampered) mod p, which does not equal y^r * r^s mod p with overwhelming probability."
        ),
    }


# ---------------------------------------------------------------------------
# API Routes: ElGamal Algorithm Visualizer (Educational Step-by-Step)
# ---------------------------------------------------------------------------

@app.get("/api/algorithm/simulate")
def algorithm_simulate(message: str = "Educational Cryptography Demonstration"):
    """
    Returns step-by-step arithmetic trace of ElGamal key generation, hashing,
    nonce selection, modular inversion, signing, and verification.
    Uses small toy parameters for classroom visual clarity.
    """
    return toy_elgamal_simulate(message=message)


# ---------------------------------------------------------------------------
# API Routes: Benchmark & Test Lab (Real Experiments)
# ---------------------------------------------------------------------------

@app.post("/api/benchmarks/run")
def run_benchmark(req: BenchmarkRunRequest = BenchmarkRunRequest(), db: Session = Depends(db_session)):
    """
    Execute repeatable real performance & security experiments:
    Measures SHA-256 hashing, ElGamal signing, and verification times across 1 KB, 100 KB, and 1 MB.
    Computes valid acceptance rate and tamper detection rate.
    """
    test_sizes = [
        (1 * 1024, "1 KB"),
        (100 * 1024, "100 KB"),
        (1024 * 1024, "1 MB"),
    ]

    # Generate dedicated temporary benchmark keypair
    pub, x = generate_keypair()
    results = []

    for size_bytes, label in test_sizes:
        # Repetitive real measurement
        hash_times = []
        sign_times = []
        verify_times = []
        valid_passed = True
        tamper_detected = True

        for _ in range(req.repetitions):
            # Deterministic test payload
            payload = os.urandom(size_bytes)

            # 1. Hashing
            t0 = time.perf_counter()
            _ = hashlib.sha256(payload).hexdigest()
            t1 = time.perf_counter()
            hash_times.append((t1 - t0) * 1000)

            # 2. Signing
            t0 = time.perf_counter()
            sig = sign(payload, x)
            t1 = time.perf_counter()
            sign_times.append((t1 - t0) * 1000)

            # 3. Verification of valid
            t0 = time.perf_counter()
            v_ok, _ = verify(payload, pub, sig)
            t1 = time.perf_counter()
            verify_times.append((t1 - t0) * 1000)
            if not v_ok:
                valid_passed = False

            # 4. Tamper verification
            tampered = bytearray(payload)
            tampered[0] ^= 0x01  # Flip 1 bit
            t_ok, _ = verify(bytes(tampered), pub, sig)
            if t_ok:  # If tampered document passed, detection failed!
                tamper_detected = False

        avg_hash = sum(hash_times) / len(hash_times)
        avg_sign = sum(sign_times) / len(sign_times)
        avg_verify = sum(verify_times) / len(verify_times)

        record = BenchmarkRecord(
            file_size_bytes=size_bytes,
            file_size_label=label,
            hash_time_ms=round(avg_hash, 3),
            sign_time_ms=round(avg_sign, 3),
            verify_time_ms=round(avg_verify, 3),
            valid_pass=valid_passed,
            tamper_detected=tamper_detected,
            repetitions=req.repetitions,
            environment_info=f"{platform.system()} {platform.machine()} Python {sys.version.split()[0]}",
        )
        db.add(record)
        results.append({
            "size_bytes": size_bytes,
            "label": label,
            "hash_time_ms": round(avg_hash, 3),
            "sign_time_ms": round(avg_sign, 3),
            "verify_time_ms": round(avg_verify, 3),
            "valid_signature_pass_rate": 100.0 if valid_passed else 0.0,
            "tamper_detection_rate": 100.0 if tamper_detected else 0.0,
            "repetitions": req.repetitions,
        })

    db.commit()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": f"{platform.system()} {platform.machine()} Python {sys.version.split()[0]}",
        "parameters": "RFC 3526 MODP Group 14 (2048-bit)",
        "benchmarks": results,
    }


@app.get("/api/benchmarks/history")
def benchmark_history(db: Session = Depends(db_session)):
    """Fetch stored real benchmark runs."""
    records = db.query(BenchmarkRecord).order_by(BenchmarkRecord.created_at.desc()).limit(30).all()
    return [
        {
            "id": r.id,
            "file_size_bytes": r.file_size_bytes,
            "file_size_label": r.file_size_label,
            "hash_time_ms": r.hash_time_ms,
            "sign_time_ms": r.sign_time_ms,
            "verify_time_ms": r.verify_time_ms,
            "valid_pass": r.valid_pass,
            "tamper_detected": r.tamper_detected,
            "repetitions": r.repetitions,
            "environment_info": r.environment_info,
            "created_at": r.created_at.isoformat(),
        }
        for r in records
    ]


# ---------------------------------------------------------------------------
# API Routes: Upgraded Audit Trail & Verification Reports
# ---------------------------------------------------------------------------

@app.get("/api/audit-trail")
def audit_trail(
    event_type: str | None = None,
    result: str | None = None,
    q: str | None = None,
    db: Session = Depends(db_session),
):
    """
    Searchable, filterable audit ledger recording all signing, verification, and key events.
    Integrity guarantee: append-only SQLite table with server timestamps.
    """
    query = db.query(AuditEvent)
    if event_type and event_type != "ALL":
        query = query.filter(AuditEvent.event_type == event_type)
    if result and result != "ALL":
        query = query.filter(AuditEvent.result == result)
    if q:
        search_filter = or_(
            AuditEvent.filename.contains(q),
            AuditEvent.fingerprint.contains(q),
            AuditEvent.digest.contains(q),
            AuditEvent.reason_code.contains(q),
        )
        query = query.filter(search_filter)

    rows = query.order_by(AuditEvent.created_at.desc()).limit(300).all()
    return [
        {
            "id": r.id,
            "event_type": r.event_type,
            "filename": r.filename,
            "digest": r.digest,
            "fingerprint": r.fingerprint,
            "result": r.result,
            "reason_code": r.reason_code,
            "details": r.details,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@app.get("/api/history")
def legacy_history(
    q: str | None = None,
    result: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    db: Session = Depends(db_session),
):
    """Maintained for existing API & test compatibility."""
    query = db.query(VerificationEvent)
    if q:
        query = query.filter(VerificationEvent.filename.contains(q))
    if result in ("valid", "invalid"):
        query = query.filter(VerificationEvent.result == (result == "valid"))
    if date_from:
        query = query.filter(func.date(VerificationEvent.created_at) >= date_from)
    if date_to:
        query = query.filter(func.date(VerificationEvent.created_at) <= date_to)

    return [
        {
            "id": e.id,
            "filename": e.filename,
            "valid": e.result,
            "reason_code": e.reason_code,
            "digest": e.digest,
            "fingerprint": e.fingerprint,
            "created_at": e.created_at.isoformat(),
        }
        for e in query.order_by(VerificationEvent.created_at.desc()).limit(500)
    ]


@app.get("/api/documents")
def documents(db: Session = Depends(db_session)):
    return [
        {
            "id": d.id,
            "filename": d.filename,
            "sha256": d.sha256,
            "size": d.size,
            "created_at": d.created_at.isoformat(),
        }
        for d in db.query(Document).order_by(Document.created_at.desc()).limit(200)
    ]
