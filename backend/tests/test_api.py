import io, json
import pytest
from fastapi import HTTPException, UploadFile
from app.main import (
    health,
    stats,
    make_key,
    import_key,
    revoke_key,
    rotate_key,
    list_keys,
    sign_document,
    verify_document,
    tamper_lab_run,
    algorithm_simulate,
    run_benchmark,
    audit_trail,
    GenerateRequest,
    ImportRequest,
    RevokeRequest,
    RotateRequest,
    BenchmarkRunRequest,
)
from app.db import SessionLocal

@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def make_upload_file(data: bytes, filename: str) -> UploadFile:
    stream = io.BytesIO(data)
    return UploadFile(file=stream, filename=filename, size=len(data))


def test_health():
    res = health()
    assert res["status"] == "ok"
    assert res["scheme"] == "ElGamal-SHA256"
    assert "RFC 3526" in res["parameters"]


def test_stats_structure(db):
    s = stats(db)
    assert "signed_documents" in s
    assert "valid" in s
    assert "tampered_documents" in s
    assert "malformed_packages" in s
    assert "active_keys" in s


def test_key_generation_and_no_plaintext_leak(db):
    req = GenerateRequest(label="Audit Test Key", password="correct horse battery")
    res = make_key(req, db=db)
    assert "id" in res
    assert "public_key" in res
    assert "fingerprint" in res
    assert res["status"] == "active"
    export = res["private_key_export"]
    assert export["encryption"] == "AES-256-GCM+scrypt"
    assert "ciphertext" in export

    # Ensure list_keys never returns private key material
    all_keys = list_keys(db=db)
    assert any(k["id"] == res["id"] for k in all_keys)
    for k in all_keys:
        assert "private" not in str(k).lower()
        assert "ciphertext" not in str(k).lower()


def test_key_revocation_and_rotation(db):
    req = GenerateRequest(label="To Revoke", password="correct horse battery")
    created = make_key(req, db=db)
    key_id = created["id"]

    # Revoke
    rev_req = RevokeRequest(key_id=key_id, reason="Testing key compromise protocol")
    rev_res = revoke_key(rev_req, db=db)
    assert rev_res["status"] == "revoked"
    assert rev_res["reason"] == "Testing key compromise protocol"

    # Verify key list reflects revoked status
    all_keys = list_keys(db=db)
    revoked_entry = next(k for k in all_keys if k["id"] == key_id)
    assert revoked_entry["status"] == "revoked"
    assert revoked_entry["active"] is False

    # Rotate another key
    gen_req2 = GenerateRequest(label="To Rotate", password="correct horse battery")
    created2 = make_key(gen_req2, db=db)
    rot_req = RotateRequest(
        old_key_id=created2["id"],
        new_label="Rotated Active Key",
        password="new passphrase secure 123",
    )
    rot_res = rotate_key(rot_req, db=db)
    assert rot_res["old_status"] == "retired"
    assert rot_res["new_key"]["label"] == "Rotated Active Key"


def test_sign_verify_and_tamper_roundtrip(db):
    # Create key
    created = make_key(
        GenerateRequest(label="Roundtrip Key", password="correct horse battery"), db=db
    )
    key_id = created["id"]

    # Sign file
    doc_bytes = b"Official digital asset transaction records"
    doc_upload = make_upload_file(doc_bytes, "records.txt")
    response_stream = sign_document(
        file=doc_upload, key_id=key_id, password="correct horse battery", db=db
    )
    package_bytes = getattr(response_stream, "package_bytes", b"")
    assert len(package_bytes) > 0

    # Verify original
    orig_file = make_upload_file(doc_bytes, "records.txt")
    orig_pack = make_upload_file(package_bytes, "signature-package.zip")
    verify_res = verify_document(file=orig_file, package=orig_pack, db=db)
    assert verify_res["valid"] is True
    assert verify_res["reason_code"] == "valid"
    assert "Integrity Confirmed" in verify_res["message"]

    # Verify tampered file
    tampered_bytes = b"Official digital asset transaction records!"
    tampered_file = make_upload_file(tampered_bytes, "records.txt")
    tampered_pack = make_upload_file(package_bytes, "signature-package.zip")
    tamper_res = verify_document(file=tampered_file, package=tampered_pack, db=db)
    assert tamper_res["valid"] is False
    assert tamper_res["reason_code"] == "signature_mismatch"
    assert "Tamper Detected" in tamper_res["message"]


def test_verify_malformed_package(db):
    doc_file = make_upload_file(b"content", "doc.txt")
    bad_pack = make_upload_file(b"{bad json", "signature.json")
    res = verify_document(file=doc_file, package=bad_pack, db=db)
    assert res["valid"] is False
    assert res["reason_code"] == "invalid_package"


def test_protected_key_import_and_wrong_password(db):
    generated = make_key(
        GenerateRequest(label="Export Source", password="correct horse battery"), db=db
    )
    export = generated["private_key_export"]

    # Import with correct password
    restored = import_key(
        ImportRequest(
            label="Restored Key",
            password="correct horse battery",
            private_key_export=export,
        ),
        db=db,
    )
    assert restored["public_key"] == generated["public_key"]
    assert restored["fingerprint"] == generated["fingerprint"]

    # Import with wrong password raises HTTPException 400
    with pytest.raises(HTTPException) as exc_info:
        import_key(
            ImportRequest(
                label="Bad Key",
                password="wrong passphrase here",
                private_key_export=export,
            ),
            db=db,
        )
    assert exc_info.value.status_code == 400


def test_tamper_lab_endpoint(db):
    created = make_key(
        GenerateRequest(label="Tamper Lab Key", password="correct horse battery"), db=db
    )
    file_upload = make_upload_file(b"A confidential report on cyber defense", "report.txt")
    lab_res = tamper_lab_run(
        file=file_upload,
        byte_offset=2,
        new_byte_val=ord("X"),
        key_id=created["id"],
        password="correct horse battery",
        db=db,
    )
    assert lab_res["original_file"]["verified"] is True
    assert lab_res["tampered_file"]["verified"] is False
    assert lab_res["tampered_file"]["reason_code"] == "signature_mismatch"
    assert lab_res["tamper_details"]["offset"] == 2
    assert "avalanche" in lab_res["mathematical_explanation"].lower()


def test_algorithm_simulation_endpoint():
    res = algorithm_simulate("Classroom Proof")
    assert "key_generation" in res
    assert "signing" in res
    assert "verification" in res
    assert res["verification"]["equations_equal"] is True


def test_benchmark_endpoint(db):
    res = run_benchmark(BenchmarkRunRequest(repetitions=1), db=db)
    assert "benchmarks" in res
    assert len(res["benchmarks"]) == 3
    for b in res["benchmarks"]:
        assert b["hash_time_ms"] >= 0
        assert b["sign_time_ms"] > 0
        assert b["verify_time_ms"] > 0
        assert b["valid_signature_pass_rate"] == 100.0
        assert b["tamper_detection_rate"] == 100.0


def test_audit_trail_endpoint(db):
    events = audit_trail(event_type="ALL", result="ALL", db=db)
    assert isinstance(events, list)
    assert len(events) > 0
    # Ensure no secret keys or passphrases leaked into audit details
    for ev in events:
        details_str = str(ev.get("details", "")).lower()
        assert "password" not in details_str
        assert "private_key" not in details_str
