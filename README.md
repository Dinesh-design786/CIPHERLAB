# CipherLab // Zero
### ElGamal Digital Signature Verification System

An educational, high-integrity cryptography demonstration platform for digital signatures using the classic ElGamal signature scheme over an RFC 3526 MODP Group 14 safe prime (2048-bit). Includes a single-page cyberpunk workstation, interactive Tamper Detection Lab, step-by-step Algorithm Visualizer, downloadable verification reports, Key Vault with key rotation and revocation, append-only SQLite Audit Trail, and a repeatable Benchmark & Performance Lab.

> **Academic and Educational Implementation:** This project demonstrates the mathematical equations and integrity guarantees of ElGamal digital signatures. A valid signature mathematically verifies consistency with the supplied public key; it does not certify real-world human identity. Private key protection uses scrypt and AES-256-GCM at rest, but this local prototype does not include a hardware security module (HSM) or public key infrastructure (PKI). Run on localhost for academic study and evaluation.

---

## Architecture & Features

```
CipherLab // Zero
├── Frontend (React 19, TypeScript, Tailwind CSS v4, Vite, Lucide Icons)
│   ├── Single-Page Landing Workstation (No Multi-Page Transitions)
│   ├── Cyber Green (#00ff88) & Crimson Red (#ff2a55) High-Contrast HUD
│   ├── 3D Cyber Floating Keycard Mockup (Dynamic DB Metrics)
│   ├── Interactive Document Signer & Verifier
│   ├── Tamper Detection Lab (Single-Byte Modification & Avalanche Diff)
│   ├── ElGamal Algorithm Visualizer (Step-by-Step Educational Walkthrough)
│   ├── Key Vault (Lifecycle, Rotation, Revocation, AES-256-GCM + scrypt Export/Import)
│   ├── Audit Trail Ledger (Searchable & Filterable Event Stream)
│   └── Benchmark & Performance Lab (Real Empirical Measurements)
│
└── Backend (FastAPI, SQLite, SQLAlchemy 2.0, Cryptography)
    ├── crypto/elgamal.py: RFC 3526 Group 14 safe prime (2048-bit), g=2, SHA-256
    ├── db.py: SQLite models (PublicKey, Signature, Document, AuditEvent, BenchmarkRecord)
    └── main.py: REST endpoints, tamper simulations, key lifecycle, benchmark engine
```

---

## 1. Cryptographic Specifications & Equations

### Mathematical Foundation
- **Finite Field Safe Prime ($p$):** 2048-bit safe prime from RFC 3526 Group 14, where $p = 2q + 1$ ($q$ is prime).
  > *Note on RFC 3526:* RFC 3526 defines Modular Exponential (MODP) groups for Diffie–Hellman key exchange; this project utilizes the standardized Group 14 safe prime and generator as fixed public group parameters for ElGamal digital signatures.
- **Generator ($g$):** $g = 2$, which generates the quadratic residue subgroup of order $q = (p - 1) / 2$.
- **Message Digest ($h$):** $\text{SHA-256}(M)$, interpreted as an unsigned big-endian integer.

### Key Generation
1. Choose private exponent $x \in_R [1, q - 1]$ using OS cryptographic entropy (`secrets`).
2. Compute public exponent $y = g^x \bmod p$.
3. Public key is $(p, g, y)$; private key is $x$.
4. Public-key fingerprint is the canonical $\text{SHA-256}(\{"g": g, "p": p, "y": y\})$.

### Signing
1. Compute message digest $h = \text{int}(\text{SHA-256}(M))$.
2. Choose fresh random ephemeral nonce $k \in [2, p - 2]$ such that $\gcd(k, p - 1) = 1$.
3. Compute $r = g^k \bmod p$. (Ensure $r \notin \{0, 1\}$).
4. Compute $s = k^{-1}(h - xr) \bmod (p - 1)$ using the Extended Euclidean Algorithm.
5. The detached signature is $(r, s)$. Ephemeral nonce $k$ is immediately purged from memory.

### Verification
1. Validate public parameters: $p == P_{\text{Group14}}$, $g == 2$, $1 < y < p$, and $y^{(p-1)/2} \equiv 1 \pmod p$.
2. Verify range bounds: $0 < r < p$, $\gcd(r, p) == 1$, and $0 < s < p - 1$.
3. Compute $h = \text{int}(\text{SHA-256}(M))$.
4. Check verification equation:
   $$g^h \equiv y^r \cdot r^s \pmod p$$
   If LHS == RHS, the document signature is valid.

---

## 2. Interactive Features & Labs

### A. Tamper Detection Lab
- Demonstrates byte-level integrity verification.
- Users can sign a document and execute controlled single-byte modifications at an exact byte offset.
- Displays side-by-side byte diffs (Hex and ASCII), original vs. modified SHA-256 hashes, and verification outcome.
- Explains the cryptographic avalanche effect: altering a single bit in the document produces an uncorrelated SHA-256 digest, which breaks the equation $g^{h'} \not\equiv y^r r^s \pmod p$.

### B. ElGamal Algorithm Visualizer
- Step-by-step educational walkthrough using small toy parameters ($p = 467, g = 2$).
- Breaks down:
  1. Key generation ($x = 105, y = g^x \bmod p$)
  2. SHA-256 message hashing and integer mapping ($h$)
  3. Nonce selection ($k$) and Extended Euclidean modular inverse calculation ($k^{-1} \bmod (p - 1)$)
  4. Signature calculation ($r, s$)
  5. Verification equation evaluation ($g^h \bmod p$ vs. $y^r r^s \bmod p$)
  6. Tamper proof behavior demonstration

### C. Downloadable Verification Report
- Generates a structured JSON verification report containing:
  - Document filename and SHA-256 digest
  - Signature scheme and parameter details
  - Public-key fingerprint and key registry trust/revocation status
  - Verification outcome (`VALID`, `TAMPERED`, `INVALID_PACKAGE`)
  - Diagnostic reason codes (`valid`, `signature_mismatch`, `invalid_signature_component`, `invalid_package`)
  - Unique Report ID (UUID) and UTC timestamp
  - Explicit disclaimer separating mathematical validity from verified human identity

### D. Upgraded Key Vault & Lifecycle
- Private keys encrypted at rest using `scrypt` ($N=32768, r=8, p=1$) and AES-256-GCM with authenticated tags and random nonces.
- Protected JSON export and password-authenticated import.
- Key Revocation: Revoke compromised keys with required reason logging.
- Key Rotation: Retire old keys and establish new keypairs in one workflow.
- Clear separation between signing (requires private key passphrase) and verification (uses public key).

### E. Append-Only Audit Trail
- Stored in SQLite (`audit_events` table).
- Logs signing events, verification events, key generations, revocations, and rotations.
- Supports search by filename, hash, or fingerprint, and filtering by event type or outcome.
- Never logs private keys, passwords, or ephemeral nonces.

### F. Benchmark & Test Lab
- Measures actual runtime performance across payload sizes: 1 KB, 100 KB, and 1 MB.
- Reports:
  - SHA-256 hashing duration (ms)
  - ElGamal 2048-bit signing duration (ms)
  - ElGamal verification duration (ms)
  - Valid-signature acceptance rate (100%)
  - Tamper detection rate (100%)
- Records CPU, operating system, and runtime environment.

---

## 3. Local Setup & Execution

### Prerequisites
- Python 3.11+
- Node.js 20+

### Backend Setup & Execution
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Interactive API docs are available at <http://127.0.0.1:8000/docs>.

### Frontend Setup & Execution
```powershell
cd frontend
npm install
npm run dev
```
Open <http://localhost:5173> in your browser.

---

## 4. Automated Testing

### Backend Unit & Integration Tests (pytest)
```powershell
cd backend
python -m pytest -v
```
**Test Results: 21 / 21 Passed (100%)**
- `test_health`: API status and parameter checks
- `test_stats_structure`: Real database-backed statistics verification
- `test_key_generation_and_no_plaintext_leak`: Key creation and zero-plaintext leak audit
- `test_key_revocation_and_rotation`: Lifecycle status and revocation workflows
- `test_sign_verify_and_tamper_roundtrip`: End-to-end signing, verification, and tamper detection
- `test_verify_malformed_package`: Malformed package rejection
- `test_protected_key_import_and_wrong_password`: AES-256-GCM + scrypt export/import validation
- `test_tamper_lab_endpoint`: Single-byte modification and mathematical divergence
- `test_algorithm_simulation_endpoint`: Step-by-step modular arithmetic verification
- `test_benchmark_endpoint`: Real performance timing measurements
- `test_audit_trail_endpoint`: Audit ledger event logging and secret redaction
- `test_generate_consistency`: Keypair mathematical consistency
- `test_sign_verify_unchanged_and_changed`: Signature equation correctness
- `test_wrong_key_fails`: Unmatched public key rejection
- `test_corrupt_components_fail`: Corrupted component rejection
- `test_empty_file_and_fresh_nonces`: Nonce freshness and empty file support
- `test_invalid_key_and_signature_package`: Parameter boundary enforcement
- `test_fingerprint_stable`: Canonical fingerprint determinism
- `test_single_byte_tampering`: Controlled 1-bit and 1-byte alteration tests
- `test_toy_simulation_math`: Toy parameter step-by-step arithmetic verification
- `test_extended_gcd_and_inverse`: Extended Euclidean algorithm unit tests

### Frontend Component & Integration Tests (vitest)
```powershell
cd frontend
npm test
```
**Test Results: 3 / 3 Passed (100%)**
- Shows dashboard state when no activity exists
- Shows loading state and invalid verification result on tamper
- Shows useful API error on verification failure

### Production Build
```powershell
cd frontend
npm run build
```
Builds cleanly with zero TypeScript errors into `frontend/dist/`.
#   C I P H E R L A B  
 #   C I P H E R L A B  
 