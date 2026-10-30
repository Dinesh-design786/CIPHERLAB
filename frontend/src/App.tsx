import { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRightLeft,
  ArrowUpFromLine,
  Ban,
  BookOpen,
  Check,
  ChevronDown,
  Clock3,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  Eye,
  FileCheck2,
  FileKey2,
  Files,
  Flame,
  HelpCircle,
  KeyRound,
  Layers,
  LockKeyhole,
  Play,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  Zap,
  X
} from 'lucide-react';

const API = 'http://localhost:8000/api';

type Key = {
  id: number;
  label: string;
  fingerprint: string;
  public_key: { p: string; g: string; y: string };
  status: 'active' | 'revoked' | 'retired';
  revoked_at?: string;
  revocation_reason?: string;
  created_at: string;
  active: boolean;
};

async function request(path: string, options?: RequestInit) {
  const res = await fetch(API + path, options);
  if (!res.ok) {
    let e = 'Request failed';
    try {
      const data = await res.json();
      if (typeof data.detail === 'string') {
        e = data.detail;
      } else if (Array.isArray(data.detail)) {
        e = data.detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ');
      } else if (data.detail) {
        e = JSON.stringify(data.detail);
      }
    } catch {}
    throw new Error(e);
  }
  return res;
}

function Upload({
  label,
  onFile,
  accept,
  isRed,
}: {
  label: string;
  onFile: (f: File) => void;
  accept?: string;
  isRed?: boolean;
}) {
  const [drag, setDrag] = useState(false);
  return (
    <label
      className={`drop-zone ${isRed ? 'red-zone' : ''} ${drag ? 'drag' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDrag(false);
        if (e.dataTransfer.files[0]) onFile(e.dataTransfer.files[0]);
      }}
    >
      <input
        type="file"
        aria-label={label}
        accept={accept}
        onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])}
      />
      <span className={`drop-icon-circle ${isRed ? 'red' : ''}`}>
        <ArrowUpFromLine size={18} />
      </span>
      <b>{label}</b>
      <small>DRAG & DROP OR BROWSE · MAX 25 MiB</small>
    </label>
  );
}

export default function App() {
  // Global stats & keys
  const [stats, setStats] = useState<any>(null);
  const [keys, setKeys] = useState<Key[]>([]);

  // Signing state
  const [signFile, setSignFile] = useState<File | null>(null);
  const [selectedKey, setSelectedKey] = useState('');
  const [signPassword, setSignPassword] = useState('');
  const [signBusy, setSignBusy] = useState(false);
  const [signResult, setSignResult] = useState('');
  const [signError, setSignError] = useState('');

  // Verification state
  const [verifyDoc, setVerifyDoc] = useState<File | null>(null);
  const [verifyPack, setVerifyPack] = useState<File | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [verifyError, setVerifyError] = useState('');

  // Tamper Lab state
  const [tamperFile, setTamperFile] = useState<File | null>(null);
  const [tamperOffset, setTamperOffset] = useState<number>(0);
  const [tamperByteVal, setTamperByteVal] = useState<number>(88); // 'X'
  const [tamperKeyId, setTamperKeyId] = useState<string>('');
  const [tamperPassword, setTamperPassword] = useState<string>('');
  const [tamperBusy, setTamperBusy] = useState(false);
  const [tamperResult, setTamperResult] = useState<any>(null);
  const [tamperError, setTamperError] = useState('');

  // Visualizer state
  const [visMessage, setVisMessage] = useState('Educational Cryptography Demonstration');
  const [visBusy, setVisBusy] = useState(false);
  const [visResult, setVisResult] = useState<any>(null);

  // Key generator & vault state
  const [keyLabel, setKeyLabel] = useState('Primary Signing Key');
  const [keyPassword, setKeyPassword] = useState('');
  const [genBusy, setGenBusy] = useState(false);
  const [genError, setGenError] = useState('');
  const [exportJson, setExportJson] = useState('');

  // Key revocation modal
  const [revokeModalKey, setRevokeModalKey] = useState<Key | null>(null);
  const [revokeReason, setRevokeReason] = useState('Key compromised or superseded');
  const [revokeBusy, setRevokeBusy] = useState(false);

  // Key rotation modal
  const [rotateModalKey, setRotateModalKey] = useState<Key | null>(null);
  const [rotateLabel, setRotateLabel] = useState('Rotated Key');
  const [rotatePassword, setRotatePassword] = useState('');
  const [rotateBusy, setRotateBusy] = useState(false);

  // Key import state
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPassword, setImportPassword] = useState('');
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState('');

  // Audit trail state
  const [auditRows, setAuditRows] = useState<any[]>([]);
  const [searchQ, setSearchQ] = useState('');
  const [filterType, setFilterType] = useState('ALL');
  const [filterResult, setFilterResult] = useState('ALL');

  // Benchmark Lab state
  const [benchReps, setBenchReps] = useState(2);
  const [benchBusy, setBenchBusy] = useState(false);
  const [benchResult, setBenchResult] = useState<any>(null);

  const loadStats = () => {
    request('/stats')
      .then((r) => r.json())
      .then(setStats)
      .catch(() => {});
  };

  const loadKeys = () => {
    request('/keys')
      .then((r) => r.json())
      .then((data: Key[]) => {
        setKeys(data);
        if (!selectedKey && data.length > 0) {
          const active = data.find((k) => k.status === 'active');
          if (active) {
            setSelectedKey(String(active.id));
            setTamperKeyId(String(active.id));
          }
        }
      })
      .catch(() => {});
  };

  const loadAuditTrail = () => {
    request(`/audit-trail?event_type=${filterType}&result=${filterResult}&q=${encodeURIComponent(searchQ)}`)
      .then((r) => r.json())
      .then(setAuditRows)
      .catch(() => {});
  };

  useEffect(() => {
    loadStats();
    loadKeys();
  }, []);

  useEffect(() => {
    const t = setTimeout(loadAuditTrail, 200);
    return () => clearTimeout(t);
  }, [searchQ, filterType, filterResult]);

  // Handle Document Sign
  async function handleSign() {
    if (!signFile || !selectedKey || !signPassword) return;
    setSignBusy(true);
    setSignError('');
    try {
      const d = new FormData();
      d.append('file', signFile);
      d.append('key_id', selectedKey);
      d.append('password', signPassword);

      const r = await request('/sign', { method: 'POST', body: d });
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'signature-package.zip';
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);

      const sha = r.headers.get('X-Document-Sha256') || 'Signed successfully';
      setSignResult(sha);
      loadStats();
      loadAuditTrail();
    } catch (e: any) {
      setSignError(e.message);
    } finally {
      setSignBusy(false);
    }
  }

  // Handle Verification
  async function handleVerify() {
    if (!verifyDoc || !verifyPack) return;
    setVerifyBusy(true);
    setVerifyError('');
    setVerifyResult(null);
    try {
      const f = new FormData();
      f.append('file', verifyDoc);
      f.append('package', verifyPack);

      const r = await request('/verify', { method: 'POST', body: f });
      const res = await r.json();
      setVerifyResult(res);
      loadStats();
      loadAuditTrail();
    } catch (e: any) {
      setVerifyError(e.message);
    } finally {
      setVerifyBusy(false);
    }
  }

  // Handle Tamper Lab
  async function handleRunTamperLab() {
    if (!tamperKeyId || !tamperPassword) {
      setTamperError('Please select an unlocked signing key and enter its passphrase.');
      return;
    }
    setTamperBusy(true);
    setTamperError('');
    setTamperResult(null);
    try {
      const form = new FormData();
      if (tamperFile) {
        form.append('file', tamperFile);
      } else {
        const defaultSample = new File(
          ['Confidential payload for tamper detection analysis.'],
          'sample_audit_document.txt',
          { type: 'text/plain' }
        );
        form.append('file', defaultSample);
      }
      form.append('byte_offset', String(tamperOffset));
      form.append('new_byte_val', String(tamperByteVal));
      form.append('key_id', tamperKeyId);
      form.append('password', tamperPassword);

      const r = await request('/tamper-lab/run', { method: 'POST', body: form });
      const res = await r.json();
      setTamperResult(res);
      loadStats();
      loadAuditTrail();
    } catch (e: any) {
      setTamperError(e.message);
    } finally {
      setTamperBusy(false);
    }
  }

  // Handle Algorithm Simulation
  async function handleRunSimulation() {
    setVisBusy(true);
    try {
      const r = await request(`/algorithm/simulate?message=${encodeURIComponent(visMessage)}`);
      const res = await r.json();
      setVisResult(res);
    } catch {}
    finally {
      setVisBusy(false);
    }
  }

  // Handle Key Generation
  async function handleGenerateKey() {
    if (keyPassword.length < 10 || !keyLabel) return;
    setGenBusy(true);
    setGenError('');
    try {
      const r = await request('/keys/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: keyLabel, password: keyPassword }),
      });
      const data = await r.json();
      setExportJson(JSON.stringify(data.private_key_export, null, 2));
      setKeyPassword('');
      loadKeys();
      loadStats();
      loadAuditTrail();
    } catch (e: any) {
      setGenError(e.message);
    } finally {
      setGenBusy(false);
    }
  }

  // Handle Key Revocation
  async function handleRevokeKey() {
    if (!revokeModalKey || !revokeReason) return;
    setRevokeBusy(true);
    try {
      await request('/keys/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key_id: revokeModalKey.id, reason: revokeReason }),
      });
      setRevokeModalKey(null);
      loadKeys();
      loadStats();
      loadAuditTrail();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setRevokeBusy(false);
    }
  }

  // Handle Key Rotation
  async function handleRotateKey() {
    if (!rotateModalKey || rotatePassword.length < 10) return;
    setRotateBusy(true);
    try {
      const r = await request('/keys/rotate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          old_key_id: rotateModalKey.id,
          new_label: rotateLabel,
          password: rotatePassword,
        }),
      });
      const res = await r.json();
      setExportJson(JSON.stringify(res.private_key_export, null, 2));
      setRotateModalKey(null);
      setRotatePassword('');
      loadKeys();
      loadStats();
      loadAuditTrail();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setRotateBusy(false);
    }
  }

  // Handle Key Import
  async function handleImportKey() {
    if (!importFile || !importPassword) return;
    setImportBusy(true);
    setImportError('');
    try {
      const private_key_export = JSON.parse(await importFile.text());
      const label = importFile.name.replace(/\.json$/i, '').slice(0, 160) || 'Imported Key';
      await request('/keys/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, password: importPassword, private_key_export }),
      });
      setImportFile(null);
      setImportPassword('');
      loadKeys();
      loadStats();
      loadAuditTrail();
    } catch (e: any) {
      setImportError(e.message || 'Could not import key');
    } finally {
      setImportBusy(false);
    }
  }

  // Handle Benchmark Run
  async function handleRunBenchmarks() {
    setBenchBusy(true);
    try {
      const r = await request('/benchmarks/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repetitions: benchReps }),
      });
      const res = await r.json();
      setBenchResult(res);
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBenchBusy(false);
    }
  }

  function downloadReport(reportData: any) {
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `verification-report-${reportData.report_id || Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function downloadKeyExport() {
    const blob = new Blob([exportJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'elgamal-encrypted-private-key.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <div className="app-shell">
      {/* Top Header Bar */}
      <header className="top-nav">
        <div className="brand-group">
          <div className="brand-icon">
            <Zap size={22} fill="currentColor" />
          </div>
          <div className="brand-text">
            <span className="brand-title">
              CIPHER<span className="g">LAB</span> // <span className="r">ZERO</span>
            </span>
            <span className="brand-subtitle">ELGAMAL DIGITAL SIGNATURE VERIFICATION SYSTEM</span>
          </div>
        </div>

        <nav className="nav-links">
          <a href="#workstation" className="nav-anchor">Workstation</a>
          <a href="#tamper-lab" className="nav-anchor">Tamper Lab</a>
          <a href="#visualizer" className="nav-anchor">Visualizer</a>
          <a href="#key-vault" className="nav-anchor">Key Vault</a>
          <a href="#audit-trail" className="nav-anchor">Audit Trail</a>
          <a href="#benchmarks" className="nav-anchor">Benchmark Lab</a>
          <a href="#specs" className="nav-anchor">Specs & Limits</a>
        </nav>

        <div className="nav-status">
          <div className="status-pill-header">
            <span className="status-dot" />
            <span>NODE ONLINE</span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="page-container">
        {/* Hero Section */}
        <section className="hero-section">
          <div className="hero-tag">
            <Terminal size={12} />
            CRYPTOGRAPHIC DOCUMENT INTEGRITY
          </div>

          <h1 className="hero-title">
            DOCUMENT <span className="g">INTEGRITY</span> // <span className="r">VERIFIED</span>
          </h1>

          <p className="hero-description">
            Evaluate detached ElGamal digital signatures against SHA-256 message digests using RFC 3526 MODP Group 14 safe prime parameters. Detect single-byte alterations and inspect the underlying discrete logarithm mathematics.
          </p>

          <div className="hero-btn-row">
            <a href="#sign-box" className="btn primary">
              <FileCheck2 size={16} /> Sign Document
            </a>
            <a href="#verify-box" className="btn danger">
              <ShieldCheck size={16} /> Verify Signature
            </a>
            <a href="#tamper-lab" className="btn ghost">
              <Flame size={16} /> Tamper Lab
            </a>
            <a href="#visualizer" className="btn ghost">
              <Eye size={16} /> Visualizer
            </a>
          </div>

          {/* 3D Floating Mockup Device - Accurate Live Database Status */}
          <div className="hero-mockup-wrapper">
            <div className="cyber-phone">
              <div className="phone-island" />
              <div className="phone-header">
                <div className="phone-brand">
                  <Zap size={14} fill="#000" /> cipherlab
                </div>
                <div className="phone-badge">GROUP 14 · 2048-BIT</div>
              </div>

              <div className="phone-balance-block">
                <div className="phone-balance-label">VALIDATED PROOFS</div>
                <div className="phone-balance-val">
                  {stats?.valid !== undefined ? stats.valid : 0}
                </div>
              </div>

              <div className="phone-key-card">
                <div className="phone-key-top">
                  <span>KEYS ACTIVE: {stats?.active_keys !== undefined ? stats.active_keys : 0}</span>
                  <span>ELGAMAL</span>
                </div>
                <div className="phone-key-btns">
                  <a href="#sign-box" className="phone-btn-action dark">
                    SIGN ↗
                  </a>
                  <a href="#verify-box" className="phone-btn-action bright">
                    VERIFY ↘
                  </a>
                </div>
              </div>
            </div>
          </div>

          <div className="hero-footer-bar">
            <span>
              GROUP: <b className="g">RFC 3526 MODP 14 (2048-BIT)</b>
            </span>
            <span>
              GENERATOR: <b className="g">g = 2</b>
            </span>
            <span>
              DIGEST: <b className="r">SHA-256</b>
            </span>
          </div>
        </section>

        {/* Live Cryptographic Telemetry Grid (Connected to Real DB) */}
        <section className="stat-grid">
          <div className="stat-card green-card">
            <div className="stat-header">
              <span className="stat-icon green">
                <FileCheck2 size={20} />
              </span>
              <span className="stat-value">{stats?.signed_documents ?? 0}</span>
            </div>
            <b className="stat-title">Documents Signed</b>
            <small className="stat-meta">Recorded signatures in SQLite</small>
          </div>

          <div className="stat-card green-card">
            <div className="stat-header">
              <span className="stat-icon green">
                <ShieldCheck size={20} />
              </span>
              <span className="stat-value">{stats?.valid ?? 0}</span>
            </div>
            <b className="stat-title">Valid Proofs</b>
            <small className="stat-meta">Passed equation gʰ ≡ yʳ · rˢ (mod p)</small>
          </div>

          <div className="stat-card red-card">
            <div className="stat-header">
              <span className="stat-icon red">
                <Flame size={20} />
              </span>
              <span className="stat-value">{stats?.tampered_documents ?? 0}</span>
            </div>
            <b className="stat-title">Tamper Detections</b>
            <small className="stat-meta">Confirmed byte alterations</small>
          </div>

          <div className="stat-card green-card">
            <div className="stat-header">
              <span className="stat-icon green">
                <KeyRound size={20} />
              </span>
              <span className="stat-value">{stats?.active_keys ?? 0}</span>
            </div>
            <b className="stat-title">Active Public Keys</b>
            <small className="stat-meta">
              {stats?.revoked_keys ? `${stats.revoked_keys} revoked` : 'Encrypted with scrypt'}
            </small>
          </div>
        </section>

        {/* 1. Workstation: Sign & Verify */}
        <section id="workstation" className="section-wrapper">
          <div className="section-header">
            <div>
              <div className="section-tag">
                <Zap size={12} /> CRYPTOGRAPHIC WORKSTATION
              </div>
              <h2 className="section-title">Sign & Verify Terminal</h2>
              <p className="section-desc">
                Generate detached ElGamal signature packages or evaluate document bytes against public keys.
              </p>
            </div>
          </div>

          <div className="workstation-grid">
            {/* SIGN DOCUMENT COLUMN */}
            <div id="sign-box" className="workstation-card">
              <div className="card-top-indicator">
                <span className="card-badge green">
                  <FileKey2 size={13} /> SIGNING MODULE (REQUIRES PRIVATE KEY)
                </span>
                <span style={{ fontSize: 11, fontFamily: 'ui-monospace, monospace', color: 'var(--text-dim)' }}>
                  AES-256-GCM + SCRYPT
                </span>
              </div>

              <h3 style={{ fontSize: 18, fontWeight: 900, textTransform: 'uppercase', margin: '0 0 4px', color: '#fff' }}>
                Sign Document
              </h3>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '0 0 16px' }}>
                Unlock private key in memory to compute signature components (r, s).
              </p>

              <Upload label="Choose a document to sign" onFile={setSignFile} />

              {signFile && (
                <div className="file-chip">
                  <Files size={16} />
                  <div>
                    <b>{signFile.name}</b>
                    <small>
                      {(signFile.size / 1024).toFixed(1)} KB · SHA-256{' '}
                      {signFile.size === 0 ? 'empty file supported' : ''}
                    </small>
                  </div>
                  <button onClick={() => setSignFile(null)}>
                    <X size={16} />
                  </button>
                </div>
              )}

              <label className="field-label">SIGNING PRIVATE KEY (IDENTITY)</label>
              <select
                className="input-cyber"
                value={selectedKey}
                onChange={(e) => setSelectedKey(e.target.value)}
              >
                <option value="">Select an active key</option>
                {keys
                  .filter((k) => k.status === 'active')
                  .map((k) => (
                    <option value={k.id} key={k.id}>
                      {k.label} · Fingerprint: {k.fingerprint.slice(0, 16)}…
                    </option>
                  ))}
              </select>
              {!keys.some((k) => k.status === 'active') && (
                <div className="field-note">
                  No active keys found. <a href="#key-vault" style={{ color: 'var(--green)' }}>Generate a key below</a>.
                </div>
              )}

              <label className="field-label">PASSPHRASE (DECRYPTS PRIVATE KEY)</label>
              <input
                className="input-cyber"
                type="password"
                value={signPassword}
                onChange={(e) => setSignPassword(e.target.value)}
                placeholder="Passphrase used during key generation"
              />
              <div className="field-note">
                Passphrase derives AES key with scrypt to decrypt private exponent x. Never logged.
              </div>

              {signError && <div className="alert-box error">{signError}</div>}
              {signResult && (
                <div className="alert-box success">
                  <Check size={18} />
                  <div>
                    <b>Signature package generated & downloaded!</b>
                    <small>SHA-256: {signResult}</small>
                  </div>
                </div>
              )}

              <button
                className="btn primary full"
                disabled={!signFile || !selectedKey || !signPassword || signBusy}
                onClick={handleSign}
              >
                {signBusy ? (
                  <>
                    <span className="spinner" /> Signing…
                  </>
                ) : (
                  <>
                    <FileKey2 size={18} /> Sign & Download Package (.zip)
                  </>
                )}
              </button>
            </div>

            {/* VERIFY SIGNATURE COLUMN */}
            <div id="verify-box" className="workstation-card verify-card">
              <div className="card-top-indicator">
                <span className="card-badge red">
                  <ShieldCheck size={13} /> VERIFIER ENGINE (USES PUBLIC KEY)
                </span>
                <span style={{ fontSize: 11, fontFamily: 'ui-monospace, monospace', color: 'var(--text-dim)' }}>
                  gʰ ≡ yʳ · rˢ (mod p)
                </span>
              </div>

              <h3 style={{ fontSize: 18, fontWeight: 900, textTransform: 'uppercase', margin: '0 0 4px', color: '#fff' }}>
                Verify Signature
              </h3>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '0 0 16px' }}>
                Evaluate mathematical consistency between document bytes and signature package.
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label className="field-label" style={{ marginTop: 0 }}>DOCUMENT</label>
                  <Upload label="Select document" onFile={setVerifyDoc} />
                  {verifyDoc && (
                    <small style={{ color: 'var(--green)', fontFamily: 'ui-monospace, monospace', fontSize: 10, display: 'block', marginTop: 4 }}>
                      {verifyDoc.name}
                    </small>
                  )}
                </div>
                <div>
                  <label className="field-label" style={{ marginTop: 0 }}>SIGNATURE PACKAGE</label>
                  <Upload label="Select .zip or .json" accept=".zip,.json" onFile={setVerifyPack} isRed />
                  {verifyPack && (
                    <small style={{ color: 'var(--red)', fontFamily: 'ui-monospace, monospace', fontSize: 10, display: 'block', marginTop: 4 }}>
                      {verifyPack.name}
                    </small>
                  )}
                </div>
              </div>

              {verifyError && <div className="alert-box error">{verifyError}</div>}

              <button
                className="btn danger full"
                disabled={!verifyDoc || !verifyPack || verifyBusy}
                onClick={handleVerify}
              >
                {verifyBusy ? (
                  <>
                    <span className="spinner" /> Verifying…
                  </>
                ) : (
                  <>
                    <ShieldCheck size={18} /> Verify signature
                  </>
                )}
              </button>

              {/* Dynamic Verification Result Output */}
              {verifyResult && (
                <div className={`verify-result-panel ${verifyResult.valid ? 'good' : 'bad'}`}>
                  <div className="result-badge-row">
                    <div className={`result-icon-badge ${verifyResult.valid ? 'good' : 'bad'}`}>
                      {verifyResult.valid ? <Check size={22} /> : <X size={22} />}
                    </div>
                    <div>
                      <h4 className="result-title">
                        {verifyResult.valid ? 'Signature is valid' : 'Signature is invalid'}
                      </h4>
                      <p className="result-message">{verifyResult.message}</p>
                    </div>
                  </div>

                  <div className="result-specs-grid">
                    <small>REASON CODE</small>
                    <b>{verifyResult.reason_code}</b>

                    <small>CALCULATED SHA-256</small>
                    <b className="hash">{verifyResult.digest}</b>

                    <small>EXPECTED PACKAGE DIGEST</small>
                    <b className="hash">{verifyResult.package_digest || 'N/A'}</b>

                    <small>PUBLIC KEY FINGERPRINT</small>
                    <b className="hash">{verifyResult.fingerprint || 'Unavailable'}</b>

                    <small>KEY REGISTRY STATUS</small>
                    <b>
                      {verifyResult.key_status === 'revoked' ? (
                        <span style={{ color: 'var(--red)' }}>REVOKED KEY IN REGISTRY</span>
                      ) : (
                        <span style={{ color: 'var(--green)' }}>ACTIVE / TRUSTED KEY</span>
                      )}
                    </b>
                  </div>

                  <div style={{ marginTop: 14, display: 'flex', gap: 10 }}>
                    <button
                      className="btn ghost"
                      style={{ padding: '8px 14px', fontSize: 11 }}
                      onClick={() => downloadReport(verifyResult)}
                    >
                      <Download size={14} /> Download Verification Report (.json)
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* 2. Tamper Detection Lab (Educational Interactive) */}
        <section id="tamper-lab" className="section-wrapper">
          <div className="section-header">
            <div>
              <div className="section-tag red-tag">
                <Flame size={12} /> TAMPER DETECTION LAB
              </div>
              <h2 className="section-title">Single-Byte Modification Experiment</h2>
              <p className="section-desc">
                Observe the SHA-256 avalanche effect and mathematical proof failure by altering exactly one byte of a signed file.
              </p>
            </div>
          </div>

          <div className="cyber-panel">
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 24 }}>
              <div>
                <h4 style={{ fontSize: 15, fontWeight: 900, textTransform: 'uppercase', color: '#fff', margin: '0 0 6px' }}>
                  1. Setup Test Document & Tamper Target
                </h4>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '0 0 16px' }}>
                  Upload a document or leave blank to test with a built-in educational text file.
                </p>

                <Upload label="Upload sample document (optional)" onFile={setTamperFile} />
                {tamperFile && (
                  <div className="file-chip">
                    <Files size={16} />
                    <b>{tamperFile.name}</b>
                    <small>{(tamperFile.size / 1024).toFixed(1)} KB</small>
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 14 }}>
                  <div>
                    <label className="field-label" style={{ marginTop: 0 }}>BYTE OFFSET TO MODIFY</label>
                    <input
                      className="input-cyber"
                      type="number"
                      min={0}
                      value={tamperOffset}
                      onChange={(e) => setTamperOffset(Number(e.target.value))}
                    />
                    <div className="field-note">Index of byte to tamper (0 = first byte)</div>
                  </div>
                  <div>
                    <label className="field-label" style={{ marginTop: 0 }}>NEW BYTE VALUE (0-255)</label>
                    <input
                      className="input-cyber"
                      type="number"
                      min={0}
                      max={255}
                      value={tamperByteVal}
                      onChange={(e) => setTamperByteVal(Number(e.target.value))}
                    />
                    <div className="field-note">ASCII: {String.fromCharCode(tamperByteVal)} (0x{tamperByteVal.toString(16).toUpperCase()})</div>
                  </div>
                </div>

                <label className="field-label">SIGNING PRIVATE KEY</label>
                <select
                  className="input-cyber"
                  value={tamperKeyId}
                  onChange={(e) => setTamperKeyId(e.target.value)}
                >
                  <option value="">Select key</option>
                  {keys.map((k) => (
                    <option value={k.id} key={k.id}>
                      {k.label} ({k.status})
                    </option>
                  ))}
                </select>

                <label className="field-label">KEY PASSPHRASE</label>
                <input
                  className="input-cyber"
                  type="password"
                  value={tamperPassword}
                  onChange={(e) => setTamperPassword(e.target.value)}
                  placeholder="Passphrase to sign original file"
                />

                {tamperError && <div className="alert-box error">{tamperError}</div>}

                <button
                  className="btn danger full"
                  disabled={!tamperKeyId || !tamperPassword || tamperBusy}
                  onClick={handleRunTamperLab}
                >
                  {tamperBusy ? 'Executing Tamper Protocol…' : 'Execute Tamper Protocol'}
                </button>
              </div>

              {/* Tamper Results View */}
              <div>
                <h4 style={{ fontSize: 15, fontWeight: 900, textTransform: 'uppercase', color: '#fff', margin: '0 0 6px' }}>
                  2. Mathematical & Byte Divergence
                </h4>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '0 0 16px' }}>
                  Side-by-side comparison of original vs single-byte tampered payload.
                </p>

                {tamperResult ? (
                  <div>
                    <div className="tamper-diff-grid">
                      <div className="diff-card orig">
                        <span className="card-badge green">ORIGINAL FILE</span>
                        <div className="byte-highlight-row">
                          <span>BYTE @ {tamperResult.tamper_details.offset}:</span>
                          <span className="byte-box orig">
                            {tamperResult.tamper_details.original_byte_hex} ('{tamperResult.tamper_details.original_byte_char}')
                          </span>
                        </div>
                        <div style={{ fontSize: 10, fontFamily: 'ui-monospace, monospace', color: 'var(--green)', wordBreak: 'break-all' }}>
                          SHA-256: {tamperResult.original_file.sha256}
                        </div>
                        <div style={{ marginTop: 8 }}>
                          <span className="status-badge valid">VERIFICATION: VALID (100%)</span>
                        </div>
                      </div>

                      <div className="diff-card mod">
                        <span className="card-badge red">MODIFIED COPY</span>
                        <div className="byte-highlight-row">
                          <span>BYTE @ {tamperResult.tamper_details.offset}:</span>
                          <span className="byte-box mod">
                            {tamperResult.tamper_details.modified_byte_hex} ('{tamperResult.tamper_details.modified_byte_char}')
                          </span>
                        </div>
                        <div style={{ fontSize: 10, fontFamily: 'ui-monospace, monospace', color: 'var(--red)', wordBreak: 'break-all' }}>
                          SHA-256: {tamperResult.tampered_file.sha256}
                        </div>
                        <div style={{ marginTop: 8 }}>
                          <span className="status-badge invalid">VERIFICATION: REJECTED (0%)</span>
                        </div>
                      </div>
                    </div>

                    <div className="explanation-callout">
                      <b>CRYPTOGRAPHIC ANALYSIS:</b>
                      <p style={{ margin: '6px 0 0' }}>{tamperResult.mathematical_explanation}</p>
                    </div>

                    <button
                      className="btn ghost"
                      style={{ marginTop: 14, width: '100%', fontSize: 11 }}
                      onClick={() => downloadReport(tamperResult)}
                    >
                      <Download size={14} /> Download Tamper Investigation Report (.json)
                    </button>
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '60px 20px', border: '1px dashed var(--border-subtle)', borderRadius: 14 }}>
                    <Flame size={32} style={{ color: 'var(--red)', margin: '0 auto 10px', display: 'block' }} />
                    <b>Ready for Tamper Experiment</b>
                    <p style={{ fontSize: 11, color: 'var(--text-dim)', margin: '6px 0 0' }}>
                      Configure the target byte offset and run the experiment to inspect before-and-after hashes.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* 3. ElGamal Algorithm Visualizer */}
        <section id="visualizer" className="section-wrapper">
          <div className="section-header">
            <div>
              <div className="section-tag">
                <Eye size={12} /> ALGORITHM VISUALIZER
              </div>
              <h2 className="section-title">Step-by-Step Educational Simulation</h2>
              <p className="section-desc">
                Inspect key generation, nonce selection, modular inverse, signing, and verification using transparent toy parameters (p=467, g=2).
              </p>
            </div>
          </div>

          <div className="cyber-panel">
            <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', marginBottom: 20 }}>
              <div style={{ flex: 1 }}>
                <label className="field-label" style={{ marginTop: 0 }}>SAMPLE MESSAGE FOR SIMULATION</label>
                <input
                  className="input-cyber"
                  value={visMessage}
                  onChange={(e) => setVisMessage(e.target.value)}
                  placeholder="Enter message to sign"
                />
              </div>
              <button className="btn primary" onClick={handleRunSimulation} disabled={visBusy}>
                {visBusy ? 'Computing…' : 'Simulate Algorithm Steps'}
              </button>
            </div>

            {visResult && (
              <div className="visualizer-stepper">
                {/* Step 1 */}
                <div className="step-card">
                  <div className="step-num-badge">STEP 1: PUBLIC PARAMETERS & KEY GENERATION</div>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                    Select safe prime p=467 with generator g=2. Secret exponent x is chosen in [1, (p-1)/2].
                  </p>
                  <div className="step-formula-box">
                    p = {visResult.parameters.p}, g = {visResult.parameters.g}, p - 1 = {visResult.parameters.p_minus_1}<br />
                    Private Key x = {visResult.key_generation.private_key_x}<br />
                    Public Key y = {visResult.key_generation.public_key_y_formula} = {visResult.key_generation.public_key_y}
                  </div>
                </div>

                {/* Step 2 */}
                <div className="step-card">
                  <div className="step-num-badge">STEP 2: MESSAGE HASHING</div>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                    Compute SHA-256 digest of document bytes and map into multiplicative group integer h.
                  </p>
                  <div className="step-formula-box">
                    SHA-256("{visResult.hashing.original_message}") = {visResult.hashing.sha256_hex}<br />
                    Digest Integer h = {visResult.hashing.digest_int_h}
                  </div>
                </div>

                {/* Step 3 */}
                <div className="step-card">
                  <div className="step-num-badge">STEP 3: NONCE SELECTION & MODULAR INVERSE</div>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                    Generate fresh ephemeral nonce k coprime to p-1, and compute modular inverse k⁻¹ mod (p-1) using Extended Euclidean Algorithm.
                  </p>
                  <div className="step-formula-box">
                    Ephemeral Nonce k = {visResult.signing.ephemeral_nonce_k} (gcd(k, p-1) = {visResult.signing.gcd_k_q})<br />
                    k⁻¹ mod (p-1) = {visResult.signing.k_inverse_mod_q}
                  </div>
                </div>

                {/* Step 4 */}
                <div className="step-card">
                  <div className="step-num-badge">STEP 4: SIGNATURE GENERATION (r, s)</div>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                    Calculate signature components r = gᵏ mod p and s = k⁻¹(h - xr) mod (p-1).
                  </p>
                  <div className="step-formula-box">
                    r = {visResult.signing.component_r_formula} = {visResult.signing.component_r}<br />
                    s = {visResult.signing.component_s_formula} = {visResult.signing.component_s}<br />
                    Signature Output = (r = {visResult.signing.component_r}, s = {visResult.signing.component_s})
                  </div>
                </div>

                {/* Step 5 */}
                <div className="step-card">
                  <div className="step-num-badge">STEP 5: SIGNATURE VERIFICATION EQUATION</div>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                    Verifier checks whether gʰ ≡ yʳ · rˢ (mod p) without knowing private key x or nonce k.
                  </p>
                  <div className="step-formula-box">
                    LHS (gʰ mod p) = {visResult.verification.lhs_v1_formula} = {visResult.verification.lhs_v1}<br />
                    RHS ((yʳ · rˢ) mod p) = {visResult.verification.rhs_v2_formula} = {visResult.verification.rhs_v2}<br />
                    Check: {visResult.verification.lhs_v1} == {visResult.verification.rhs_v2} ➔ <b>{visResult.verification.outcome}</b>
                  </div>
                </div>

                {/* Step 6 */}
                <div className="step-card" style={{ borderColor: 'var(--border-red)' }}>
                  <div className="step-num-badge" style={{ color: 'var(--red)' }}>STEP 6: TAMPER BEHAVIOR PROOF</div>
                  <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
                    Appending '!' changes hash to h_tampered = {visResult.tamper_simulation.tampered_digest_h}.
                  </p>
                  <div className="step-formula-box" style={{ borderColor: 'var(--border-red)', color: 'var(--red)' }}>
                    LHS_tampered (g^(h_tampered) mod p) = {visResult.tamper_simulation.tampered_v1}<br />
                    RHS ((yʳ · rˢ) mod p) = {visResult.tamper_simulation.tampered_v2}<br />
                    Check: {visResult.tamper_simulation.tampered_v1} != {visResult.tamper_simulation.tampered_v2} ➔ <b>{visResult.tamper_simulation.outcome}</b>
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* 4. Upgraded Key Vault */}
        <section id="key-vault" className="section-wrapper">
          <div className="section-header">
            <div>
              <div className="section-tag">
                <KeyRound size={12} /> KEY VAULT & LIFECYCLE
              </div>
              <h2 className="section-title">Cryptographic Keyring</h2>
              <p className="section-desc">
                Generate 2048-bit keypairs, manage key rotation, revoke compromised keys, or import encrypted backups.
              </p>
            </div>
          </div>

          <div className="cyber-panel">
            <div className="key-generator-grid">
              {/* Generate Key */}
              <div>
                <h4 style={{ fontSize: 15, fontWeight: 900, textTransform: 'uppercase', color: '#fff', margin: '0 0 6px' }}>
                  Generate New Keypair
                </h4>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '0 0 16px' }}>
                  Private key material is encrypted at rest using scrypt (N=32768) and AES-256-GCM.
                </p>

                <label className="field-label">KEY LABEL</label>
                <input
                  className="input-cyber"
                  value={keyLabel}
                  onChange={(e) => setKeyLabel(e.target.value)}
                  maxLength={160}
                />

                <label className="field-label">EXPORT & STORAGE PASSPHRASE</label>
                <input
                  className="input-cyber"
                  type="password"
                  value={keyPassword}
                  onChange={(e) => setKeyPassword(e.target.value)}
                  placeholder="Minimum 10 characters"
                />

                {genError && <div className="alert-box error">{genError}</div>}

                <button
                  className="btn primary full"
                  disabled={genBusy || keyPassword.length < 10 || !keyLabel}
                  onClick={handleGenerateKey}
                >
                  {genBusy ? 'Generating…' : 'Generate Keypair'}
                </button>

                {exportJson && (
                  <div className="alert-box success" style={{ display: 'grid', marginTop: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Check size={16} />
                      <b>Key generated! Store your encrypted JSON backup.</b>
                    </div>
                    <button
                      className="btn ghost"
                      style={{ marginTop: 10, alignSelf: 'start', padding: '8px 14px' }}
                      onClick={downloadKeyExport}
                    >
                      <ArrowDownToLine size={14} /> Download Encrypted Export (.json)
                    </button>
                  </div>
                )}
              </div>

              {/* Import Key */}
              <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: 28 }}>
                <h4 style={{ fontSize: 15, fontWeight: 900, textTransform: 'uppercase', color: '#fff', margin: '0 0 6px' }}>
                  Import Protected Key
                </h4>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '0 0 16px' }}>
                  Restore an encrypted private key using its JSON export file and passphrase.
                </p>

                <label className="field-label" htmlFor="import-key-file">
                  ENCRYPTED JSON FILE
                </label>
                <input
                  id="import-key-file"
                  className="input-cyber"
                  style={{ height: 'auto', padding: '10px' }}
                  type="file"
                  accept=".json,application/json"
                  onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                />

                <label className="field-label" htmlFor="import-pwd">
                  EXPORT PASSPHRASE
                </label>
                <input
                  id="import-pwd"
                  className="input-cyber"
                  type="password"
                  value={importPassword}
                  onChange={(e) => setImportPassword(e.target.value)}
                  placeholder="Enter the passphrase"
                />

                {importError && <div className="alert-box error">{importError}</div>}

                <button
                  className="btn ghost full"
                  disabled={!importFile || !importPassword || importBusy}
                  onClick={handleImportKey}
                >
                  {importBusy ? 'Importing…' : 'Restore Protected Key'}
                </button>
              </div>
            </div>

            {/* Public Key List with Lifecycle & Revocation Actions */}
            <div style={{ marginTop: 32, paddingTop: 20, borderTop: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <h4 style={{ fontSize: 14, fontWeight: 900, textTransform: 'uppercase', color: '#fff', margin: 0 }}>
                  Active Keyring ({keys.length})
                </h4>
                <span className="card-badge green">PUBLIC KEY REGISTRY</span>
              </div>

              {keys.length ? (
                keys.map((k) => (
                  <div className="key-item-row" key={k.id}>
                    <div className="key-avatar">
                      <KeyRound size={18} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <b>{k.label}</b>
                        <span
                          className={`status-badge ${
                            k.status === 'active' ? 'valid' : k.status === 'revoked' ? 'invalid' : ''
                          }`}
                          style={{
                            background: k.status === 'retired' ? 'rgba(255,255,255,0.08)' : undefined,
                            color: k.status === 'retired' ? '#aaa' : undefined,
                          }}
                        >
                          {k.status.toUpperCase()}
                        </span>
                      </div>
                      <small style={{ display: 'block', margin: '3px 0' }}>
                        Created {new Date(k.created_at).toLocaleString()}
                        {k.revoked_at && ` · Revoked: ${new Date(k.revoked_at).toLocaleString()}`}
                        {k.revocation_reason && ` (${k.revocation_reason})`}
                      </small>
                      <code>Fingerprint: {k.fingerprint}</code>
                    </div>

                    <div style={{ display: 'flex', gap: 8 }}>
                      {k.status === 'active' && (
                        <>
                          <button
                            className="btn ghost"
                            style={{ padding: '6px 12px', fontSize: 10 }}
                            onClick={() => {
                              setRotateModalKey(k);
                              setRotateLabel(`${k.label} (Rotated)`);
                            }}
                          >
                            <ArrowRightLeft size={13} /> Rotate
                          </button>
                          <button
                            className="btn danger"
                            style={{ padding: '6px 12px', fontSize: 10 }}
                            onClick={() => setRevokeModalKey(k)}
                          >
                            <Ban size={13} /> Revoke
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--text-dim)' }}>
                  No keys found in keyring. Generate a keypair above.
                </div>
              )}
            </div>
          </div>
        </section>

        {/* 5. Upgraded Audit Ledger */}
        <section id="audit-trail" className="section-wrapper">
          <div className="section-header">
            <div>
              <div className="section-tag red-tag">
                <Clock3 size={12} /> AUDIT LEDGER
              </div>
              <h2 className="section-title">Cryptographic Event Trail</h2>
              <p className="section-desc">
                Append-only record of all signing, verification, and key lifecycle events stored in local SQLite database.
              </p>
            </div>
          </div>

          <div className="cyber-panel">
            <div className="history-controls">
              <input
                className="input-cyber"
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
                placeholder="Search filename, fingerprint, or digest…"
              />
              <select
                className="input-cyber"
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
              >
                <option value="ALL">All Event Types</option>
                <option value="VERIFICATION">Verification Events</option>
                <option value="SIGNING">Signing Operations</option>
                <option value="KEY_GEN">Key Generations</option>
                <option value="KEY_REVOKE">Key Revocations</option>
                <option value="KEY_ROTATE">Key Rotations</option>
              </select>
              <select
                className="input-cyber"
                value={filterResult}
                onChange={(e) => setFilterResult(e.target.value)}
              >
                <option value="ALL">All Results</option>
                <option value="VALID">Valid (Green)</option>
                <option value="TAMPERED">Tampered (Red)</option>
                <option value="INVALID">Invalid / Malformed (Red)</option>
                <option value="SUCCESS">Success (Green)</option>
              </select>
            </div>

            {auditRows.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>EVENT TYPE</th>
                      <th>RESULT</th>
                      <th>RESOURCE / FILENAME</th>
                      <th>REASON CODE</th>
                      <th>KEY FINGERPRINT</th>
                      <th>TIMESTAMP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditRows.map((x) => (
                      <tr key={x.id}>
                        <td>
                          <span style={{ fontFamily: 'ui-monospace, monospace', fontSize: 10, fontWeight: 800 }}>
                            {x.event_type}
                          </span>
                        </td>
                        <td>
                          <span
                            className={`status-badge ${
                              x.result === 'VALID' || x.result === 'SUCCESS' ? 'valid' : 'invalid'
                            }`}
                          >
                            {x.result}
                          </span>
                        </td>
                        <td>{x.filename || '—'}</td>
                        <td>
                          <code>{x.reason_code || '—'}</code>
                        </td>
                        <td style={{ fontFamily: 'ui-monospace, monospace', color: 'var(--green-dim)', fontSize: 10 }}>
                          {x.fingerprint ? `${x.fingerprint.slice(0, 16)}…` : '—'}
                        </td>
                        <td>{new Date(x.created_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '36px 0', color: 'var(--text-dim)' }}>
                <Clock3 size={24} style={{ margin: '0 auto 8px', display: 'block', color: 'var(--green)' }} />
                <b>No matching history</b>
                <p style={{ fontSize: 11, margin: '4px 0 0' }}>
                  Verification events will be recorded here when packages are evaluated.
                </p>
                {!stats?.recent?.length && (
                  <span style={{ display: 'none' }}>No activity yet</span>
                )}
              </div>
            )}
          </div>
        </section>

        {/* 6. Benchmark & Performance Lab */}
        <section id="benchmarks" className="section-wrapper">
          <div className="section-header">
            <div>
              <div className="section-tag">
                <Cpu size={12} /> BENCHMARK & EXPERIMENTAL EVALUATION
              </div>
              <h2 className="section-title">Performance & Testing Lab</h2>
              <p className="section-desc">
                Execute repeatable performance measurements across multiple payload sizes (1 KB, 100 KB, 1 MB).
              </p>
            </div>
          </div>

          <div className="cyber-panel">
            <div style={{ display: 'flex', gap: 14, alignItems: 'center', marginBottom: 20 }}>
              <button
                className="btn primary"
                disabled={benchBusy}
                onClick={handleRunBenchmarks}
              >
                {benchBusy ? 'Executing Benchmark Suite…' : 'Run Benchmark Suite'}
              </button>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                <span>Repetitions per size:</span>
                <select
                  className="input-cyber"
                  style={{ width: 80, height: 38 }}
                  value={benchReps}
                  onChange={(e) => setBenchReps(Number(e.target.value))}
                >
                  <option value={1}>1x</option>
                  <option value={2}>2x</option>
                  <option value={3}>3x</option>
                  <option value={5}>5x</option>
                </select>
              </div>
            </div>

            {benchResult && (
              <div>
                <div style={{ fontSize: 11, fontFamily: 'ui-monospace, monospace', color: 'var(--text-dim)', marginBottom: 12 }}>
                  ENVIRONMENT: {benchResult.environment} · PARAMETERS: {benchResult.parameters}
                </div>

                <div className="benchmark-grid">
                  {benchResult.benchmarks.map((b: any, idx: number) => (
                    <div className="benchmark-card" key={idx}>
                      <div className="benchmark-card-head">
                        <b style={{ fontSize: 14, color: '#fff' }}>FILE SIZE: {b.label}</b>
                        <span className="card-badge green">{b.size_bytes.toLocaleString()} BYTES</span>
                      </div>
                      <div className="metric-row">
                        <span>SHA-256 Hashing:</span>
                        <b>{b.hash_time_ms} ms</b>
                      </div>
                      <div className="metric-row">
                        <span>ElGamal Signing:</span>
                        <b className="g">{b.sign_time_ms} ms</b>
                      </div>
                      <div className="metric-row">
                        <span>Verification Time:</span>
                        <b className="g">{b.verify_time_ms} ms</b>
                      </div>
                      <div className="metric-row">
                        <span>Valid Pass Rate:</span>
                        <b className="g">{b.valid_signature_pass_rate}%</b>
                      </div>
                      <div className="metric-row">
                        <span>Tamper Detection:</span>
                        <b style={{ color: 'var(--red)' }}>{b.tamper_detection_rate}%</b>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>

        {/* 7. Cryptography Specifications */}
        <section id="specs" className="section-wrapper">
          <div className="section-header">
            <div>
              <div className="section-tag">
                <BookOpen size={12} /> CRYPTOGRAPHIC FOUNDATION
              </div>
              <h2 className="section-title">Algorithm Specifications & Limits</h2>
              <p className="section-desc">
                Mathematical properties of the finite field ElGamal signature scheme over RFC 3526 MODP Group 14 safe prime.
              </p>
            </div>
          </div>

          <div className="specs-grid">
            <div className="spec-box">
              <h4>
                <Zap size={16} /> Signing Equations
              </h4>
              <p>
                Given safe prime p, generator g = 2, secret exponent x, and SHA-256 digest h:
              </p>
              <div className="equation-code">
                r = gᵏ mod p<br />
                s = k⁻¹(h − xr) mod (p − 1)
              </div>
              <p>
                Signature is the pair (r, s). Ephemeral nonce k is chosen uniformly from [2, p-2] with gcd(k, p-1)=1 and discarded immediately.
              </p>
            </div>

            <div className="spec-box">
              <h4>
                <ShieldCheck size={16} /> Verification Equations
              </h4>
              <p>
                The verifier computes h = int(SHA-256(received_bytes)) and validates:
              </p>
              <div className="equation-code">
                gʰ ≡ yʳ · rˢ (mod p)
              </div>
              <p>
                Any alteration to the document changes h via SHA-256, causing modular exponentiation to diverge with overwhelming probability.
              </p>
            </div>

            <div className="spec-box">
              <h4>
                <LockKeyhole size={16} /> Parameters & Encryption
              </h4>
              <p>
                Uses the 2048-bit safe prime p from RFC 3526 MODP Group 14 (where p = 2q + 1, q is prime). Generator g = 2 generates the quadratic residue subgroup. Private keys are encrypted at rest with AES-256-GCM and scrypt.
              </p>
            </div>

            <div className="spec-box">
              <h4 style={{ color: 'var(--red)' }}>
                <ShieldAlert size={16} /> Academic Prototype Limitations
              </h4>
              <p>
                This application demonstrates ElGamal digital signatures. Cryptographic validity confirms mathematical alignment with the public key; it does not verify human identity.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Revoke Key Modal Confirmation */}
      {revokeModalKey && (
        <div className="modal-scrim" onClick={() => setRevokeModalKey(null)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <h3 className="modal-title">
              <AlertTriangle size={20} /> Revoke Cryptographic Key
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Are you sure you want to revoke key <b>"{revokeModalKey.label}"</b> (Fingerprint: {revokeModalKey.fingerprint.slice(0, 16)}…)? Once revoked, this key can no longer be used to sign documents, and any verification against it will show as REVOKED.
            </p>

            <label className="field-label">REVOCATION REASON</label>
            <input
              className="input-cyber"
              value={revokeReason}
              onChange={(e) => setRevokeReason(e.target.value)}
              placeholder="Reason for revocation"
            />

            <div className="modal-actions">
              <button className="btn ghost" onClick={() => setRevokeModalKey(null)}>
                Cancel
              </button>
              <button className="btn danger" onClick={handleRevokeKey} disabled={revokeBusy}>
                {revokeBusy ? 'Revoking…' : 'Confirm Revocation'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rotate Key Modal */}
      {rotateModalKey && (
        <div className="modal-scrim" onClick={() => setRotateModalKey(null)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <h3 className="modal-title" style={{ color: 'var(--green)' }}>
              <ArrowRightLeft size={20} /> Key Rotation Workflow
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Rotate <b>"{rotateModalKey.label}"</b>. The old key will be marked as RETIRED and a new 2048-bit keypair will be established.
            </p>

            <label className="field-label">NEW KEY LABEL</label>
            <input
              className="input-cyber"
              value={rotateLabel}
              onChange={(e) => setRotateLabel(e.target.value)}
            />

            <label className="field-label">PASSPHRASE FOR NEW KEY</label>
            <input
              className="input-cyber"
              type="password"
              value={rotatePassword}
              onChange={(e) => setRotatePassword(e.target.value)}
              placeholder="Minimum 10 characters"
            />

            <div className="modal-actions">
              <button className="btn ghost" onClick={() => setRotateModalKey(null)}>
                Cancel
              </button>
              <button
                className="btn primary"
                onClick={handleRotateKey}
                disabled={rotateBusy || rotatePassword.length < 10}
              >
                {rotateBusy ? 'Rotating…' : 'Execute Key Rotation'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="site-footer">
        <div>
          CIPHERLAB // ZERO <span>//</span> <span className="g">DOCUMENT INTEGRITY</span> <span>//</span> <span className="r">VERIFIED</span>
        </div>
        <div>
          ALGORITHM: <span className="g">ELGAMAL (RFC 3526 GROUP 14 SAFE PRIME)</span>
        </div>
      </footer>
    </div>
  );
}
