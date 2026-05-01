import { useState, useEffect, useRef, useCallback } from 'react';
import './App.css';

const BACKEND_URL = 'http://localhost:4000';

/* =====================================================
   Screen 1 — Upload
   ===================================================== */
function UploadScreen({ onStartAudit }) {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('javascript');
  const [fileName, setFileName] = useState('');
  const [dragover, setDragover] = useState(false);
  const fileRef = useRef(null);

  const handleFile = (file) => {
    if (!file) return;
    setFileName(file.name);
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext === 'py') setLanguage('python');
    else if (ext === 'java') setLanguage('java');
    else setLanguage('javascript');
    const reader = new FileReader();
    reader.onload = (e) => setCode(e.target.result);
    reader.readAsText(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragover(false);
    handleFile(e.dataTransfer.files[0]);
  };

  const canSubmit = code.trim().length > 10;

  return (
    <div className="upload-screen">
      <div className="upload-card">
        <h2>🔍 Upload Code for Security Audit</h2>
        <p className="upload-desc">
          Drop a source file or paste your code below. We'll scan for race conditions,
          concurrency bugs, and other security vulnerabilities.
        </p>

        <div
          className={`dropzone ${dragover ? 'dragover' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragover(true); }}
          onDragLeave={() => setDragover(false)}
          onDrop={handleDrop}
          onClick={() => fileRef.current?.click()}
        >
          {fileName ? (
            <div className="dropzone-file">
              <span>📄</span> {fileName}
            </div>
          ) : (
            <>
              <div className="dropzone-icon">📁</div>
              <div className="dropzone-text">Drop your code file here or click to browse</div>
              <div className="dropzone-sub">.js, .py, .java files accepted</div>
            </>
          )}
          <input
            ref={fileRef}
            type="file"
            accept=".js,.py,.java,.ts,.jsx"
            style={{ display: 'none' }}
            onChange={(e) => handleFile(e.target.files[0])}
          />
        </div>

        <div className="or-divider">— or paste code —</div>

        <textarea
          className="code-textarea"
          placeholder="// Paste your code here..."
          value={code}
          onChange={(e) => setCode(e.target.value)}
          spellCheck={false}
        />

        <div className="upload-options">

          <div className="form-group">
            <label htmlFor="url-field">Target URL (optional)</label>
            <input
              id="url-field"
              className="form-input"
              type="text"
              placeholder="Auto-detect"
            />
          </div>
        </div>

        <button
          className="btn-audit"
          disabled={!canSubmit}
          onClick={() => onStartAudit(code, language)}
        >
          🛡️ Run Security Audit
        </button>
      </div>
    </div>
  );
}

/* =====================================================
   Screen 2 — Analysis Progress
   ===================================================== */
const STEPS = [
  'Parsing code structure...',
  'Running ML risk model...',
  'Running AI validation...',
  'Applying fixes...',
  'Running attack verification...',
  'Generating report...',
];

function ProgressScreen({ progressData, logLines }) {
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logLines]);

  return (
    <div className="progress-screen">
      <div className="progress-card">
        <h2 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '1.5rem' }}>
          ⚙️ Security Analysis in Progress
        </h2>

        <div className="progress-steps">
          {STEPS.map((label, i) => {
            const stepNum = i + 1;
            const stepData = progressData[stepNum];
            let status = 'pending';
            if (stepData?.status === 'complete') status = 'complete';
            else if (stepData?.status === 'running' || stepData?.status === 'error') status = 'active';

            return (
              <div key={i} className={`progress-step ${status}`}>
                <div className={`step-status ${status}`}>
                  {status === 'complete' ? '✓' : status === 'active' ? '◌' : (i + 1)}
                </div>
                <div className="step-info">
                  <div className="step-label">{label}</div>
                  {stepData?.message && (
                    <div className="step-message">{stepData.message}</div>
                  )}
                  {stepData?.error && (
                    <div className="step-message" style={{ color: 'var(--block)' }}>
                      {stepData.error}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        <div className="live-log" ref={logRef}>
          {logLines.map((line, i) => (
            <div key={i} className={`log-line ${line.type || ''}`}>
              <span className="log-prefix">[{line.time}] </span>
              {line.text}
            </div>
          ))}
          {logLines.length === 0 && (
            <div className="log-line">Waiting for analysis to begin...</div>
          )}
        </div>
      </div>
    </div>
  );
}

/* =====================================================
   Score Gauge Component
   ===================================================== */
function ScoreGauge({ score, animated }) {
  const [display, setDisplay] = useState(0);
  const radius = 70;
  const circumference = 2 * Math.PI * radius;

  useEffect(() => {
    if (!animated) { setDisplay(score); return; }
    let start = 0;
    const duration = 1500;
    const startTime = Date.now();
    const animate = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(eased * score));
      if (progress < 1) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);
  }, [score, animated]);

  const offset = circumference - (display / 100) * circumference;
  const colorClass = display < 40 ? 'red' : display < 70 ? 'yellow' : 'green';

  return (
    <div className="score-gauge" style={{ position: 'relative', width: 180, height: 180 }}>
      <svg className="gauge-svg" width="180" height="180" viewBox="0 0 180 180">
        <circle className="gauge-track" cx="90" cy="90" r={radius} />
        <circle
          className={`gauge-fill stroke-${colorClass}`}
          cx="90" cy="90" r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="gauge-center" style={{
        position: 'absolute', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)'
      }}>
        <span className={`gauge-score score-${colorClass}`}>{display}</span>
        <span className="gauge-label">Security Score</span>
      </div>
    </div>
  );
}

/* =====================================================
   Vulnerability Card
   ===================================================== */
function VulnCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const ml = finding.mlPrediction || {};
  const name = finding.vulnerabilityName || finding.vulnerabilityType || 'Unknown';

  return (
    <div className="vuln-card">
      <div className="vuln-card-header">
        <span className="vuln-name">{name}</span>
        <span className={`severity-badge severity-${finding.severity}`}>{finding.severity}</span>
      </div>

      <div className="vuln-meta">
        <span>📍 Lines {finding.startLine}–{finding.endLine}</span>
        <span>🎯 {finding.fixStrategy}</span>
        <span>🔑 {finding.sharedVariable}</span>
      </div>

      {/* ML Risk Prediction */}
      {ml.predictedSeverity && (
        <div className="ml-prediction">
          <div className="ml-header">🤖 ML Risk Prediction</div>
          <div className="ml-row">
            <div className="ml-gauge-wrap">
              <div className="ml-gauge-label">Exploitability</div>
              <div className="ml-gauge-track">
                <div className="ml-gauge-fill" style={{ width: `${ml.exploitabilityScore || 0}%` }} />
              </div>
              <span className="ml-gauge-val">{ml.exploitabilityScore || 0}%</span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.4rem' }}>
              {(ml.riskFactors || []).map((f, i) => (
                <span key={i} className="risk-tag">{f}</span>
              ))}
            </div>
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
            ML Confidence: {(ml.confidence || 0).toFixed(0)}%
          </div>
        </div>
      )}

      <div className="vuln-section-label">💬 AI Explanation (Claude)</div>
      <p className="vuln-desc">{finding.plainEnglishExplanation || finding.whatCanGoWrong || 'N/A'}</p>

      <div className="vuln-attack">
        <strong>Attack Vector:</strong> {finding.attackVector}
      </div>
      <div className="vuln-attack" style={{ borderLeftColor: 'var(--flag)' }}>
        <strong>Worst Case:</strong> {finding.worstCaseImpact || 'Data loss or financial exploitation'}
      </div>

      <div className="confidence-bar">
        <span className="confidence-label">AI Confidence</span>
        <div className="confidence-track">
          <div className="confidence-fill" style={{ width: `${finding.confidence}%` }} />
        </div>
        <span className="confidence-value">{finding.confidence}%</span>
      </div>

      <button className="expand-btn" onClick={() => setExpanded(!expanded)}>
        {expanded ? '▲ Hide' : '▼ Show'} Full Analysis
      </button>
      {expanded && (
        <div className="proof-section">
          {finding.rootCause && (
            <div className="analysis-block">
              <div className="analysis-label">🔍 Root Cause</div>
              <p>{finding.rootCause}</p>
            </div>
          )}
          <div className="analysis-block">
            <div className="analysis-label">🛠️ Fix Strategy: {finding.fixStrategy?.replace(/_/g, ' ')}</div>
            <p>{finding.fixStrategyReasoning || finding.fixExplanation}</p>
          </div>
          {finding.defenseInDepth?.length > 0 && (
            <div className="analysis-block">
              <div className="analysis-label">🛡️ Defense in Depth</div>
              <ul className="defense-list">
                {finding.defenseInDepth.map((d, i) => <li key={i}>{d}</li>)}
              </ul>
            </div>
          )}
          {finding.verificationPlan?.length > 0 && (
            <div className="analysis-block">
              <div className="analysis-label">✅ Verification Plan</div>
              <ul className="defense-list">
                {finding.verificationPlan.map((v, i) => <li key={i}>{v}</li>)}
              </ul>
            </div>
          )}
          {finding.alternativeFix && (
            <div className="analysis-block" style={{ borderLeft: '3px solid var(--flag)' }}>
              <div className="analysis-label">⚠️ Alternative / Stronger Fix</div>
              <p>{finding.alternativeFix}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* =====================================================
   Diff View
   ===================================================== */
function DiffView({ finding }) {
  if (!finding) return null;
  const original = finding.originalCode || '';
  const fixed = finding.fixedCode || '';

  return (
    <div className="diff-section">
      <h2>🔧 Code Fix</h2>
      <div className="diff-container">
        <div className="diff-panel original">
          <div className="diff-panel-header">❌ Original (Vulnerable)</div>
          <pre className="diff-code">
            {original.split('\n').map((line, i) => (
              <span key={i} className="diff-line-removed">{line}{'\n'}</span>
            ))}
          </pre>
        </div>
        <div className="diff-panel fixed">
          <div className="diff-panel-header">✅ Fixed (Secure)</div>
          <pre className="diff-code">
            {fixed.split('\n').map((line, i) => (
              <span key={i} className="diff-line-added">{line}{'\n'}</span>
            ))}
          </pre>
        </div>
      </div>
      {finding.fixExplanation && (
        <div className="diff-explanation">
          <strong>Why this fix works: </strong>{finding.fixExplanation}
        </div>
      )}
    </div>
  );
}

/* =====================================================
   Screen 3 — Report
   ===================================================== */
/* =====================================================
   Proof of Exploit vs Proof of Fix
   ===================================================== */
function VerificationPanel({ verification }) {
  if (!verification || !verification.original) return null;
  const o = verification.original;
  const f = verification.fixed;
  const verified = verification.fixVerified;

  return (
    <div className="verification-panel">
      {verified && (
        <div className="verified-banner">
          ✅ FIX VERIFIED — ATTACK NEUTRALIZED
        </div>
      )}
      <div className="verify-grid">
        <div className="verify-card verify-before">
          <div className="verify-card-label">❌ BEFORE FIX</div>
          <div className="verify-stat">
            <span className="verify-big">{o.attacksSucceeded}/20</span>
            <span className="verify-sub">attacks succeeded</span>
          </div>
          <div className="verify-balance">
            ₹{o.valueBefore} → ₹{o.valueAfter}
          </div>
          {verification.exploitTimeMs > 0 && (
            <div className="verify-time">Exploitable in {verification.exploitTimeMs}ms</div>
          )}
        </div>
        <div className="verify-card verify-after">
          <div className="verify-card-label">✅ AFTER FIX</div>
          <div className="verify-stat">
            <span className="verify-big">{f.attacksSucceeded}/20</span>
            <span className="verify-sub">attacks succeeded</span>
          </div>
          <div className="verify-balance">
            ₹{f.valueBefore} → ₹{f.valueAfter}
          </div>
          <div className="verify-time" style={{ color: 'var(--allow)' }}>
            {verified ? 'Fix verified ✅' : 'Partial fix'}
          </div>
        </div>
      </div>
    </div>
  );
}

function ReportScreen({ report, onBack, onViewAttack }) {
  const [selectedFinding, setSelectedFinding] = useState(0);

  if (!report) return null;

  const handlePDF = () => window.print();

  return (
    <div className="report-screen" id="audit-report">
      <div className="report-header">
        <ScoreGauge score={report.securityScore} animated={true} />
        <div className="exec-summary">
          <h2>📋 Executive Summary</h2>
          <p>{report.executiveSummary}</p>
        </div>
      </div>

      {/* Proof of Exploit vs Fix — centerpiece */}
      <VerificationPanel verification={report.verification} />

      <div className="vuln-section">
        <h2>🐛 Vulnerabilities Found ({report.findings.length})</h2>
        {report.findings.map((f, i) => (
          <div key={i} onClick={() => setSelectedFinding(i)} style={{ cursor: 'pointer' }}>
            <VulnCard finding={f} />
          </div>
        ))}
        {report.findings.length === 0 && (
          <div style={{
            textAlign: 'center', padding: '2rem',
            color: 'var(--allow)', fontSize: '1.1rem', fontWeight: 600
          }}>
            ✅ No vulnerabilities detected — your code looks secure!
          </div>
        )}
      </div>

      {report.findings.length > 0 && (
        <DiffView finding={report.findings[selectedFinding]} />
      )}

      <div className="report-actions">
        <button className="btn-secondary" onClick={onBack}>← New Audit</button>
        <button className="btn-primary-sm" onClick={handlePDF}>📥 Download PDF</button>
      </div>
    </div>
  );
}

/* =====================================================
   Screen 4 — Attack Simulation Live View
   ===================================================== */
function AttackScreen({ report, onBack }) {
  if (!report) return null;
  const results = report.attackSimulationResults || [];
  const exploitable = results.filter(r => r.exploitable).length;
  const totalSent = results.reduce((s, r) => s + (r.requestsSent || 0), 0);
  const totalSucceeded = results.reduce((s, r) => s + (r.requestsSucceeded || 0), 0);

  return (
    <div className="attack-screen">
      <div className="attack-results-grid">
        <div className="attack-stat-card">
          <div className="attack-stat-value" style={{ color: 'var(--block)' }}>
            {exploitable}
          </div>
          <div className="attack-stat-label">Exploitable Vulns</div>
        </div>
        <div className="attack-stat-card">
          <div className="attack-stat-value" style={{ color: 'var(--accent-blue)' }}>
            {totalSent}
          </div>
          <div className="attack-stat-label">Requests Sent</div>
        </div>
        <div className="attack-stat-card">
          <div className="attack-stat-value" style={{ color: 'var(--flag)' }}>
            {totalSucceeded}
          </div>
          <div className="attack-stat-label">Succeeded</div>
        </div>
      </div>

      <div className="attack-log-card">
        <h3>⚡ Attack Simulation Results</h3>
        {results.map((r, i) => (
          <div key={i} className="vuln-card" style={{ marginBottom: '0.75rem' }}>
            <div className="vuln-card-header">
              <span className="vuln-name">
                {r.vulnerabilityType || `Attack ${i + 1}`}
              </span>
              <span className={`severity-badge ${r.exploitable ? 'severity-CRITICAL' : 'severity-LOW'}`}>
                {r.exploitable ? 'EXPLOITABLE' : 'SAFE'}
              </span>
            </div>
            <div className="vuln-meta">
              <span>💰 Before: ${r.beforeValue}</span>
              <span>💰 After: ${r.afterValue}</span>
              <span>📤 Sent: {r.requestsSent}</span>
              <span>✅ Succeeded: {r.requestsSucceeded}</span>
            </div>
            {r.exploitable && (
              <div className="vuln-attack">
                Balance changed from ${r.beforeValue} to ${r.afterValue} —
                attacker gained ${r.afterValue - r.beforeValue} through race condition exploitation.
              </div>
            )}
            {r.error && (
              <div style={{ fontSize: '0.8rem', color: 'var(--block)', marginTop: '0.5rem' }}>
                ⚠️ {r.error}
              </div>
            )}
          </div>
        ))}
        {results.length === 0 && (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            No attack simulations were run.
          </div>
        )}
      </div>

      <div className="report-actions">
        <button className="btn-secondary" onClick={onBack}>← Back to Report</button>
      </div>
    </div>
  );
}

/* =====================================================
   Main App
   ===================================================== */
export default function App() {
  const [screen, setScreen] = useState('upload');
  const [progressData, setProgressData] = useState({});
  const [logLines, setLogLines] = useState([]);
  const [report, setReport] = useState(null);

  const addLog = useCallback((text, type = '') => {
    const time = new Date().toLocaleTimeString();
    setLogLines(prev => [...prev, { time, text, type }]);
  }, []);

  const startAudit = useCallback(async (code, language) => {
    setScreen('analysis');
    setProgressData({});
    setLogLines([]);
    setReport(null);
    addLog('Starting security audit...');

    try {
      const res = await fetch(`${BACKEND_URL}/api/audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, language }),
      });

      if (!res.ok) {
        addLog(`Error: ${res.statusText}`, 'error');
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const data = JSON.parse(line.slice(6));
            setProgressData(prev => ({ ...prev, [data.step]: data }));

            if (data.message) addLog(data.message);
            if (data.error) addLog(data.error, 'error');
            if (data.status === 'complete') {
              addLog(`Step ${data.step} complete ✓`, 'success');
            }

            if (data.report) {
              setReport(data.report);
              addLog('Audit complete!', 'success');
              setTimeout(() => setScreen('report'), 800);
            }
          } catch (e) {
            // Skip malformed lines
          }
        }
      }
    } catch (err) {
      addLog(`Connection error: ${err.message}`, 'error');
    }
  }, [addLog]);

  const screenIndex = { upload: 0, analysis: 1, report: 2 };
  const currentIdx = screenIndex[screen] || 0;

  return (
    <div className="app-shell">
      {/* Header */}
      <header className="app-header">
        <div className="header-brand">
          <div className="header-icon">🛡️</div>
          <div>
            <h1 className="header-title">Security Audit Platform</h1>
            <p className="header-subtitle">AI-powered vulnerability detection &amp; attack simulation</p>
          </div>
        </div>

        <div className="step-indicator">
          {['Upload', 'Analyze', 'Report'].map((label, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div
                className={`step-dot ${i === currentIdx ? 'active' : i < currentIdx ? 'complete' : ''}`}
                title={label}
              >
                {i < currentIdx ? '✓' : i + 1}
              </div>
              {i < 2 && <div className={`step-line ${i < currentIdx ? 'complete' : ''}`} />}
            </div>
          ))}
        </div>
      </header>

      {/* Screens */}
      {screen === 'upload' && <UploadScreen onStartAudit={startAudit} />}
      {screen === 'analysis' && (
        <ProgressScreen progressData={progressData} logLines={logLines} />
      )}
      {screen === 'report' && (
        <ReportScreen
          report={report}
          onBack={() => setScreen('upload')}
        />
      )}
      {screen === 'attack' && (
        <AttackScreen report={report} onBack={() => setScreen('report')} />
      )}
    </div>
  );
}
