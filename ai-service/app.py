from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import joblib
import numpy as np
import json
import time

from scanner import scan_for_vulnerabilities
from pipeline import predict_risk, run_ai_analysis_concurrent, apply_fix, verify_fix, generate_report

app = Flask(__name__)
CORS(app)

# Load anomaly detection model for /analyze
model = joblib.load('../data/model.pkl')
print("Anomaly model loaded")

# ── Existing /analyze endpoint (unchanged) ──
user_history = {}

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    userId, timestamp = data['userId'], data['timestamp']
    concurrent, gap = data['concurrentCount'], data['timeSinceLastRequest']
    endpoint = data.get('endpoint', '/api/redeem')

    history_key = f"{userId}:{endpoint}"
    history = user_history.get(history_key, [])
    history = [t for t in history if timestamp - t < 60000]
    history.append(timestamp)
    user_history[history_key] = history
    rpm = len(history)

    features = np.array([[concurrent, gap, rpm]])
    score = model.decision_function(features)[0]
    prediction = model.predict(features)[0]
    risk_score = max(0, min(100, int((-score + 0.2) * 200)))

    if endpoint == '/api/redeem':
        if concurrent >= 5: risk_score = max(risk_score, 85)
        elif concurrent >= 3: risk_score = max(risk_score, 65)
        if gap < 50: risk_score = max(risk_score, 70)
        if rpm >= 10: risk_score = max(risk_score, 80)
        elif rpm >= 5: risk_score = max(risk_score, 60)
    else:
        if concurrent >= 10: risk_score = max(risk_score, 70)
        if rpm >= 30: risk_score = max(risk_score, 65)
    risk_score = min(100, risk_score)

    if endpoint == '/api/redeem':
        if prediction == -1 or risk_score > 60:
            decision = 'block' if risk_score > 75 else 'flag'
        else: decision = 'allow'
    else:
        if risk_score > 75: decision = 'block'
        elif risk_score > 60: decision = 'flag'
        else: decision = 'allow'; risk_score = min(risk_score, 25)

    return jsonify({'decision': decision, 'riskScore': risk_score, 'requestsPerMinute': rpm})

@app.route('/clear-history', methods=['POST'])
def clear_history():
    user_history.clear()
    return jsonify({'message': 'AI history cleared'})


# ── /audit endpoint — 6-step pipeline with SSE ──
def sse(data):
    return f"data: {json.dumps(data)}\n\n"

@app.route('/audit', methods=['POST'])
def audit():
    data = request.json
    code = data.get('code', '')
    language = data.get('language', 'javascript')
    if not code.strip():
        return jsonify({'error': 'No code provided'}), 400

    def generate():
        # STEP 1: AST Scanner
        yield sse({'step': 1, 'status': 'running', 'label': 'Parsing code structure...'})
        suspects, err = scan_for_vulnerabilities(code, language)
        if err:
            yield sse({'step': 1, 'status': 'error', 'label': 'Parsing code structure...', 'error': err})
            return
        yield sse({'step': 1, 'status': 'complete', 'label': 'Parsing code structure...',
                   'message': f'Found {len(suspects)} suspicious patterns', 'suspects': len(suspects)})

        if not suspects:
            # Skip to report with perfect score
            report = {'securityScore': 100, 'executiveSummary': 'No vulnerabilities detected. Your code appears secure.',
                      'findings': [], 'diffs': [], 'verification': {}, 'auditTimestamp': ''}
            for step in range(2, 7):
                yield sse({'step': step, 'status': 'complete', 'label': 'Skipped — no vulnerabilities', 'message': 'Clean code'})
            yield sse({'step': 7, 'status': 'complete', 'label': 'Report ready', 'report': report})
            return

        # STEP 2: ML Risk Model
        yield sse({'step': 2, 'status': 'running', 'label': 'Running ML risk model...'})
        for s in suspects:
            s['mlPrediction'] = predict_risk(s)
        critical = sum(1 for s in suspects if s['mlPrediction']['predictedSeverity'] == 'CRITICAL')
        high = sum(1 for s in suspects if s['mlPrediction']['predictedSeverity'] == 'HIGH')
        yield sse({'step': 2, 'status': 'complete', 'label': 'Running ML risk model...',
                   'message': f'ML model: {critical} CRITICAL, {high} HIGH'})

        # Split: only CRITICAL/HIGH go to Claude
        high_risk = [s for s in suspects if s['mlPrediction']['predictedSeverity'] in ('CRITICAL', 'HIGH')]
        low_risk = [s for s in suspects if s['mlPrediction']['predictedSeverity'] in ('MEDIUM', 'LOW')]

        # STEP 3: Claude API (only for high-risk)
        yield sse({'step': 3, 'status': 'running', 'label': 'Running AI validation...',
                   'message': f'Validating {len(high_risk)} high-risk findings'})
        if high_risk:
            ai_findings = run_ai_analysis_concurrent(high_risk, language)
        else:
            ai_findings = []
        # Add template findings for low-risk
        from pipeline import _mock_analysis
        for s in low_risk:
            mock = _mock_analysis(s)
            mock['aiValidation'] = 'skipped_low_risk'
            ai_findings.append(mock)

        # Filter out non-vulnerable
        confirmed = [f for f in ai_findings if f.get('confirmedVulnerable', True)]
        yield sse({'step': 3, 'status': 'complete', 'label': 'Running AI validation...',
                   'message': f'AI confirmed {len(confirmed)} vulnerabilities'})

        # Attach ML predictions to findings
        for i, f in enumerate(confirmed):
            sl = f.get('startLine', 0)
            matching = [s for s in suspects if s['startLine'] == sl]
            if matching:
                f['mlPrediction'] = matching[0].get('mlPrediction', {})

        # STEP 4: Apply Fixes
        yield sse({'step': 4, 'status': 'running', 'label': 'Applying fixes...'})
        fix_results = []
        for f in confirmed:
            fix = apply_fix(code, f)
            fix_results.append(fix)
        yield sse({'step': 4, 'status': 'complete', 'label': 'Applying fixes...',
                   'message': f'Fixes applied to {len(fix_results)} locations'})

        # STEP 5: Attack Verification
        yield sse({'step': 5, 'status': 'running', 'label': 'Running attack verification...'})
        verification = {}
        # Use the first critical finding for verification
        crit_findings = [f for f in confirmed if f.get('severity') in ('CRITICAL', 'HIGH')]
        if crit_findings and fix_results:
            best_fix = None
            for fr in fix_results:
                if fr.get('fixedFileCode') and fr['fixedFileCode'] != code:
                    best_fix = fr; break
            if best_fix:
                yield sse({'step': 5, 'status': 'running', 'label': 'Running attack verification...',
                           'message': 'Attacking original and fixed code simultaneously...'})
                verification = verify_fix(code, best_fix['fixedFileCode'], crit_findings[0], language)
                blocked = 20 - verification.get('fixed', {}).get('attacksSucceeded', 20)
                yield sse({'step': 5, 'status': 'complete', 'label': 'Running attack verification...',
                           'message': f'{blocked}/20 attacks blocked by fix'})
            else:
                yield sse({'step': 5, 'status': 'complete', 'label': 'Running attack verification...',
                           'message': 'No applicable fix to verify'})
        else:
            yield sse({'step': 5, 'status': 'complete', 'label': 'Running attack verification...',
                       'message': 'No critical findings to verify'})

        # STEP 6: Generate Report
        yield sse({'step': 6, 'status': 'running', 'label': 'Generating report...'})
        report = generate_report(code, confirmed, fix_results, verification)
        yield sse({'step': 6, 'status': 'complete', 'label': 'Generating report...',
                   'message': 'Report ready', 'report': report})

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no'})


import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)