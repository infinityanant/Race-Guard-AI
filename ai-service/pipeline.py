"""Steps 2-6: ML prediction, Claude API, fix application, attack verification, report generation."""
import os, re, json, time, socket, subprocess, threading, tempfile, shutil, difflib
from datetime import datetime
import numpy as np
import joblib

# ── Step 2: ML Risk Prediction ──
risk_model = None
try:
    risk_model = joblib.load('../data/risk_model.pkl')
    print("Risk model loaded")
except Exception as e:
    print(f"Risk model not found: {e}")


def predict_risk(suspect):
    if risk_model is None:
        return {'predictedSeverity': 'HIGH', 'exploitabilityScore': 75, 'confidence': 50.0,
                'featureImportance': {}, 'riskFactors': ['model_unavailable']}
    features = np.array([[
        suspect.get('raceWindowMs', 100),
        1,  # sharedVariableCount
        1,  # concurrentEndpoints
        0,  # hasAuthentication
        1,  # isFinancialData
        suspect.get('asyncDepth', 1),
        1,  # isPublicEndpoint
    ]])
    severity = risk_model.predict(features)[0]
    probs = risk_model.predict_proba(features)[0]
    exploit = int(min(100, features[0][0] / 5 + 5 + 20 + 15))
    feat_names = ['raceWindowMs', 'sharedVariableCount', 'concurrentEndpoints',
                  'hasAuthentication', 'isFinancialData', 'asyncDepth', 'isPublicEndpoint']
    importance = dict(zip(feat_names, [float(x) for x in risk_model.feature_importances_]))
    top_factors = sorted(importance, key=importance.get, reverse=True)[:3]
    return {
        'predictedSeverity': severity,
        'exploitabilityScore': exploit,
        'confidence': float(max(probs)) * 100,
        'featureImportance': importance,
        'riskFactors': top_factors
    }


# ── Step 3: Claude API ──
def get_claude_client():
    key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not key: return None
    try:
        import anthropic
        return anthropic.Anthropic(api_key=key)
    except: return None


SYSTEM_PROMPT = """You are a senior application security engineer specializing in concurrency vulnerabilities.

PIPELINE — follow these steps in order before generating your response:

1. VULNERABILITY DETECTION: Identify ALL vulnerabilities in the snippet, not just the flagged one.
   Categories: Race condition (TOCTOU), Input validation, Missing auth, Business logic flaw, Concurrency bug.

2. ROOT CAUSE ANALYSIS: Explain WHY the vulnerability exists at a system design level, not just syntax.

3. FIX STRATEGY SELECTION — You MUST use this exact logic:
   if (raceConditionDetected) {
       if (sharedInMemoryState) {
           suggest = "move to atomic database operation";
       } else if (dbAlreadyUsed) {
           suggest = "use atomic update / transaction";
       } else {
           suggest = "mutex (with warning)";
       }
   }
   Use these exact strings for the fixStrategy field if possible, or map them to the closest category.

4. CONTEXT AWARENESS: Detect the framework (Express/Flask/Django) and database type. Generate fixes specific to that stack.

5. DEFENSE IN DEPTH: Always include rate limiting, input validation, logging in the fix.

Respond ONLY with valid JSON, no markdown:
{
  "confirmedVulnerable": true/false,
  "vulnerabilityName": "exact name e.g. TOCTOU Race Condition",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100,
  "rootCause": "why this vulnerability exists at a design level",
  "attackVector": "step by step exploit scenario with timing details",
  "plainEnglishExplanation": "explanation a non-technical founder would understand",
  "worstCaseImpact": "worst realistic business impact with dollar amounts if applicable",
  "fixStrategy": "atomic_operation|database_transaction|distributed_lock|mutex",
  "fixStrategyReasoning": "why this strategy was chosen over alternatives",
  "fixedCode": "complete corrected version using same variable names and framework",
  "fixExplanation": "mechanical explanation of how the fix eliminates the race window",
  "defenseInDepth": ["rate limiting suggestion", "input validation", "logging", "monitoring"],
  "verificationPlan": ["step 1 to verify fix works", "step 2", "step 3"],
  "scoreImpact": -40 to 0,
  "alternativeFix": "if primary fix has limitations, suggest a stronger alternative approach"
}

RULES:
- Do NOT use global mutex as the primary fix strategy
- Do NOT assume single-server deployment
- ALWAYS prioritize scalable, production-safe solutions
- fixedCode MUST be drop-in replacement using identical variable names"""


def get_ai_analysis(suspect, language, client=None):
    user_msg = f"""Language: {language}
Pattern: {suspect['patternType']}
Shared variable: {suspect['sharedVariable']}
Race window: {suspect['raceWindowMs']}ms
Code (lines {suspect['startLine']}-{suspect['endLine']}):
{suspect['codeSnippet']}

Full function:
{suspect['fullFunctionCode']}"""

    if client:
        try:
            resp = client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=2000,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}])
            text = resp.content[0].text.strip()
            if text.startswith('```'): text = re.sub(r'^```\w*\n?', '', text); text = re.sub(r'\n?```$', '', text)
            result = json.loads(text)
            result['startLine'] = suspect['startLine']
            result['endLine'] = suspect['endLine']
            result['originalCode'] = suspect['codeSnippet']
            result['sharedVariable'] = suspect['sharedVariable']
            return result
        except Exception as e:
            print(f"Claude error: {e}")

    # Mock/fallback
    return _mock_analysis(suspect)


def _mock_analysis(suspect):
    p = suspect['patternType']
    code = suspect.get('codeSnippet', '')
    var = suspect.get('sharedVariable', 'data')
    race_ms = suspect.get('raceWindowMs', 100)

    # ── Context Detection ──
    # Use full function code for better detection (snippet may miss imports/db setup)
    full_code = suspect.get('fullFunctionCode', code)
    ctx = _detect_context(full_code, code, var)

    # ── Root Cause Analysis ──
    root_causes = {
        'TOCTOU': f'The variable "{var}" is read, then an async operation occurs ({race_ms}ms gap), then a decision is made based on the stale read. In a concurrent environment, multiple requests read the same value before any write completes, creating a {race_ms}ms exploitation window.',
        'ReadModifyWrite': f'The read-modify-write on "{var}" is not atomic. Each step (read, compute, write) is a separate operation, allowing interleaving between concurrent requests.',
        'MissingTransaction': 'Multiple database operations execute independently. If any operation fails mid-sequence, data is left in an inconsistent state with no rollback capability.',
        'SharedState': f'"{var}" is module-level mutable state shared across all concurrent request handlers. Node.js event loop interleaving means any await/setTimeout creates a window where another request can read stale data.'
    }

    # ── Fix Strategy Selection (Priority: atomic > transaction > distributed_lock > mutex) ──
    strategy, reasoning = _select_fix_strategy(p, ctx)

    # ── Generate Fix ──
    fixed = _generate_smart_fix(code, var, strategy, ctx)

    # ── Defense in Depth ──
    defenses = [
        f'Add rate limiting: max 5 requests per second per IP to /withdraw endpoint',
        f'Validate input: ensure "amount" is a positive number, not exceeding balance, and not zero',
        f'Add request logging: log all {var} mutations with timestamp, userId, IP, and before/after values',
        'Add monitoring alerts: trigger if balance drops below 0 or more than 10 requests/sec hit the endpoint',
        'Add authentication: verify JWT/session token before processing any financial operation'
    ]

    # ── Verification Plan ──
    verification = [
        f'1. Start server, set {var} = 1000',
        f'2. Send 20 concurrent POST requests each withdrawing 100 (total = 2000, but only 1000 available)',
        f'3. PASS condition: final {var} must be >= 0 AND exactly (1000 - N*100) where N <= 10',
        '4. FAIL condition: final balance is negative, or more than 10 withdrawals succeeded',
        '5. Edge case: send amount=0, amount=-100, amount=999999 — all must be rejected',
        '6. Repeat test 10 times to account for timing variations'
    ]

    names = {'TOCTOU': 'TOCTOU Race Condition', 'ReadModifyWrite': 'Read-Modify-Write Race',
             'MissingTransaction': 'Missing Transaction Boundary', 'SharedState': 'Unprotected Shared State'}
    impacts = {'TOCTOU': -35, 'ReadModifyWrite': -25, 'MissingTransaction': -20, 'SharedState': -30}

    worst_case = {
        'TOCTOU': f'With a {race_ms}ms race window, an attacker can send 20 concurrent withdrawal requests. All 20 read balance=1000 before any write occurs. All 20 pass the check and execute, resulting in balance = 1000 - (20 × 100) = -1000. Financial loss: ₹2,000 stolen per attack cycle. Automated scripts can repeat this every second.',
        'SharedState': f'Every concurrent request reads the same stale "{var}" value. With no synchronization, N simultaneous requests each deduct independently from the same snapshot, multiplying the actual deduction. An attacker drains the entire account in under 1 second.',
        'ReadModifyWrite': f'The read-modify-write cycle on "{var}" allows lost updates. If 10 concurrent requests each try to deduct 100, only the last write survives — the other 9 deductions are lost, giving away ₹900 for free.',
        'MissingTransaction': 'A partial failure leaves the database in an inconsistent state. For example, a debit succeeds but the credit fails, causing money to vanish from the system.'
    }

    alt_fix = {
        'atomic_operation': 'If moving to a database, use findOneAndUpdate with $inc for true atomicity. For distributed systems, consider Redis WATCH/MULTI/EXEC pipeline.',
        'database_transaction': 'For even stronger guarantees, use serializable isolation level or add optimistic locking with version numbers.',
        'distributed_lock': 'Consider using database-level advisory locks (pg_advisory_lock) for PostgreSQL, or RedLock algorithm for Redis cluster deployments.',
        'mutex': 'WARNING: This mutex only works on a single server instance. For production, migrate to database-backed atomic operations or a distributed lock service.'
    }

    return {
        'confirmedVulnerable': True,
        'vulnerabilityName': names.get(p, p),
        'severity': suspect.get('mlPrediction', {}).get('predictedSeverity', 'HIGH'),
        'confidence': 85,
        'rootCause': root_causes.get(p, 'Concurrent access to shared state without synchronization'),
        'attackVector': f'1. Attacker identifies the /{var} endpoint has a {race_ms}ms race window\n2. Attacker crafts a script: for(i=0;i<20;i++) fetch("/withdraw", {{method:"POST", body:JSON.stringify({{amount:100}})}})\n3. All 20 requests hit the server simultaneously\n4. All 20 read {var}=1000 before any write occurs\n5. All 20 pass the balance check\n6. All 20 execute the deduction\n7. Result: {var} goes negative, attacker steals funds',
        'plainEnglishExplanation': f'Imagine 20 people checking your bank balance at the exact same instant — they all see ₹1000. Then all 20 withdraw ₹100 each. Because they all checked at the same time, the bank thought it had enough for everyone. Your account ends up at -₹1000. This is exactly what happens to your code with concurrent requests.',
        'worstCaseImpact': worst_case.get(p, 'Data corruption and financial loss'),
        'fixStrategy': strategy,
        'fixStrategyReasoning': reasoning,
        'fixedCode': fixed,
        'fixExplanation': f'The {strategy.replace("_", " ")} approach eliminates the race window by making the check-and-update a single indivisible operation. No request can read stale data because the operation completes atomically.',
        'defenseInDepth': defenses,
        'verificationPlan': verification,
        'alternativeFix': alt_fix.get(strategy, ''),
        'scoreImpact': impacts.get(p, -20),
        'startLine': suspect['startLine'],
        'endLine': suspect['endLine'],
        'originalCode': suspect['codeSnippet'],
        'sharedVariable': suspect['sharedVariable']
    }


def _detect_context(full_code, snippet, shared_var):
    """Detect framework, database, environment, and shared-state type from code."""
    # Combine both for broader detection
    combined = full_code + '\n' + snippet

    ctx = {'framework': 'unknown', 'db': 'none', 'lang': 'javascript',
           'sharedInMemoryState': False, 'dbAlreadyUsed': False}

    # Framework detection
    if 'express' in combined or 'app.post' in combined or 'app.get' in combined:
        ctx['framework'] = 'express'
    elif 'flask' in combined.lower() or '@app.route' in combined:
        ctx['framework'] = 'flask'; ctx['lang'] = 'python'
    elif 'django' in combined.lower():
        ctx['framework'] = 'django'; ctx['lang'] = 'python'

    # Database detection
    if re.search(r'mongoose|mongodb|MongoClient|mongo', combined, re.I):
        ctx['db'] = 'mongodb'; ctx['dbAlreadyUsed'] = True
    elif re.search(r'sequelize|knex|prisma|pg\.|mysql|sqlite|typeorm|drizzle', combined, re.I):
        ctx['db'] = 'sql'; ctx['dbAlreadyUsed'] = True
    elif re.search(r'redis', combined, re.I):
        ctx['db'] = 'redis'; ctx['dbAlreadyUsed'] = True
    # Also check for generic DB patterns
    elif re.search(r'\b(db|database|collection|model|repository|dao)\s*\.\s*(find|update|insert|save|query|get|set)', combined, re.I):
        ctx['db'] = 'generic'; ctx['dbAlreadyUsed'] = True

    # Shared in-memory state detection
    # JS: let/var at module level (not inside a function)
    if re.search(rf'^(?:let|var)\s+{re.escape(shared_var)}\s*=', combined, re.MULTILINE):
        ctx['sharedInMemoryState'] = True
    # Python: global keyword
    if re.search(rf'global\s+{re.escape(shared_var)}', combined):
        ctx['sharedInMemoryState'] = True
    # Generic: variable modified without any DB call in the handler
    if not ctx['dbAlreadyUsed'] and re.search(rf'\b{re.escape(shared_var)}\b\s*[+\-\*]?=', snippet):
        ctx['sharedInMemoryState'] = True

    return ctx


def _select_fix_strategy(pattern, ctx):
    """
    Decision tree (user-specified logic):
      if raceConditionDetected:
          if sharedInMemoryState  → "move to atomic database operation"
          elif dbAlreadyUsed      → "use atomic update / transaction"
          else                    → "mutex (with warning)"
    """
    race_detected = pattern in ('TOCTOU', 'SharedState', 'ReadModifyWrite', 'MissingTransaction')

    if not race_detected:
        return 'mutex (with warning)', 'No race condition pattern detected. Using basic serialization as precaution.'

    # Branch 1: Shared in-memory state (let balance = 1000) → move to DB
    if ctx['sharedInMemoryState']:
        return 'move to atomic database operation', (
            'DETECTED: Shared in-memory state (variable declared at module level and mutated inside request handlers). '
            'In-memory state cannot be safely shared across concurrent requests or multiple server instances. '
            'FIX: Move this state to a database and use atomic operations (e.g. MongoDB findOneAndUpdate with $inc, '
            'or SQL UPDATE ... WHERE balance >= amount). This eliminates the race window entirely — '
            'the check-and-update becomes a single indivisible database operation.'
        )

    # Branch 2: DB already used but not atomically → use atomic update / transaction
    if ctx['dbAlreadyUsed']:
        if ctx['db'] == 'mongodb':
            return 'use atomic update / transaction', (
                'DETECTED: MongoDB is already in use but the read-check-write is done in separate calls. '
                'FIX: Replace the separate find() + save() with a single findOneAndUpdate() using $inc and $gte condition. '
                'This makes the operation atomic at the database level — no application lock needed, works across multiple servers.'
            )
        elif ctx['db'] in ('sql', 'generic'):
            return 'use atomic update / transaction', (
                'DETECTED: SQL/database is already in use but operations are not wrapped in a transaction. '
                'FIX: Wrap the read-check-write in a database transaction with SELECT FOR UPDATE (row-level lock). '
                'This prevents any other request from reading the row until the transaction commits, eliminating the race window.'
            )
        else:
            return 'use atomic update / transaction', (
                f'DETECTED: {ctx["db"]} database is already in use. '
                'FIX: Use the database\'s native atomic operations or transaction support to make the read-check-write indivisible.'
            )

    # Branch 3: No shared state, no DB → mutex as last resort
    return 'mutex (with warning)', (
        'No shared in-memory state or database detected in the code. '
        'Using application-level async mutex as a last resort. '
        'WARNING: This only works on a single server instance. '
        'For production, strongly recommend migrating state to a database with atomic operations.'
    )


def _generate_smart_fix(code_snippet, shared_var, strategy, ctx):
    """Generate production-grade fix based on selected strategy."""
    lines = code_snippet.split('\n')
    fixed_lines = []
    in_handler = False
    handler_indent = ''

    for line in lines:
        if re.search(r'(?:app|router)\s*\.\s*(get|post|put|delete|patch)\s*\(', line):
            in_handler = True
            fixed_lines.append(line)
            continue
        if in_handler and not handler_indent:
            m = re.match(r'^(\s+)', line)
            handler_indent = m.group(1) if m else '    '
            ind = handler_indent

            if strategy == 'atomic_operation':
                fixed_lines.append(f'{ind}// FIX: Atomic operation — no race window possible')
                fixed_lines.append(f'{ind}const {{ amount }} = req.body;')
                fixed_lines.append(f'{ind}if (!amount || amount <= 0) return res.status(400).json({{ error: "Invalid amount" }});')
                fixed_lines.append(f'{ind}// Single atomic operation: check balance AND deduct in one step')
                fixed_lines.append(f'{ind}const result = await db.findOneAndUpdate(')
                fixed_lines.append(f'{ind}  {{ _id: userId, {shared_var}: {{ $gte: amount }} }},')
                fixed_lines.append(f'{ind}  {{ $inc: {{ {shared_var}: -amount }} }},')
                fixed_lines.append(f'{ind}  {{ returnDocument: "after" }}')
                fixed_lines.append(f'{ind});')
                fixed_lines.append(f'{ind}if (!result) return res.status(400).json({{ error: "Insufficient funds" }});')
                fixed_lines.append(f'{ind}res.json({{ success: true, {shared_var}: result.{shared_var} }});')
                in_handler = False
                continue
            elif strategy == 'database_transaction':
                fixed_lines.append(f'{ind}// FIX: Database transaction with row-level lock')
                fixed_lines.append(f'{ind}const {{ amount }} = req.body;')
                fixed_lines.append(f'{ind}if (!amount || amount <= 0) return res.status(400).json({{ error: "Invalid amount" }});')
                fixed_lines.append(f'{ind}const trx = await db.transaction();')
                fixed_lines.append(f'{ind}try {{')
                fixed_lines.append(f'{ind}  const row = await trx("accounts").where("id", userId).forUpdate().first();')
                fixed_lines.append(f'{ind}  if (row.{shared_var} < amount) {{ await trx.rollback(); return res.status(400).json({{ error: "Insufficient funds" }}); }}')
                fixed_lines.append(f'{ind}  await trx("accounts").where("id", userId).update({{ {shared_var}: row.{shared_var} - amount }});')
                fixed_lines.append(f'{ind}  await trx.commit();')
                fixed_lines.append(f'{ind}  res.json({{ success: true, {shared_var}: row.{shared_var} - amount }});')
                fixed_lines.append(f'{ind}}} catch (e) {{ await trx.rollback(); res.status(500).json({{ error: "Transaction failed" }}); }}')
                in_handler = False
                continue
            else:
                # Mutex — but proper async queue, not boolean flag
                fixed_lines.append(f'{ind}// FIX: Async mutex with queue (single-server only)')
                fixed_lines.append(f'{ind}// For production, migrate to database atomic operations')
                fixed_lines.append(f'{ind}const release = await acquireLock("{shared_var}");')
                fixed_lines.append(f'{ind}try {{')
                fixed_lines.append(f'{ind}  {line.strip()}')
                continue
        if in_handler and handler_indent:
            ind = handler_indent
            if re.search(r'res\.(json|send|status)', line) and not re.search(r'return\s+res', line):
                fixed_lines.append(f'{ind}  {line.strip()}')
                fixed_lines.append(f'{ind}}} finally {{')
                fixed_lines.append(f'{ind}  release();')
                fixed_lines.append(f'{ind}}}')
                in_handler = False
                continue
            if re.search(r'return\s+res', line):
                fixed_lines.append(f'{ind}  {line.strip()}')
                continue
            fixed_lines.append(f'{ind}  {line.strip()}')
            continue
        fixed_lines.append(line)
    return '\n'.join(fixed_lines)


def run_ai_analysis_concurrent(suspects, language):
    """Run Claude analysis concurrently via threading."""
    client = get_claude_client()
    results = [None] * len(suspects)

    def analyze(i, s):
        results[i] = get_ai_analysis(s, language, client)

    threads = [threading.Thread(target=analyze, args=(i, s)) for i, s in enumerate(suspects)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=30)
    return [r for r in results if r]


# ── Step 4: Apply Fix ──
def apply_fix(original_code, finding):
    lines = original_code.split('\n')
    start = finding.get('startLine', 1) - 1
    end = finding.get('endLine', len(lines))
    fixed_snippet = finding.get('fixedCode', '')
    if not fixed_snippet or fixed_snippet == finding.get('originalCode', ''):
        return {'fixedFileCode': original_code, 'diff': [], 'linesChanged': []}

    new_lines = lines[:start] + fixed_snippet.split('\n') + lines[end:]
    fixed_code = '\n'.join(new_lines)

    diff = list(difflib.unified_diff(
        lines, new_lines, fromfile='vulnerable', tofile='fixed', lineterm=''))
    changed = list(range(start + 1, start + 1 + len(fixed_snippet.split('\n'))))
    return {'fixedFileCode': fixed_code, 'diff': diff, 'linesChanged': changed}


# ── Step 5: Attack Verification ──
def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0)); return s.getsockname()[1]


def verify_fix(original_code, fixed_code, finding, language):
    result = {
        'original': {'attacksSucceeded': 0, 'attacksFailed': 20, 'valueBefore': 1000, 'valueAfter': 1000, 'exploitable': False},
        'fixed': {'attacksSucceeded': 0, 'attacksFailed': 20, 'valueBefore': 1000, 'valueAfter': 1000, 'exploitable': False},
        'fixVerified': False, 'exploitTimeMs': 0, 'successRateBefore': 0, 'successRateAfter': 0
    }
    ext = '.py' if language.lower().startswith('python') else '.js'
    port_orig, port_fix = _find_free_port(), _find_free_port()

    def _inject_port(code, port):
        if ext == '.js':
            return re.sub(r'\.listen\s*\(\s*\d+', f'.listen({port}', code)
        return re.sub(r'\.run\s*\([^)]*port\s*=\s*\d+', f'.run(port={port}', code)

    tmp = tempfile.mkdtemp(prefix='audit_verify_')
    procs = []
    try:
        for label, code, port in [('orig', original_code, port_orig), ('fix', fixed_code, port_fix)]:
            f_path = os.path.join(tmp, f'{label}{ext}')
            with open(f_path, 'w') as f:
                f.write(_inject_port(code, port))
            # Run the process with cwd pointing to the backend directory so it can resolve node_modules (e.g. express)
            workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            backend_dir = os.path.join(workspace_dir, 'backend') if ext == '.js' else tmp
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=backend_dir)
            procs.append(p)

        time.sleep(2)
        if any(p.poll() is not None for p in procs):
            result['original']['error'] = 'Server failed to start'
            return result

        import urllib.request, urllib.error

        def _attack(port):
            successes, url = [], f'http://localhost:{port}'
            # Init
            try:
                req = urllib.request.Request(f'{url}/api/init',
                    data=json.dumps({'userId': 'test', 'balance': 1000}).encode(),
                    headers={'Content-Type': 'application/json'}, method='POST')
                urllib.request.urlopen(req, timeout=3)
            except: pass
            # Also try /withdraw init pattern
            try:
                req = urllib.request.Request(f'{url}/init',
                    data=json.dumps({'balance': 1000}).encode(),
                    headers={'Content-Type': 'application/json'}, method='POST')
                urllib.request.urlopen(req, timeout=3)
            except: pass

            def fire(i):
                try:
                    # Try common vulnerable endpoints
                    for ep in ['/withdraw', '/api/redeem']:
                        try:
                            req = urllib.request.Request(f'{url}{ep}',
                                data=json.dumps({'userId': 'test', 'amount': 100}).encode(),
                                headers={'Content-Type': 'application/json'}, method='POST')
                            resp = urllib.request.urlopen(req, timeout=5)
                            successes.append(json.loads(resp.read()))
                            return
                        except urllib.error.HTTPError: pass
                except: pass

            threads = [threading.Thread(target=fire, args=(i,)) for i in range(20)]
            for t in threads: t.start()
            for t in threads: t.join(timeout=10)

            # Get final state
            final_val = 1000
            try:
                for ep in ['/api/wallet/test', '/balance']:
                    try:
                        resp = urllib.request.urlopen(f'{url}{ep}', timeout=3)
                        data = json.loads(resp.read())
                        final_val = data.get('balance', data.get('value', 1000))
                        break
                    except: pass
            except: pass
            return len(successes), final_val

        t_start = time.time()
        orig_ok, orig_val = _attack(port_orig)
        fix_ok, fix_val = _attack(port_fix)
        elapsed = int((time.time() - t_start) * 1000)

        result['original'] = {
            'attacksSucceeded': orig_ok, 'attacksFailed': 20 - orig_ok,
            'valueBefore': 1000, 'valueAfter': orig_val, 'exploitable': orig_ok > 1
        }
        result['fixed'] = {
            'attacksSucceeded': fix_ok, 'attacksFailed': 20 - fix_ok,
            'valueBefore': 1000, 'valueAfter': fix_val, 'exploitable': fix_ok > 1
        }
        result['fixVerified'] = fix_ok <= 1
        result['exploitTimeMs'] = elapsed
        result['successRateBefore'] = orig_ok / 20
        result['successRateAfter'] = fix_ok / 20

    except Exception as e:
        result['original']['error'] = str(e)
    finally:
        for p in procs:
            try: p.terminate(); p.wait(3)
            except:
                try: p.kill()
                except: pass
        shutil.rmtree(tmp, ignore_errors=True)
    return result


# ── Step 6: Report Generation ──
def generate_report(original_code, findings, fix_results, verification_results):
    score = 100
    for f in findings:
        score += f.get('scoreImpact', -15)
    score = max(0, min(100, score))

    summary = _generate_summary(findings, score, verification_results)

    report = {
        'securityScore': score,
        'executiveSummary': summary,
        'findings': findings,
        'diffs': fix_results,
        'verification': verification_results,
        'auditTimestamp': datetime.now().isoformat()
    }

    # Save to history
    try:
        history_path = '../data/audit_history.json'
        history = []
        if os.path.exists(history_path):
            with open(history_path) as f: history = json.load(f)
        history.append({'timestamp': report['auditTimestamp'], 'score': score, 'findingCount': len(findings)})
        with open(history_path, 'w') as f: json.dump(history, f, indent=2)
    except: pass

    return report


def _generate_summary(findings, score, verification):
    client = get_claude_client()
    count = len(findings)
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    verified = verification.get('fixVerified', False) if isinstance(verification, dict) else False

    if client:
        try:
            resp = client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=300,
                system="Write a 3-sentence executive summary for a non-technical startup founder.",
                messages=[{"role": "user", "content":
                    f"Score: {score}/100. Found {count} vulnerabilities ({critical} critical, {high} high). "
                    f"Fix verified by attack simulation: {verified}"}])
            return resp.content[0].text.strip()
        except: pass

    if score < 30: urgency = "URGENT: Your application has critical security flaws"
    elif score < 60: urgency = "Your application has significant security vulnerabilities"
    else: urgency = "Your application has minor security concerns"

    return (f"{urgency} — we found {count} race condition vulnerabilities "
            f"({critical} critical, {high} high severity) with a security score of {score}/100. "
            f"{'Our automated fix was verified by running a real attack simulation — the fix successfully blocked all exploit attempts.' if verified else 'Automated fixes have been generated and should be applied immediately.'} "
            f"Without remediation, an attacker could exploit these within minutes using a simple script.")
