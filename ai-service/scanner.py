"""Step 1: AST-based vulnerability scanner. No AI, no API calls."""
import ast
import re


def scan_for_vulnerabilities(code, language):
    if language.lower().startswith('python'):
        return _scan_python(code)
    return _scan_javascript(code)


def _scan_python(code):
    suspects = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [], f"Python syntax error: {e}"
    lines = code.split('\n')

    # Find module-level variables
    module_vars = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    module_vars.append(t.id)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = ast.get_source_segment(code, node) or ''
        start, end = node.lineno, node.end_lineno or node.lineno
        snippet = '\n'.join(lines[start-1:end])

        # Pattern 4: Shared mutable state
        for var in module_vars:
            if re.search(rf'\b{re.escape(var)}\b\s*[+\-\*]?=', src):
                if not re.search(r'(lock|mutex|semaphore)', src, re.I):
                    suspects.append(_make_suspect('SharedState', start, end, snippet, snippet, var, 50, 1))
                    break

        # Pattern 1: TOCTOU
        if re.search(r'if\s', src) and re.search(r'(await|sleep|time\.sleep)', src):
            if re.search(r'\.\w+\s*[+\-\*]?=', src) or re.search(r'\b\w+\s*=\s*\w+\s*[-+]', src):
                race_ms = 100
                m = re.search(r'(?:sleep|setTimeout)\s*\(\s*(\d+)', src)
                if m: race_ms = int(m.group(1))
                var = _find_shared_var(src)
                suspects.append(_make_suspect('TOCTOU', start, end, snippet, snippet, var, race_ms, src.count('await')))

        # Pattern 2: Read-Modify-Write
        if re.search(r'\w+\s*=\s*.*\.(get|find|read|query|fetch)', src):
            if re.search(r'\w+\s*[+\-\*]?=', src):
                if re.search(r'\.(set|save|update|write|put)', src):
                    if not re.search(r'(transaction|atomic|lock)', src, re.I):
                        var = _find_shared_var(src)
                        suspects.append(_make_suspect('ReadModifyWrite', start, end, snippet, snippet, var, 100, 1))

        # Pattern 3: Multiple DB ops without transaction
        db_ops = re.findall(r'\.(insert|update|delete|save|remove|create|destroy)', src)
        if len(db_ops) >= 2:
            if not re.search(r'(transaction|BEGIN|COMMIT|atomic)', src, re.I):
                suspects.append(_make_suspect('MissingTransaction', start, end, snippet, snippet, 'db', 50, 1))

    return _dedupe(suspects), None


def _scan_javascript(code):
    suspects = []
    lines = code.split('\n')

    # Find handler blocks with brace matching
    handler_re = re.compile(
        r'(?:app|router)\s*\.\s*(get|post|put|delete|patch)\s*\('
        r'[^,]*,\s*(?:async\s+)?(?:function\s*)?'
        r'(?:\([^)]*\)|[a-zA-Z_]\w*)\s*(?:=>)?\s*\{', re.DOTALL)

    handlers = []
    for m in handler_re.finditer(code):
        brace, pos = 1, m.end()
        while pos < len(code) and brace > 0:
            if code[pos] == '{': brace += 1
            elif code[pos] == '}': brace -= 1
            pos += 1
        body = code[m.end():pos-1]
        sl = code[:m.start()].count('\n') + 1
        el = code[:pos].count('\n') + 1
        snippet = '\n'.join(lines[sl-1:el])
        handlers.append((body, sl, el, snippet))

    # Module-level mutable vars (let/var any value, const only objects/arrays)
    module_vars = re.findall(r'^(?:let|var)\s+(\w+)\s*=', code, re.MULTILINE)
    module_vars += re.findall(r'^const\s+(\w+)\s*=\s*(?:\{|\[|new\s)', code, re.MULTILINE)

    for body, sl, el, snippet in handlers:
        # Pattern 4: Shared state
        for var in module_vars:
            # Check for any mutation: var[x], var.x =, var =, var +=
            if (re.search(rf'\b{re.escape(var)}\b\s*\[', body) or
                re.search(rf'\b{re.escape(var)}\b\.\w*\s*[+\-\*]?=', body) or
                re.search(rf'\b{re.escape(var)}\b\s*[+\-\*]?=(?!=|>)', body)):
                if not re.search(r'(lock|mutex|semaphore)', body, re.I):
                    suspects.append(_make_suspect('SharedState', sl, el, snippet, snippet, var, 50, 1))
                    break

        # Pattern 1: TOCTOU — check → await → write (in order)
        has_check = re.search(r'if\s*\(', body)
        has_await = re.search(r'(await\s+|setTimeout|setImmediate)', body)
        # Find writes AFTER the await gap
        if has_check and has_await:
            after_await = body[has_await.end():]
            has_write_after = re.search(r'\b\w+\s*[+\-\*]?=\s*(?!>|=)', after_await)
            if has_write_after:
                race_ms = 100
                m2 = re.search(r'(?:setTimeout|delay)\s*\(\s*(?:\w+\s*,\s*)?(\d+)', body)
                if m2: race_ms = int(m2.group(1))
                var = _find_shared_var(after_await)
                depth = len(re.findall(r'await\s+', body))
                suspects.append(_make_suspect('TOCTOU', sl, el, snippet, snippet, var, race_ms, depth))

        # Pattern 2: Read-Modify-Write
        rmw = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*(\w+)', body)
        if rmw:
            vname = rmw.group(1)
            if re.search(rf'\b{re.escape(vname)}\b\s*[+\-\*]?=', body[rmw.end():]):
                if not re.search(r'(transaction|atomic|lock)', body, re.I):
                    suspects.append(_make_suspect('ReadModifyWrite', sl, el, snippet, snippet, vname, 100, 1))

        # Pattern 3: Multiple DB ops
        db_ops = re.findall(r'\.(insert|update|delete|save|remove|create|destroy)', body)
        if len(db_ops) >= 2 and not re.search(r'(transaction|BEGIN|COMMIT)', body, re.I):
            suspects.append(_make_suspect('MissingTransaction', sl, el, snippet, snippet, 'db', 50, 1))

    return _dedupe(suspects), None


def _make_suspect(pattern, start, end, snippet, full_func, shared_var, race_ms, async_depth):
    return {
        'patternType': pattern,
        'startLine': start,
        'endLine': end,
        'codeSnippet': snippet,
        'fullFunctionCode': full_func,
        'sharedVariable': shared_var or 'unknown',
        'raceWindowMs': race_ms,
        'asyncDepth': async_depth,
        'confidence': 80
    }


def _find_shared_var(src):
    m = re.search(r'(\w+)\s*[+\-\*]?=\s*(?!>|=)', src)
    return m.group(1) if m else 'unknown'


def _dedupe(suspects):
    seen, result = set(), []
    for s in suspects:
        key = (s['patternType'], s['startLine'])
        if key not in seen:
            seen.add(key)
            result.append(s)
    return result
