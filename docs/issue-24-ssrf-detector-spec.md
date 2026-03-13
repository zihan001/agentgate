# Issue #24: SSRF Private IP Detector — Implementation Spec

**Status:** Ready to build  
**Depends on:** Nothing (standalone detector, no cross-module deps)  
**Blocked by:** Nothing  
**Blocks:** #26 (wire detectors into engine)  
**Estimated effort:** ~2 hours  
**Acceptance test:** AT-5 (SSRF Private IP Block)

---

## 1. What This Detector Does

Scans all string parameter values in a tool call for URLs or IP-address-like strings that resolve to private, loopback, link-local, or cloud metadata addresses. If found, returns `DetectorResult(matched=True)`. This blocks SSRF attacks where an agent is tricked into hitting internal infrastructure or cloud metadata endpoints.

**This detector is deterministic, regex+stdlib only. No DNS resolution, no network calls, no ML.**

---

## 2. Detection Strategy

### Why not just regex?

Pure regex for IP range matching is fragile and error-prone (e.g., matching `172.16.x.x` through `172.31.x.x` as a regex is ugly and easy to get wrong). Instead:

1. **Extract candidate IPs/hostnames from strings** using a URL parser + bare IP regex fallback.
2. **Parse extracted IPs** using `ipaddress.ip_address()` from stdlib.
3. **Check parsed IPs** against stdlib's `is_private`, `is_loopback`, `is_link_local`, `is_reserved` — plus explicit checks for the AWS metadata IP `169.254.169.254` and `0.0.0.0`.

This is more robust than regex-only approaches and handles edge cases like:
- Decimal IPs (`http://2130706433` = `127.0.0.1`)
- IPv6 loopback (`http://[::1]/`)
- Hex-encoded octets (`http://0x7f.0x00.0x00.0x01/`) — handled by attempting parse
- Ports in URLs (`http://10.0.0.1:8080/path`)

### Extraction approach

For each string value in the tool call arguments:

1. **Try `urllib.parse.urlparse()`** — if the string has a scheme (`http://`, `https://`, `ftp://`, etc.), extract the hostname from the parsed URL.
2. **Bare IP fallback** — if no URL scheme, check if the string itself looks like a bare IP address (v4 or v6) using a simple regex, then parse it.

This covers:
- `http://169.254.169.254/latest/meta-data/` → hostname `169.254.169.254`
- `https://10.0.0.1:8080/admin` → hostname `10.0.0.1`
- `http://[::1]:3000/` → hostname `::1`
- `192.168.1.1` (bare string) → parsed directly

### What counts as "private/dangerous"

An extracted IP is flagged if ANY of:

| Check | What it catches |
|-------|-----------------|
| `ip.is_private` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` |
| `ip.is_loopback` | `127.0.0.0/8`, `::1` |
| `ip.is_link_local` | `169.254.0.0/16` (includes AWS metadata), `fe80::/10` |
| `ip.is_reserved` | Various reserved ranges |
| `ip == 0.0.0.0` | Explicit zero-address check (binds all interfaces) |
| `ip == ::` | IPv6 unspecified |

**Note:** `ipaddress` stdlib's `is_private` in Python 3.11+ covers `0.0.0.0` and most reserved ranges. For Python 3.10 compatibility, add explicit checks for `0.0.0.0` and `::` since `is_private` behavior varies slightly across versions.

### What does NOT get flagged

- Public IPs: `8.8.8.8`, `1.1.1.1`, `151.101.1.69`
- Public hostnames: `api.github.com`, `example.com` — **no DNS resolution**, so hostnames that might resolve to private IPs are not caught. This is a known MVP limitation (documented, not addressed).
- Non-URL strings that happen to contain digit sequences: `"order 192 items"` — the bare IP regex requires a full IPv4 dotted-quad pattern to avoid false positives.
- Strings that don't look like URLs or IPs at all.

---

## 3. Module Contract

### File: `src/agentgate/detectors/ssrf.py`

```python
def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for SSRF-dangerous IP addresses.
    
    Returns DetectorResult with matched=True on first private/loopback/
    link-local/metadata IP found in any URL or bare IP string.
    """
```

**Inputs:** `ToolCall` (from `models.py`) — uses `tool_call.arguments` dict.  
**Outputs:** `DetectorResult` — `matched=True` with `detector_name="ssrf_private_ip"` and descriptive `detail`, or `matched=False`.  
**Side effects:** None. Pure function.  
**Dependencies:** `urllib.parse`, `ipaddress` (both stdlib), `re`. No third-party deps.

---

## 4. Internal Design

### Helper functions

**`_extract_strings(arguments, prefix="")`** — Reuse the same recursive string extractor from the other detectors. Copy the pattern from `sql_injection.py` / `path_traversal.py` / `command_injection.py`. (Shared extraction is a future refactor; for now, each detector has its own copy per existing convention.)

**`_extract_host_from_url(value: str) -> str | None`** — Attempt to parse the string as a URL. If it has a recognized scheme and a hostname, return the hostname (stripped of brackets for IPv6). Return `None` if not a URL.

**`_is_dangerous_ip(host: str) -> bool`** — Try to parse the host string as an IP address via `ipaddress.ip_address()`. If it parses, check against the private/loopback/link-local/reserved predicates. Return `True` if dangerous. Return `False` if the parse fails (meaning it's a hostname, not an IP) or if the IP is public.

### Detection flow

```
For each (param_path, string_value) in _extract_strings(arguments):
    1. host = _extract_host_from_url(value)
       → if host and _is_dangerous_ip(host): MATCH
    2. Bare IP fallback: if value matches IPv4_REGEX or IPv6_REGEX:
       → if _is_dangerous_ip(value): MATCH
    3. Continue to next string
Return no-match
```

### Regex for bare IP fallback

```python
# IPv4: exactly 4 dotted decimal octets (no trailing path/port)
_BARE_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# IPv6: starts with brackets or contains colons (simplified)
_BARE_IPV6_RE = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")
```

These are intentionally conservative to avoid false positives on non-IP strings.

### Edge cases to handle

| Case | How handled |
|------|-------------|
| `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | URL parse → host `169.254.169.254` → link-local → **MATCH** |
| `http://[::1]:3000/admin` | URL parse → host `::1` (strip brackets) → loopback → **MATCH** |
| `http://0.0.0.0:8080/` | URL parse → host `0.0.0.0` → explicit check → **MATCH** |
| `http://2130706433/` | URL parse → host `2130706433` → `ipaddress` parses decimal IPs → `127.0.0.1` → loopback → **MATCH** |
| `http://0x7f000001/` | URL parse → host `0x7f000001` → `ipaddress` may or may not parse hex; if not, **no match** (acceptable MVP gap) |
| `ftp://10.0.0.1/file` | URL parse with `ftp` scheme → host `10.0.0.1` → private → **MATCH** |
| `https://api.github.com/repos` | URL parse → host `api.github.com` → not an IP → `_is_dangerous_ip` returns False → **no match** |
| `192.168.1.1` (bare string) | No URL scheme → bare IP regex matches → `_is_dangerous_ip` → private → **MATCH** |
| `"order 192.168 items"` | No URL scheme → bare IP regex does NOT match (not 4 octets) → **no match** |
| Port in URL: `http://10.0.0.1:9090/` | `urlparse` extracts hostname without port → works correctly |
| `http://localhost/` | URL parse → host `localhost` → not a valid IP → **no match** (known gap: no DNS) |

**Known MVP gaps (documented, not fixed):**
- Hostnames that resolve to private IPs (e.g., `http://localhost/`, `http://internal.corp.com/`) — requires DNS resolution, out of scope.
- Hex-encoded IPs (`0x7f000001`) — `ipaddress` doesn't reliably parse all encoding tricks. Acceptable.
- Octal-encoded octets (`http://0177.0.0.1/`) — same limitation.
- URL-encoded IPs in path components (not the host) — out of scope.

---

## 5. Test Plan

### File: `tests/test_detectors/test_ssrf.py`

All tests are sync, no I/O, no network. Each test constructs a `ToolCall` and asserts on the `DetectorResult`.

### Positive cases (8 tests — must all match)

| Test name | Tool call | Why it matters |
|-----------|-----------|----------------|
| `test_aws_metadata_endpoint` | `fetch_url(url="http://169.254.169.254/latest/meta-data/iam/security-credentials/")` | AT-5 exact scenario. AWS metadata SSRF. |
| `test_private_10_network` | `fetch_url(url="http://10.0.0.1/admin")` | Class A private range. |
| `test_private_172_network` | `fetch_url(url="http://172.16.0.1/internal")` | Class B private range (172.16-31). |
| `test_private_192_network` | `fetch_url(url="http://192.168.1.1/config")` | Class C private range. |
| `test_loopback_127` | `fetch_url(url="http://127.0.0.1:8080/")` | Loopback with port. |
| `test_zero_address` | `fetch_url(url="http://0.0.0.0/")` | Zero address (binds all). |
| `test_ipv6_loopback` | `fetch_url(url="http://[::1]:3000/")` | IPv6 loopback. |
| `test_bare_private_ip` | `make_request(target="192.168.1.1")` | Bare IP string, no URL scheme. |

### Negative cases (7 tests — must all NOT match)

| Test name | Tool call | Why it must pass |
|-----------|-----------|------------------|
| `test_public_api_url` | `fetch_url(url="https://api.github.com/repos")` | Normal public API. |
| `test_public_dns_ip` | `fetch_url(url="https://8.8.8.8/dns-query")` | Google DNS — public IP. |
| `test_public_website` | `fetch_url(url="https://www.example.com/page")` | Hostname, not IP. |
| `test_non_url_string` | `read_file(path="/data/workspace/report.csv")` | Not a URL at all. |
| `test_numeric_string_not_ip` | `query(limit="192")` | Number that isn't an IP. |
| `test_public_ip_bare` | `connect(host="151.101.1.69")` | Public IP, bare string. |
| `test_empty_arguments` | `ping()` with `{}` arguments | No params to scan. |

### Edge cases (2 tests)

| Test name | Tool call | Expected |
|-----------|-----------|----------|
| `test_nested_url_param` | `request(options={"endpoint": "http://10.0.0.1/api"})` | **MATCH** — recursive extraction finds nested URL. |
| `test_url_with_path_only` | `fetch_url(url="/api/v1/users")` | **No match** — relative path, no host. |

**Total: 17 tests** (8 positive + 7 negative + 2 edge = matches the convention from other detectors which have 16-17 tests each).

---

## 6. Implementation Checklist

- [ ] Create `src/agentgate/detectors/ssrf.py`
  - [ ] `_extract_strings()` — copy from existing detectors
  - [ ] `_extract_host_from_url(value)` — `urlparse` + strip IPv6 brackets
  - [ ] `_is_dangerous_ip(host)` — `ipaddress.ip_address()` + private/loopback/link-local/reserved checks + explicit `0.0.0.0` / `::` checks
  - [ ] `detect(tool_call)` — main entry point, iterate strings, check URLs then bare IPs
- [ ] Create `tests/test_detectors/test_ssrf.py` — 17 tests
- [ ] Run `uv run pytest tests/test_detectors/test_ssrf.py` — all green
- [ ] Run `uv run ruff check src/agentgate/detectors/ssrf.py tests/test_detectors/test_ssrf.py`
- [ ] Run full suite `uv run pytest` — no regressions

---

## 7. Decisions Made

| Decision | Rationale |
|----------|-----------|
| **Use `ipaddress` stdlib, not regex, for range checking** | Regex for `172.16-31.x.x` is fragile. `ipaddress.is_private` is authoritative and handles IPv6 for free. |
| **No DNS resolution** | Adding DNS makes the detector async, adds latency, introduces network dependencies, and creates TOCTOU issues. MVP gap, documented. |
| **Copy `_extract_strings` rather than refactor to shared util** | Matches existing detector convention. Refactor to shared util is a future cleanup, not blocking. |
| **Check `is_reserved` in addition to `is_private`** | Catches ranges like `100.64.0.0/10` (carrier-grade NAT) and documentation ranges. Slightly broader than spec requires, but no false-positive risk on legitimate public IPs. |
| **Bare IP regex is conservative (full dotted-quad only)** | Avoids false positives on strings like `"192 items"` or `"version 10.0"`. Misses exotic encodings — acceptable. |
| **`localhost` hostname is NOT flagged** | Would require either DNS or hardcoded hostname list. Hardcoding `localhost` is tempting but opens the door to `internal.corp`, `metadata.google.internal`, etc. — slippery slope. Clean boundary: IP addresses only. |

---

## 8. What This Does NOT Do

- **No hostname resolution.** `http://localhost/`, `http://metadata.google.internal/` are not caught.
- **No hex/octal IP encoding tricks.** `0x7f000001`, `0177.0.0.1` may not parse.
- **No response inspection.** This checks outbound tool call parameters only.
- **No rate awareness.** Repeated SSRF attempts aren't escalated.
- **No allowlist for "known safe" internal IPs.** Every private IP is blocked. If a user legitimately needs to hit a private IP via a tool, they disable the `ssrf_private_ip` detector in their policy YAML.

All of these are v1 or expansion scope.