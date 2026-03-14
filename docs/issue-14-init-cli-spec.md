# Issue #14: `agentgate init` CLI Command

**Status:** Implementation-ready
**Depends on:** Nothing (no code dependencies on other open issues)
**Blocked by:** Nothing
**Blocks:** #15 (acceptance tests — AT-4 benign workflow uses `agentgate init`)
**Estimated effort:** <1 hour

---

## 1. What This Does

Replace the `init` stub in `cli.py` with real logic that copies the bundled `agentgate.yaml.example` to `./agentgate.yaml` in the current working directory.

This satisfies MVP success criterion **U2**: _"agentgate init generates a working starter policy file with sensible defaults."_

---

## 2. Current State

```python
# cli.py — current stub
@main.command()
def init() -> None:
    """Generate a starter agentgate.yaml policy file."""
    click.echo("Not yet implemented. Coming in PR1.")
```

The source template already exists and is fully functional: `src/agentgate/agentgate.yaml.example`. It demonstrates all four rule types (`tool_allow`, `tool_block`, `param_rule`, `chain_rule`) and all five detectors enabled. It passes `load_and_compile()` validation today.

---

## 3. Behavior Specification

### Happy path

```
$ agentgate init
Created agentgate.yaml — edit this file to define your policy.
```

- Copies `agentgate.yaml.example` from the installed package to `./agentgate.yaml`
- Prints confirmation to stdout
- Exit code: 0

### File already exists

```
$ agentgate init
Error: agentgate.yaml already exists. Remove it first to regenerate.
```

- Does NOT overwrite
- Prints error to stderr
- Exit code: 1

### Template missing (broken install)

```
$ agentgate init
Error: Starter policy template not found in package.
```

- Prints error to stderr
- Exit code: 1

---

## 4. Design Decisions

### How to locate the template

Use `Path(__file__).parent / "agentgate.yaml.example"` from within `cli.py`.

**Why not `importlib.resources`?** The file is co-located in the same package directory as `cli.py`. `__file__` works reliably for both `pip install -e .` (dev) and normal pip installs. `importlib.resources` adds complexity for zero benefit here.

### Destination path

Always `./agentgate.yaml` (current working directory). No `--output` or `--path` flag.

**Why?** The spec defines exactly one policy file location. Every other CLI command (`start`, `logs`) defaults to looking for `agentgate.yaml` in cwd. Adding a destination flag creates a consistency problem — the user generates the file somewhere, then `agentgate start` can't find it. Keep it simple.

### No `--force` flag

If the file exists, refuse and exit 1. User deletes manually to regenerate.

**Why?** Accidental policy overwrite is the more dangerous failure mode than mild inconvenience. A `--force` flag is a v1 nicety if anyone asks for it.

### Output channel

- Confirmation message → stdout (matches Click convention for normal output)
- Error messages → stderr (via `click.echo(..., err=True)`)

This is consistent with the existing `start` and `logs` commands.

---

## 5. Implementation

### File: `src/agentgate/cli.py`

Replace the `init` function body. No new imports needed beyond `pathlib.Path` and `shutil` (both stdlib, lazy-imported inside the function to match the existing pattern in `start`).

```python
@main.command()
def init() -> None:
    """Generate a starter agentgate.yaml policy file."""
    import shutil
    from pathlib import Path

    dest = Path("agentgate.yaml")
    if dest.exists():
        click.echo(
            f"Error: {dest} already exists. Remove it first to regenerate.",
            err=True,
        )
        raise SystemExit(1)

    source = Path(__file__).parent / "agentgate.yaml.example"
    if not source.exists():
        click.echo("Error: Starter policy template not found in package.", err=True)
        raise SystemExit(1)

    shutil.copy2(source, dest)
    click.echo(f"Created {dest} — edit this file to define your policy.")
```

~15 lines replacing 1 line.

### Packaging verification

Confirm `agentgate.yaml.example` is included in wheel builds. Hatchling with `src/` layout includes all files in the package directory by default. If not, add to `pyproject.toml`:

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/agentgate"]
```

**Verification step:** After implementation, run `uv run python -c "from pathlib import Path; import agentgate.cli; print(Path(agentgate.cli.__file__).parent / 'agentgate.yaml.example')"` and confirm the path exists.

---

## 6. Tests

### File: `tests/test_cli_init.py`

Three tests. All use `CliRunner` + `tmp_path` + `os.chdir`. No subprocess, no I/O beyond the temp directory.

#### Test 1: Happy path — creates policy file

```python
def test_init_creates_policy_file(tmp_path, monkeypatch):
    """agentgate init copies the example policy to ./agentgate.yaml."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["init"])

    assert result.exit_code == 0
    dest = tmp_path / "agentgate.yaml"
    assert dest.exists()

    # Content matches the bundled template
    source = Path(__file__).resolve().parent.parent / "src" / "agentgate" / "agentgate.yaml.example"
    assert dest.read_text() == source.read_text()
    assert "Created" in result.output
```

#### Test 2: Refuses overwrite when file exists

```python
def test_init_refuses_overwrite(tmp_path, monkeypatch):
    """agentgate init exits 1 if agentgate.yaml already exists."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "agentgate.yaml").write_text("existing policy content")

    runner = CliRunner()
    result = runner.invoke(main, ["init"])

    assert result.exit_code == 1
    assert "already exists" in result.output
    # File unchanged
    assert (tmp_path / "agentgate.yaml").read_text() == "existing policy content"
```

#### Test 3: Generated file is a valid, loadable policy

```python
def test_init_generates_valid_policy(tmp_path, monkeypatch):
    """The generated agentgate.yaml passes load_and_compile() validation."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["init"])

    from agentgate.policy import load_and_compile
    compiled = load_and_compile(tmp_path / "agentgate.yaml")
    assert compiled.config.version == "0.1"
    assert len(compiled.config.policies) > 0
    assert compiled.config.detectors.sql_injection is True
```

**Why `monkeypatch.chdir` instead of `os.chdir`?** Pytest's `monkeypatch` automatically restores cwd after each test, preventing test pollution. This is the standard pattern.

---

## 7. Acceptance Criteria

| # | Criterion | How to verify |
|---|-----------|---------------|
| 1 | `agentgate init` creates `./agentgate.yaml` | Test 1 |
| 2 | Created file content matches `agentgate.yaml.example` exactly | Test 1 |
| 3 | Exit code 0 on success | Test 1 |
| 4 | Exit code 1 if file already exists | Test 2 |
| 5 | Existing file is never overwritten | Test 2 |
| 6 | Error message printed to stderr on conflict | Test 2 |
| 7 | Generated policy passes `load_and_compile()` | Test 3 |

---

## 8. What This Does NOT Include

- `--output` / `--path` destination flag — use cwd only
- `--force` overwrite flag
- Interactive prompts or policy wizard
- Template selection (multiple starter policies)
- Environment variable override for destination
- Validation of the generated file after copy (the test does this, the CLI doesn't)

All of these are unnecessary for MVP and can be added if users request them.

---

## 9. Risk Assessment

**Risk:** None. This is a file copy with an existence check. The template file is already written and validated.

**Only thing to verify:** That the `.yaml.example` file is included in the built wheel when distributing via PyPI (PR3 concern, not blocking for PR2).

---

## 10. CLAUDE.md Updates

After implementation, update the `cli.py` row in CLAUDE.md:

```
| `cli.py` | Click CLI: `init` (copies starter policy to cwd), `start` (hardened — ...), `logs` (...) — **implemented** |
```

And update the test file listing to include:

```
- `tests/test_cli_init.py` — 3 CLI init tests (happy path, overwrite refusal, valid policy; CliRunner, tmp_path)
```