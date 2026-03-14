"""Tests for the `agentgate init` CLI command."""

from pathlib import Path

from click.testing import CliRunner

from agentgate.cli import main


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
