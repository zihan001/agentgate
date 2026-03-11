# Contributing to AgentGate

AgentGate is in early MVP development. Contributions are welcome, but please check existing issues before starting large changes.

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/agentgate.git
cd agentgate
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

## Code Style

We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

- Type hints are encouraged for all public functions
- Line length limit: 100 characters

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure all tests pass and `ruff check` is clean
5. Submit a PR with a clear description of the change

## Scope

We are building toward a focused MVP. Before contributing a new feature, please open an issue to discuss whether it fits the current scope. See the [MVP Specification](../docs/mvp-spec.md) for what is in and out of scope.
