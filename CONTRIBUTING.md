# Contributing to AgentSift

Thank you for your interest in contributing to AgentSift! This project aims to make AI agent ecosystems safer for everyone.

## How to Contribute

### Reporting Bugs

- Use the [Bug Report](https://github.com/koach08/agentsift/issues/new?template=bug_report.md) issue template
- Include your Python version, OS, and steps to reproduce

### Suggesting Features

- Use the [Feature Request](https://github.com/koach08/agentsift/issues/new?template=feature_request.md) issue template
- Describe the security problem your feature would address

### Writing Detection Rules

Detection rules are one of the most valuable contributions. See `src/agentsift/rules/` for examples.

```yaml
id: AS-XXX
name: descriptive-rule-name
severity: critical|high|medium|low|info
description: What this rule detects and why it matters
patterns:
  - type: code|behavior|metadata
    match: "pattern"
tags: [category-tags]
ecosystems: [clawhub, mcp, npm, pypi]
```

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
4. Make your changes
5. Run tests: `pytest`
6. Run linting: `ruff check .`
7. Commit with a clear message
8. Push and open a Pull Request

### Code Style

- Python 3.11+
- Format with `ruff format`
- Lint with `ruff check`
- Type hints required for public APIs
- Tests required for new features

## Development Setup

```bash
git clone https://github.com/koach08/agentsift.git
cd agentsift
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Project Structure

```
src/agentsift/
  cli.py          -- CLI entry point (Click)
  scanners/       -- Ecosystem-specific package fetchers
  analyzers/      -- Static analysis, behavioral sandbox, reputation
  reporters/      -- Output formatters (JSON, SARIF, CycloneDX)
  rules/          -- YAML detection rules + rule engine
  models.py       -- Data models (ScanResult, Finding, RiskScore)
tests/            -- Mirror of src/ structure
```

## Pull Request Guidelines

- Keep PRs focused -- one feature or fix per PR
- Add tests for new functionality
- Update documentation if behavior changes
- Reference related issues in the PR description

## Community

- Be respectful and constructive
- Security research requires responsible disclosure -- see [SECURITY.md](./SECURITY.md)
- All contributions are licensed under Apache 2.0

## Priority Areas

We especially welcome contributions in these areas:

1. **Detection rules** for new attack patterns observed in the wild
2. **Scanner support** for additional AI agent ecosystems
3. **Behavioral sandbox** improvements and evasion resistance
4. **Documentation** and internationalization (especially Japanese, Chinese, Korean)
