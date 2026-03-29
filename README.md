<p align="center">
  <h1 align="center">AgentSift</h1>
  <p align="center">
    <strong>Security scanner for AI agent plugins, skills, and MCP packages</strong>
  </p>
  <p align="center">
    <code>npm audit</code> for the AI agent ecosystem
  </p>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#quick-start">Quick Start</a> |
  <a href="#supported-ecosystems">Ecosystems</a> |
  <a href="#contributing">Contributing</a> |
  <a href="./ROADMAP.md">Roadmap</a>
</p>

---

## The Problem

AI agent ecosystems are under attack. The numbers are alarming:

- **12% of ClawHub packages** contain malicious payloads ([ClawHavoc incident](https://cyberpress.org/clawhavoc-poisons-openclaws-clawhub-with-1184-malicious-skills/))
- **41.7% of 2,890+ OpenClaw skills** have serious security vulnerabilities
- **43% of MCP servers** have command injection vulnerabilities
- **43% of MCP servers** have OAuth authentication flaws
- **$16M+ in losses** from a single supply chain attack campaign

Traditional security scanners (Snyk, Trivy, Semgrep) were built for traditional software. They cannot detect threats unique to AI agent ecosystems: tool poisoning, prompt injection via plugins, credential theft through MCP servers, and behavioral manipulation of autonomous agents.

**AgentSift fills this gap.**

## Features

- **Static Analysis** -- Detect suspicious patterns: obfuscated code, hidden network calls, credential access, crypto wallet targeting
- **Behavioral Sandbox** -- Execute plugins in an isolated environment and monitor actual system calls, network connections, and file access
- **Reputation Scoring** -- Risk score based on author history, download patterns, code similarity to known malware, and community signals
- **SBOM Generation** -- Software Bill of Materials in CycloneDX/SPDX format for compliance
- **CI/CD Integration** -- SARIF output for GitHub Advanced Security, GitLab SAST, and other platforms
- **Detection Rules** -- Extensible YAML-based rule engine (bring your own rules or use built-in detections)

## Quick Start

```bash
# Install
pip install agentsift

# Scan a ClawHub skill
agentsift scan clawhub:cryptocurrency-trader

# Scan an MCP package from npm
agentsift scan npm:@modelcontextprotocol/server-postgres

# Scan a local plugin directory
agentsift scan ./my-agent-plugin/

# Scan with full behavioral analysis (slower, more thorough)
agentsift scan --deep clawhub:cryptocurrency-trader

# Output SARIF for CI/CD
agentsift scan --format sarif -o results.sarif clawhub:some-skill

# Generate SBOM
agentsift sbom --format cyclonedx clawhub:some-skill
```

## Supported Ecosystems

| Ecosystem | Status | Description |
|-----------|--------|-------------|
| **ClawHub** | `v0.1` | OpenClaw skills marketplace |
| **MCP (npm)** | `v0.1` | Model Context Protocol servers on npm |
| **MCP (PyPI)** | `v0.2` | MCP servers on PyPI |
| **LangChain Hub** | Planned | LangChain tools and chains |
| **CrewAI Tools** | Planned | CrewAI tool packages |
| **Custom** | `v0.1` | Any local directory with agent code |

## How It Works

```
                    +-----------------+
                    |   agentsift     |
                    |   scan <pkg>    |
                    +--------+--------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v------+  +----v--------+
     |   Static   |  | Behavioral  |  | Reputation  |
     |  Analysis  |  |  Sandbox    |  |  Scoring    |
     +--------+---+  +------+------+  +----+--------+
              |              |              |
              +--------------+--------------+
                             |
                    +--------v--------+
                    |  Risk Score &   |
                    |  Report Output  |
                    |  (JSON/SARIF/   |
                    |   CycloneDX)    |
                    +-----------------+
```

### Static Analysis

Scans source code for patterns known to be associated with malicious AI agent plugins:

- **Network exfiltration**: Hidden HTTP calls, DNS tunneling, WebSocket connections to unknown hosts
- **Credential harvesting**: Access to environment variables, SSH keys, browser credential stores, crypto wallets
- **Code obfuscation**: Base64-encoded payloads, `eval()`/`exec()` usage, dynamic imports
- **Prompt injection**: Embedded instructions designed to manipulate the host AI agent
- **Privilege escalation**: Attempts to escape sandboxes, modify system files, or escalate permissions

### Behavioral Sandbox

Executes the plugin in an isolated container and monitors:

- System calls (via seccomp-bpf)
- Network connections (DNS queries, HTTP requests, raw sockets)
- File system access (reads, writes, deletes outside expected paths)
- Process spawning (unexpected child processes)
- Resource consumption (CPU, memory, disk anomalies)

### Reputation Scoring

Calculates a 0-100 risk score based on:

- Author account age and verification status
- Download count and velocity patterns
- Code similarity to known malicious packages (via fuzzy hashing)
- Dependency chain analysis
- Community reports and flags

## Detection Rules

AgentSift uses YAML-based detection rules:

```yaml
# rules/credential-access.yaml
id: AS-001
name: environment-variable-exfiltration
severity: critical
description: Plugin accesses sensitive environment variables and makes network calls
patterns:
  - type: code
    match: "os.environ|process.env"
    context: "network_call_in_same_scope"
  - type: behavior
    match: "dns_query_after_env_read"
tags: [credential-theft, exfiltration]
ecosystems: [clawhub, mcp, npm]
```

Write custom rules and contribute them back to the community!

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan MCP dependencies
  uses: agentsift/agentsift-action@v1
  with:
    targets: "mcp-packages.json"
    fail-on: "high"
```

### GitLab CI

```yaml
agentsift-scan:
  image: agentsift/agentsift:latest
  script:
    - agentsift scan --format sarif -o gl-agentsift-report.sarif ./
  artifacts:
    reports:
      sast: gl-agentsift-report.sarif
```

## Comparison with Existing Tools

| Feature | AgentSift | Cisco MCP Scanner | Snyk | Trivy |
|---------|-----------|-------------------|------|-------|
| AI agent plugin scanning | Yes | MCP only | No | No |
| Behavioral sandbox | Yes | No | No | No |
| ClawHub support | Yes | No | No | No |
| MCP server scanning | Yes | Yes | No | No |
| Prompt injection detection | Yes | No | No | No |
| SBOM generation | Yes | No | Yes | Yes |
| SARIF output | Yes | No | Yes | Yes |
| Custom detection rules | Yes | Limited | No | Yes |

## Project Status

> **Alpha** -- Under active development. APIs may change. Not yet recommended for production use.

See the [Roadmap](./ROADMAP.md) for planned features and milestones.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

Priority areas:
- Detection rules for new attack patterns
- Support for additional ecosystems
- Behavioral sandbox improvements
- Documentation and translations

## Security

Found a vulnerability in AgentSift itself? See [SECURITY.md](./SECURITY.md) for responsible disclosure.

## License

Apache License 2.0 -- See [LICENSE](./LICENSE)

## Acknowledgments

This project is informed by research from:
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner)
- [Meta LlamaFirewall](https://github.com/meta-llama/LlamaFirewall)
- [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw)
- [Ona Research on AI sandbox escapes](https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox)

---

<p align="center">
  Built with the belief that AI agents should be safe by default.
</p>
