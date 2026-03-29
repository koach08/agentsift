---
name: New Detection Rule
about: Propose a new detection rule for malicious patterns
title: "[Rule] "
labels: detection-rule
---

## Attack Pattern

Describe the malicious behavior this rule should detect.

## Real-World Example

Link to a known malicious package or CVE that exhibits this pattern.

## Proposed Rule

```yaml
id: AS-XXX
name:
severity: critical|high|medium|low
category:
description:
patterns:
  - type: code|behavior|metadata
    match: ""
ecosystems: [clawhub, mcp, npm, pypi]
```

## False Positive Risk

How likely is this rule to flag legitimate code? What benign patterns might match?
