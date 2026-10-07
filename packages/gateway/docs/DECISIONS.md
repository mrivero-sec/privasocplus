# Decision log

Only recorded decisions are authoritative. Append replacements instead of rewriting history.

| ID | Date | Decision |
|----|------|----------|
| SG1 | 2026-10-07 | The dedicated privasoc profile requires bearer authentication and a bounded manifest of IP/MAC tokens minted by the client. All unlisted addresses are blocked, regardless of token-like ranges. The manifest is stripped before forwarding and never audited. The default general-purpose policy is unchanged. |
| SG2 | 2026-10-07 | Deployments may override the NER backend and actual external model through SOVGATE_NER_BACKEND and SOVGATE_EXTERNAL_MODEL. Missing NER dependencies or weights must fail startup rather than silently disable detection. |
| SG3 | 2026-10-07 | Session scope covers gateway tokens only; client-minted deterministic tokens remain linkable. The manifest trusts the authenticated client and does not prove anonymisation of residual names, quasi-identifiers or values identical to registered tokens. |

| SG4 | 2026-10-07 | Gitleaks 8.30.1 identified two historical occurrences of the synthetic test-secret constant in tests/test_api.py. Only those exact commit/file/rule/line fingerprints are excluded; current constants carry a test-value comment. No broad path, rule or history exclusion is added. |
