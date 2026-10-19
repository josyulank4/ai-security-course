# AI Security Architecture — Course Code

Companion code for **AI Security Architecture: Production-Grade Defense
for AI Systems** (Udemy Course 4) by Naveen Kumar Josyula.

Every demo is small, self-contained, and runs **offline with no API
keys**: Python standard library only. The security tools model the real
controls faithfully — a checklist engine, a pattern scanner, policy
checks — so what you run here is the working core of what production
systems scale up.

## Requirements

- Python 3.11+
- No third-party packages (`requirements.txt` is intentionally empty:
  the standard library is the whole dependency list)

## How to run each demo

Run from the repo root:

| Section | Command | What it shows |
|---|---|---|
| S1 · Incident case files | `python -m casestudies.case_files` | Lesson 5's case files as data: six published AI incidents dissected to root cause and the course control that would have caught each — zero exotic exploits, all missing layers |
| S2–S3 · Threat model + scanner | `python -m threatmodel.threat_model` | The Lesson 9 threat-model review: a 20-control checklist (OWASP LLM Top 10 aligned) scored against a sample payments copilot — 17/20 in place, one critical gap (the missing approval gate) — plus a ranked risk register; and the Lesson 13 first-layer injection-pattern scanner: 5/5 attack payloads flagged, 0/2 benign flagged |
| S3 · Injection defense stack | `python -m injectiondefense.defense_stack` | Lesson 13's demo: a payload suite against a mock assistant with no defenses (6/6 succeed), then through the stack — least privilege, spotlighting, screening with encoding normalization, human gates — 0/6 succeed, 0/2 benign mis-flagged |
| S4 · PII redaction | `python -m redaction.redact` | Lesson 16's demo: detect, tokenize, restore — emails, phones, national IDs, secrets, and card numbers verified by Luhn checksum so order numbers are never false-flagged; restore happens only at the user-facing boundary |
| S5 · Supply chain | `python -m supplychain.verify_estate` | Lesson 22's verification pipeline: a signed, hash-pinned artifact registry and admission control that refuses tampered weights, rogue models, and even a quietly edited registry |
| S6 · Agent sandbox | `python -m agentguard.sandbox` | Lesson 25's demo: a policy engine judging agent actions ALLOW / GATE / DENY from task-scoped grants, egress allow-lists and spend caps, with a full audit record — plus Lesson 24's schema validation of tool results |
| S7 · RAG security | `python -m ragsecurity.corpus` | Lesson 28's corpus-integrity checker (provenance + hash verification, unsigned and drifted documents quarantined) and Lesson 29's per-user retrieval ACL enforced as a pre-filter |
| S8 · Guardrails + policy | `python -m guardrails.policy_engine` | Lessons 32–33: one policy-as-code engine consulted at every checkpoint (including an expired waiver that correctly stops working), and a boring, measurable input classifier with its precision/recall stated out loud |
| S9 · Red team harness | `python -m redteam.harness` | Lesson 36's demo: a maintained attack library scored by OWASP class — attack success rate 100% against the bare target, 0% against the defended one |
| S10 · Telemetry + detection | `python -m telemetry.detect` | Lessons 39–40: telemetry that stores hashes and metadata, never raw prompts (PII is redacted before storage), and detection rules that catch probing escalation and tool enumeration |
| S11 · Governance evidence | `python -m governance.evidence` | Lesson 46: every control mapped once to OWASP / EU AI Act / NIST AI RMF clauses, an asset inventory with named owners, and a generated audit evidence index |
| S12 · Gateway + readiness | `python -m gateway.gateway` | Lesson 47's secure gateway (egress allow-list + the one policy engine at a single choke point) and Lesson 51's capstone readiness review: GO / NO-GO with named blockers |

One folder per section, runnable offline, covered by `validate.py`.

## Validation

`python validate.py` runs every demo end to end as a subprocess, checks
the expected output markers, and adds direct assertions per module
(checklist scoring, defense-stack outcomes, Luhn verification, admission
control, sandbox verdicts, corpus quarantine, policy decisions, attack
success rates, telemetry privacy, readiness verdicts). It exits
non-zero if anything fails. Current status: **PASS** (all 12 modules).
