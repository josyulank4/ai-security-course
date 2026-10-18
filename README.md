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
| S2–S3 · Threat model + scanner | `python -m threatmodel.threat_model` | The Lesson 9 threat-model review: a 20-control checklist (OWASP LLM Top 10 aligned) scored against a sample payments copilot — 17/20 in place, one critical gap (the missing approval gate) — plus a ranked risk register; and the Lesson 13 first-layer injection-pattern scanner: 5/5 attack payloads flagged, 0/2 benign flagged |

Further module folders land here section by section as the course is
produced (data protection, supply chain, agent sandboxing, RAG
integrity, guardrails, red-team harness, operations, governance),
following the same pattern: one folder per section, runnable offline,
covered by `validate.py`.

## Validation

`python validate.py` runs every demo end to end as a subprocess, checks
the expected output markers, and adds direct assertions (checklist
scoring, critical-gap detection, risk ranking, scanner true/false
positives). It exits non-zero if anything fails. Current status:
**PASS** (threatmodel module; the suite grows with each section).
