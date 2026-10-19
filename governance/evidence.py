"""Governance: control mapping + audit evidence index (Course 4, S11).

Companion code for AI Security Architecture (Udemy Course 4), Lesson 46.

The governance move of Section 11 in code: map every control ONCE to
the clauses it satisfies across frameworks (OWASP LLM Top 10, EU AI
Act, NIST AI RMF, ISO/IEC 42001), keep an inventory where every asset
has a named owner, and then GENERATE the audit evidence index from the
artifacts your pipeline already produces — red-team reports, gate
records, telemetry samples, incident files. Evidence over assertions.

Standard library only. Run:  python -m governance.evidence
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ControlMapping:
    control: str
    owasp: str
    eu_ai_act: str
    nist_rmf: str
    evidence: str        # the artifact that proves the control works


MAPPINGS: list[ControlMapping] = [
    ControlMapping("Injection defense stack", "LLM01",
                   "Art. 15 (robustness)", "MEASURE 2.7",
                   "red-team report: ASR by class, before/after"),
    ControlMapping("PII redaction pipeline", "LLM02",
                   "Art. 10 (data governance)", "MAP 3.4",
                   "redaction test run + log sample, PII-free"),
    ControlMapping("Estate pinning & admission", "LLM03",
                   "Art. 17 (quality management)", "GOVERN 6.1",
                   "registry snapshot + drift-refusal record"),
    ControlMapping("Agent sandbox & approval gates", "LLM06",
                   "Art. 14 (human oversight)", "MANAGE 2.3",
                   "sandbox audit log: ALLOW/GATE/DENY records"),
    ControlMapping("Corpus integrity checks", "LLM04",
                   "Art. 10 (data governance)", "MEASURE 2.11",
                   "corpus verification report with quarantines"),
    ControlMapping("Release gates", "LLM05",
                   "Art. 17 (quality management)", "GOVERN 4.1",
                   "gate evidence packs per release"),
]


@dataclass(frozen=True)
class Asset:
    name: str
    kind: str            # model | agent | dataset | tool
    owner: str


INVENTORY: list[Asset] = [
    Asset("support-model-2.1", "model", "A. Rivera"),
    Asset("payments-copilot", "agent", "J. Chen"),
    Asset("faq-corpus", "dataset", "P. Nair"),
    Asset("ticket-tool", "tool", "J. Chen"),
    Asset("legacy-summarizer", "model", ""),   # the gap the demo finds
]


def evidence_index(mappings: list[ControlMapping]) -> list[str]:
    return [f"{m.control} -> {m.evidence}" for m in mappings]


def unowned(assets: list[Asset]) -> list[str]:
    return [a.name.strip() for a in assets if not a.owner.strip()]


def main() -> None:
    print(f"control mappings: {len(MAPPINGS)} controls mapped across "
          f"OWASP / EU AI Act / NIST AI RMF")
    idx = evidence_index(MAPPINGS)
    for line in idx:
        print(f"  evidence: {line}")
    gaps = unowned(INVENTORY)
    print(f"inventory: {len(INVENTORY)} assets, "
          f"ownerless: {len(gaps)} {gaps}")
    print(f"evidence artifacts indexed: {len(idx)}")
    print("readiness gaps listed before an auditor finds them: "
          f"{len(gaps)}")
    print("governance demo complete")


if __name__ == "__main__":
    main()
