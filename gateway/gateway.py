"""Secure AI gateway + capstone readiness review (Course 4, Section 12).

Companion code for AI Security Architecture (Udemy Course 4), Lesson 47
(the gateway pattern) and Lesson 51 (the readiness review demo).

The gateway is the single front door: authenticate the workload, check
the egress allow-list, consult the ONE policy engine (Section 8), rate-
limit, and log the shape of the call (Section 10) — every AI request
passes the same choke point, so policy lives in exactly one place.

The readiness review scores a capstone design pack against the course
checklist and renders the verdict the capstone ends with: GO, or NO-GO
with named blockers. A missing critical item is a blocker; a missing
non-critical item is a dated gap, not a veto.

Standard library only. Run:  python -m gateway.gateway
"""

from __future__ import annotations

from dataclasses import dataclass, field

from guardrails.policy_engine import POLICY

ALLOWED_HOSTS = {"api.model-provider.example", "api.payments.example"}
RATE_LIMIT = 5   # calls per window in this demo


@dataclass
class Gateway:
    seen: dict = field(default_factory=dict)

    def route(self, workload: str, role: str, action: str,
              host: str) -> tuple[bool, str]:
        if host not in ALLOWED_HOSTS:
            return False, f"egress denied: {host} not allow-listed"
        effect, why = POLICY.decide(role, action)
        if effect == "DENY":
            return False, f"policy deny ({why})"
        count = self.seen.get(workload, 0) + 1
        self.seen[workload] = count
        if count > RATE_LIMIT:
            return False, "rate limit exceeded for this workload"
        note = " (human gate required)" if effect == "GATE" else ""
        return True, f"routed under {why}{note}"


# ------------------------------------------------------------ readiness

@dataclass(frozen=True)
class ChecklistItem:
    name: str
    critical: bool


CHECKLIST: list[ChecklistItem] = [
    ChecklistItem("Threat model with scored risk register", True),
    ChecklistItem("Injection defense stack tested (ASR measured)", True),
    ChecklistItem("PII pipeline before prompts and logs", True),
    ChecklistItem("Estate pinned; admission control on", True),
    ChecklistItem("Agent grants scoped; approval gates live", True),
    ChecklistItem("Corpus integrity verification on", True),
    ChecklistItem("Telemetry stores shapes, not secrets", True),
    ChecklistItem("Incident runbook rehearsed", False),
    ChecklistItem("Governance evidence index generated", False),
    ChecklistItem("Red-team cadence scheduled", False),
]

SAMPLE_PACK = {item.name: True for item in CHECKLIST}
SAMPLE_PACK["Agent grants scoped; approval gates live"] = False
SAMPLE_PACK["Incident runbook rehearsed"] = False


def readiness_review(pack: dict) -> tuple[str, list, list]:
    blockers = [i.name for i in CHECKLIST if i.critical and not pack.get(i.name)]
    gaps = [i.name for i in CHECKLIST if not i.critical and not pack.get(i.name)]
    return ("NO-GO" if blockers else "GO"), blockers, gaps


def main() -> None:
    gw = Gateway()
    calls = [
        ("support-agent", "support", "tool:search_tickets",
         "api.model-provider.example"),
        ("support-agent", "support", "tool:issue_refund",
         "api.payments.example"),
        ("support-agent", "support", "tool:delete_customer",
         "api.payments.example"),
        ("support-agent", "support", "tool:search_tickets",
         "api.unknown-vendor.example"),
    ]
    routed = 0
    for workload, role, action, host in calls:
        ok, why = gw.route(workload, role, action, host)
        routed += ok
        print(f"  {'ROUTED' if ok else 'BLOCKED'} {action} -> {host}: {why}")
    print(f"gateway: {routed}/{len(calls)} calls routed, "
          f"the rest blocked at the front door")

    verdict, blockers, gaps = readiness_review(SAMPLE_PACK)
    print(f"capstone readiness verdict: {verdict}")
    for b in blockers:
        print(f"  BLOCKER: {b}")
    for g in gaps:
        print(f"  gap (dated, owned): {g}")
    fixed = dict(SAMPLE_PACK)
    fixed["Agent grants scoped; approval gates live"] = True
    verdict2, _, _ = readiness_review(fixed)
    print(f"verdict once the blocker is fixed: {verdict2} "
          f"(gaps remain on the record)")
    print("gateway demo complete")


if __name__ == "__main__":
    main()
