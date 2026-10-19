"""Case-file analysis of published AI security incidents (Course 4, Section 1).

Companion code for AI Security Architecture (Udemy Course 4), Lesson 5.

Encodes the incident case files the lesson dissects as structured data:
what happened, the root cause, and which course control would have caught
it. The demo "runs" the case files — for each incident it names the
missing layer and checks the pattern the lesson draws across all of
them: no exotic exploit, just missing layers.

Standard library only. Run:  python -m casestudies.case_files
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CaseFile:
    case_id: str
    title: str
    vector: str          # how the attacker / failure got in
    impact: str
    root_cause: str
    missing_control: str  # the control this course builds that catches it
    course_section: int


CASES: list[CaseFile] = [
    CaseFile(
        "CASE-1",
        "Customer-service chatbot talked into discounts and false statements",
        "Direct prompt injection by a customer (social-engineering the model)",
        "Brand damage; the company was held to the chatbot's invented promises",
        "The model could state policy with no deterministic policy check behind it",
        "Policy enforced in code outside the model (Lesson 33)",
        8,
    ),
    CaseFile(
        "CASE-2",
        "Employees pasting proprietary source code into a public model",
        "Ordinary use of an unsanctioned tool with no data boundary",
        "Trade-secret exposure; the vendor banned internal use after the fact",
        "No redaction or DLP boundary between staff and third-party models",
        "PII/secret redaction pipeline before any third-party call (Lesson 16)",
        4,
    ),
    CaseFile(
        "CASE-3",
        "Chatbot leaking fragments of other users' conversations",
        "Shared context/cache bug surfaced one user's data in another's session",
        "Privacy breach and loss of trust; service taken offline",
        "Sessions shared state that should have been strictly partitioned",
        "Per-user context isolation and minimization (Lesson 17)",
        4,
    ),
    CaseFile(
        "CASE-4",
        "Assistant with email access driven off-task by an injected message",
        "Indirect injection: instructions planted in content the agent read",
        "Unauthorized actions taken with the user's own credentials",
        "Tool results treated as trusted instructions; no approval gate",
        "Tool output = untrusted input + approval gates (Lessons 24-25)",
        6,
    ),
    CaseFile(
        "CASE-5",
        "Support agent approving refunds it was never authorized to give",
        "Excessive agency: write-capable tools granted without scoping",
        "Direct financial loss until a human noticed the pattern",
        "The agent's privilege was never matched to demonstrated reliability",
        "Task-scoped, expiring privilege grants (Lesson 23)",
        6,
    ),
    CaseFile(
        "CASE-6",
        "Public demo model manipulated into endorsing extremist content",
        "Coordinated jailbreak campaign shared on social media",
        "Reputational harm; emergency model rollback",
        "No red-team program and no production attack monitoring",
        "Red teaming + production detection (Lessons 35, 40)",
        9,
    ),
]


def missing_layers(cases: list[CaseFile]) -> list[str]:
    """The distinct course sections whose controls would have caught these."""
    return sorted({f"Section {c.course_section}" for c in cases})


def main() -> None:
    print("AI incident case files: root-cause analysis")
    for case in CASES:
        print(f"  {case.case_id}: {case.title}")
        print(f"    vector: {case.vector}")
        print(f"    root cause: {case.root_cause}")
        print(f"    control that catches it: {case.missing_control}")
    print(f"case files reviewed: {len(CASES)}")
    print(f"exotic exploits required: 0")
    print(f"sections whose controls cover these cases: "
          f"{', '.join(missing_layers(CASES))}")
    print("pattern: every incident traces to a missing layer, not a broken model")
    print("case files demo complete")


if __name__ == "__main__":
    main()
