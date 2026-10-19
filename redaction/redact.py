"""PII detection and redaction pipeline (Course 4, Section 4).

Companion code for AI Security Architecture (Udemy Course 4), Lesson 16.

The boundary control of Section 4: before text reaches a model, a log, or
a third-party API, detected PII is replaced with stable tokens
([EMAIL_1], [CARD_1]...). A vault maps tokens back to values and is
consulted ONLY at restore points the policy names (e.g. composing the
final user-facing message) — never before a model call.

Detection layers, in the order the lesson teaches them:
  1. Patterns (regex) for emails, phone numbers, national IDs.
  2. Checksums: a card number is only PII if it passes Luhn — this is
     what keeps order numbers and tracking IDs from false-flagging.
  3. Secret shapes: API keys and tokens that look like data.

Standard library only. Run:  python -m redaction.redact
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
CARD_CANDIDATE = re.compile(r"\b(?:\d{4}[ -]){3}\d{4}\b|\b\d{13,19}\b")
PHONE = re.compile(r"(?<![\w+.])(?:\+\d{1,3}[ -]?)?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
SECRET = re.compile(r"\b(?:sk|ghp|AKIA)[A-Za-z0-9_]{8,}\b|\bBearer\s+\S+")


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class Vault:
    """Token -> original value. Lives outside the prompt, always."""
    entries: dict = field(default_factory=dict)
    counters: dict = field(default_factory=dict)

    def token_for(self, kind: str, value: str) -> str:
        for token, (k, v) in self.entries.items():
            if k == kind and v == value:
                return token
        self.counters[kind] = self.counters.get(kind, 0) + 1
        token = f"[{kind}_{self.counters[kind]}]"
        self.entries[token] = (kind, value)
        return token

    def restore(self, text: str) -> str:
        for token, (_, value) in self.entries.items():
            text = text.replace(token, value)
        return text


def redact(text: str, vault: Vault) -> tuple[str, dict]:
    """Return (redacted_text, counts by kind). Order matters: secrets and
    checksum-verified cards first, so patterns don't half-eat them."""
    counts: dict[str, int] = {}

    def sub(pattern, kind, s, verify=None):
        def repl(m):
            if verify and not verify(m.group(0)):
                return m.group(0)
            counts[kind] = counts.get(kind, 0) + 1
            return vault.token_for(kind, m.group(0))
        return pattern.sub(repl, s)

    text = sub(SECRET, "SECRET", text)
    text = sub(CARD_CANDIDATE, "CARD", text, verify=luhn_ok)
    text = sub(SSN, "NATIONAL_ID", text)
    text = sub(EMAIL, "EMAIL", text)
    text = sub(PHONE, "PHONE", text)
    return text, counts


SAMPLE = (
    "Customer Jane Alvarez (jane.alvarez@example.com, +1 415-555-0132) "
    "paid with card 4242 4242 4242 4242 for order 1234 5678 9012 3456. "
    "Her SSN on file is 078-05-1120. The integration used key "
    "sk_live_9f2Kd81Qx7 internally. Call her back about the refund."
)


def main() -> None:
    vault = Vault()
    cleaned, counts = redact(SAMPLE, vault)
    print("redacted prompt (safe to send to a model):")
    print(f"  {cleaned}")
    print(f"detections: {sum(counts.values())} items across "
          f"{len(counts)} kinds: "
          + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print("order number left untouched (fails Luhn): "
          f"{'1234 5678 9012 3456' in cleaned}")
    restored = vault.restore("Refund issued to [EMAIL_1] for card [CARD_1].")
    print(f"restore at the user-facing boundary only: {restored}")
    print("redaction demo complete")


if __name__ == "__main__":
    main()
