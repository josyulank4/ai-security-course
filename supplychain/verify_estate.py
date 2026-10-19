"""Model-estate provenance: pinning, signing, drift detection (Course 4, S5).

Companion code for AI Security Architecture (Udemy Course 4), Lesson 22.

The verification pipeline that keeps the production estate equal to the
approved estate:
  * Every artifact (weights, config, dataset manifest, tool definition)
    is registered with a SHA-256 hash in an approved registry.
  * A signature (HMAC over the registry entry, keyed by the release
    process) attests the registry itself was not quietly edited.
  * Admission control: the runtime verifies every artifact against the
    registry before load and REFUSES anything unpinned or drifted.

Standard library only. Run:  python -m supplychain.verify_estate
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

RELEASE_KEY = b"course4-demo-release-key"   # in production: an HSM/KMS key


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Artifact:
    name: str
    kind: str        # weights | config | dataset | tool-definition
    content: bytes


def build_registry(artifacts: list[Artifact]) -> dict:
    entries = {a.name: {"kind": a.kind, "sha256": sha256(a.content)}
               for a in artifacts}
    body = json.dumps(entries, sort_keys=True).encode()
    return {"entries": entries,
            "signature": hmac.new(RELEASE_KEY, body, hashlib.sha256).hexdigest()}


def registry_intact(registry: dict) -> bool:
    body = json.dumps(registry["entries"], sort_keys=True).encode()
    expect = hmac.new(RELEASE_KEY, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, registry["signature"])


def admit(artifact: Artifact, registry: dict) -> tuple[bool, str]:
    """Admission control: returns (admitted, reason)."""
    if not registry_intact(registry):
        return False, "registry signature invalid — estate frozen"
    entry = registry["entries"].get(artifact.name)
    if entry is None:
        return False, f"{artifact.name}: not in the approved registry"
    if entry["sha256"] != sha256(artifact.content):
        return False, f"{artifact.name}: hash drift from the pinned value"
    return True, f"{artifact.name}: verified {entry['kind']} " \
                 f"({entry['sha256'][:12]}…)"


APPROVED = [
    Artifact("support-model-2.1", "weights", b"WEIGHTS::support-model::v2.1"),
    Artifact("support-model-config", "config", b'{"max_tokens": 800}'),
    Artifact("faq-corpus-manifest", "dataset", b"doc-ids: 1001..1042"),
    Artifact("ticket-tool-def", "tool-definition",
             b'{"name": "create_ticket", "write": false}'),
]


def main() -> None:
    registry = build_registry(APPROVED)
    print(f"registry built: {len(registry['entries'])} artifacts pinned, "
          f"signature {'ok' if registry_intact(registry) else 'BAD'}")

    admitted = 0
    for artifact in APPROVED:
        ok, reason = admit(artifact, registry)
        admitted += ok
        print(f"  admit {reason}: {'ADMITTED' if ok else 'REFUSED'}")
    print(f"clean estate admission: {admitted}/{len(APPROVED)} admitted")

    tampered = Artifact("support-model-2.1", "weights",
                        b"WEIGHTS::support-model::v2.1+backdoor")
    ok, reason = admit(tampered, registry)
    print(f"  admit {reason}: {'ADMITTED' if ok else 'REFUSED'}")

    rogue = Artifact("free-helpful-model", "weights", b"WEIGHTS::unknown")
    ok, reason = admit(rogue, registry)
    print(f"  admit {reason}: {'ADMITTED' if ok else 'REFUSED'}")

    edited = json.loads(json.dumps(registry))
    edited["entries"]["support-model-config"]["sha256"] = "0" * 64
    ok, reason = admit(APPROVED[1], edited)
    print(f"  admit {reason}: {'ADMITTED' if ok else 'REFUSED'}")
    print("supply chain demo complete")


if __name__ == "__main__":
    main()
