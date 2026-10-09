"""Integrity: an on-path attacker flips one bit of a valid protected publish.

    python -m attacks.tamper_cipher [--byte 10]

Expected: 400 integrity_failed (the AES-GCM tag no longer matches) + audit row.
"""
from __future__ import annotations

import argparse

from .common import AttackResult, attacker, from_call, report, teacher_key, with_evidence

NAME, GOAL, EXPECTED = "tamper_cipher", "Integrity", "400 integrity_failed"


def run(byte_index: int = 10, roll_no: str = "240911608") -> AttackResult:
    c = attacker(stolen_login="t104")  # replays the teacher's own credentials and key on the wire

    def flip(body: bytes) -> bytes:
        i = min(byte_index, len(body) - 1)
        return body[:i] + bytes([body[i] ^ 0x01]) + body[i + 1:]

    res = c.publish_marks(teacher_key(), "IT301", roll_no, 30, 50, mutate_body=flip)
    return with_evidence(from_call(NAME, GOAL, EXPECTED, res,
                                   f"flipped one bit of ciphertext byte {byte_index} in flight",
                                   "the request ID was NOT added to the seen set, so forged garbage cannot fill it"))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--byte", type=int, default=10)
    report(run(ap.parse_args().byte))


if __name__ == "__main__":
    main()
