"""Authentication / key management: after the admin revokes t104's signing key,
a publish signed with it is refused.

    python -m attacks.revoked_key --revoke-first   # admin revokes t104, then the publish
    python -m attacks.revoked_key                  # publish only (key already revoked)

Expected: 403 key_revoked. Records signed before the revocation still verify.
Undo for the next rehearsal:  python scripts\\setup_demo.py --rekey t104
"""
from __future__ import annotations

import argparse

from .common import AttackResult, attacker, device_client, from_call, report, teacher_key, with_evidence

NAME, GOAL, EXPECTED = "revoked_key", "Authentication, key management", "403 key_revoked"


def revoke(username: str = "t104") -> str:
    admin = device_client("admin", "admin")
    res = admin.revoke_signing(username)
    if res.ok:
        return f"admin revoked {username}'s key(s) (audit request {res.request_id[:8]}…)"
    return f"revoke: {res.summary()}"


def run(revoke_first: bool = False, roll_no: str = "240911608") -> AttackResult:
    notes = [revoke()] if revoke_first else []
    c = attacker(stolen_login="t104")
    res = c.publish_marks(teacher_key(), "IT301", roll_no, 30, 50)
    notes += ["signed with t104's real (now revoked) Ed25519 key",
              "undo for the next rehearsal: python scripts\\setup_demo.py --rekey t104"]
    return with_evidence(from_call(NAME, GOAL, EXPECTED, res, *notes))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--revoke-first", action="store_true")
    report(run(ap.parse_args().revoke_first))


if __name__ == "__main__":
    main()
