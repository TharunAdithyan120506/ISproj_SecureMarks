"""Authorisation: s608 asks for a friend's marks (roll 240911612).

    python -m attacks.idor

Expected: 403 forbidden, audited as idor_blocked.
"""
from __future__ import annotations

from .common import AttackResult, attacker, from_call, report, with_evidence

NAME, GOAL, EXPECTED = "idor", "Authorisation", "403 forbidden"


def run(friend_roll: str = "240911612") -> AttackResult:
    c = attacker(stolen_login="s608")
    res = c.view_marks(friend_roll)
    return with_evidence(from_call(NAME, GOAL, EXPECTED, res,
                                   f"s608's valid token and session, payload roll_no={friend_roll}",
                                   "the roll number travels encrypted; the server compares it with the token's roll"))


def main() -> None:
    report(run())


if __name__ == "__main__":
    main()
