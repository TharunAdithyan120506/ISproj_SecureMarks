"""Authentication: with a stolen t104 token (but not t104's private key), sign
fake marks with the attacker's own Ed25519 key and claim t104 wrote them.

    python -m attacks.forge_sig

Expected: 400 bad_signature.
"""
from __future__ import annotations

from middleware.crypto import sign
from middleware.crypto.sign import fingerprint

from .common import AttackResult, attacker, from_call, report, with_evidence

NAME, GOAL, EXPECTED = "forge_sig", "Authentication", "400 bad_signature"


def run(roll_no: str = "240911608") -> AttackResult:
    c = attacker(stolen_login="t104")
    forged_key, pub = sign.ed25519_keypair()
    res = c.publish_marks(forged_key, "IT301", roll_no, 30, 50)
    return with_evidence(from_call(NAME, GOAL, EXPECTED, res,
                                   f"record signed with the attacker's key {fingerprint(pub)}, claimed as t104's",
                                   "token, session and AES-GCM all pass; only the signature check stops it"))


def main() -> None:
    report(run())


if __name__ == "__main__":
    main()
