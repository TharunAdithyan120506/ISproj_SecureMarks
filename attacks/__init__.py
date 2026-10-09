"""Attack scripts (security analysis). Each is an importable `run()` plus a CLI:

    python -m attacks.<name> --help
"""

CATALOG = [
    # key, title, goal, expected, cli
    ("tamper_cipher", "Flip one ciphertext byte in flight", "Integrity", "400 integrity_failed",
     "python -m attacks.tamper_cipher"),
    ("tamper_db", "Malicious admin edits marks in the DB (45 → 95)", "Integrity, authenticity", "200 signature_invalid",
     "python -m attacks.tamper_db"),
    ("tamper_db_swap", "Swap another student's ciphertext into the row", "Integrity", "500 record_integrity_failed",
     "python -m attacks.tamper_db --swap"),
    ("replay", "Replay the captured publish at once", "Replay resistance", "409 replay_detected",
     "python -m attacks.replay --last"),
    ("replay_late", "Replay the captured publish after 35 s", "Replay resistance", "409 stale_request",
     "python -m attacks.replay --last --delay 35"),
    ("idor", "s608 asks for a friend's marks", "Authorisation", "403 forbidden", "python -m attacks.idor"),
    ("forge_sig", "Stolen t104 token + attacker's own signing key", "Authentication", "400 bad_signature",
     "python -m attacks.forge_sig"),
    ("revoked_key", "Admin revokes t104, then a publish with that key", "Authentication, key management",
     "403 key_revoked", "python -m attacks.revoked_key --revoke-first"),
    ("bad_login", "20 wrong passwords for t104 in 5 s", "Authentication, availability", "429 rate_limited",
     "python -m attacks.bad_login"),
    ("flood", "10 s flood at 50 req/s with a stolen s612 token", "Availability", "429 rate_limited",
     "python -m attacks.flood --seconds 10 --rate 50 --probe"),
]
