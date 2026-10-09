# SecureMarks — Security Middleware Build PRD

Oct 9, 2026 · @Yuvaraj

## 1. Overview and scope

SecureMarks is a policy-driven security middleware (FastAPI) with a student marks portal on top: teachers publish marks, students view only their own, and every encryption, signature, replay check and rate-limit decision is shown live in an inspector and proven on the wire with PyShark. Everything runs on one Windows laptop; the teacher, student and attacker "devices" are simulated with separate loopback addresses.

**Pitch:** the app only says "confidential". The middleware picks the algorithms, manages keys, blocks replays and floods, logs every decision, and the packet capture proves it.

**Stack:** Python 3.11+, FastAPI + Uvicorn, `cryptography`, `argon2-cffi`, `PyJWT`, SQLAlchemy + SQLite, `httpx`, Streamlit, PyShark + Wireshark/Npcap, pandas, matplotlib, `rich`.

| Priority | What | Rule |
| --- | --- | --- |
| P0 | Crypto core (X25519, Ed25519, AES-GCM, SHA-256, HKDF), login + roles, session handshake, protected publish/view, replay + rate + size guards, audit log, key revocation, demo trace + inspector, crypto playground, attack lab (tamper, replay, IDOR, flood), capture + PyShark analyser with graphs, PCAP → SQLite export, quick efficiency benchmark | Must work in tomorrow's demo: these are what the ISL rules require |
| P1 | Data-key rotation, exam-controller verify page, audit hash chain, TLS run, RSA policy option in the live server, PCAP → XML export | Build only after all P0 checks pass |
| P2 | Full 1 KB to 50 MB benchmark, encrypted answer-sheet image attachments, healthcare/document/IoT example scripts, report | After the demo |

## 1a. ISL requirements compliance

SecureMarks meets every ISL rule. Traffic Analysis (Wireshark + PyShark) is the mandatory module, actually built. PCAP Analysis (PCAP → SQLite) is a second one. Five security goals each get a security test and an efficiency measurement, and five devices are simulated on one laptop.

| ISL rule | How SecureMarks meets it | Evidence in the demo and report |
| --- | --- | --- |
| At least one listed module, implemented, not just mentioned | Module 7, Traffic Analysis: `dumpcap` capture + PyShark analyser in `analysis/` | Live capture, analyser CSVs and four graphs |
| (Bonus) second listed module | Module 4, PCAP Analysis: `analysis/pcap_to_sqlite.py` loads every packet and HTTP message into SQLite and joins them with `audit_log`; PCAP → XML via `tshark -T pdml` (P1) | SQL query output: each replay or flood flag matched to its audit entry |
| Multiple security goals | Five ISL goals plus authorisation and replay resistance (matrix below) | Inspector, attack lab, audit log |
| Security analysis | Attack lab: tamper ciphertext, tamper database, replay, view a friend's marks, flood, revoked key | Each attack rejected with its error code, audit entry and packet |
| Efficiency analysis | Benchmark of every algorithm across payload sizes + wire overhead and latency from captures | `bench/out/*.png`, `analysis/out/*.png` |
| At least 2 devices or a simulation | Five simulated devices with their own loopback IPs (127.0.0.2 to .5, and .66 for the attacker), each with its own login, session key and traffic | Wireshark Statistics → Conversations shows five separate hosts talking to the server |
| Same batch, group size | 2 members, both V IT, section B | Synopsis cover |
| 4-member multimedia rule | Not applicable to a 2-member group. P2 stretch: encrypted answer-sheet images | — |

**Security goals: mechanism, security test and efficiency metric**

| Goal | Mechanism | Security test (expected result) | Efficiency metric |
| --- | --- | --- | --- |
| Confidentiality | X25519 session key + AES-GCM in transit; AES-256-GCM at rest | Plain vs protected capture: marks readable vs unreadable; body entropy about 4–5 vs 7.8+ bits/byte | AES-GCM throughput (MB/s) by size; bytes added per request (nonce, tag, headers) |
| Integrity | GCM tag, SHA-256 record hash, AAD binding of headers | Flip one ciphertext byte → `400 integrity_failed`; edit marks in the DB → student's signature check fails | SHA-256 throughput; verify time per record |
| Authentication | Argon2id passwords, 15-minute JWT, Ed25519 record signatures | Wrong password or expired token → `401`; forged signature → `400 bad_signature`; revoked key → `403 key_revoked` | Ed25519 vs RSA-2048 sign/verify time and key/signature sizes; Argon2 hash time; X25519 vs RSA-OAEP handshake time |
| Accountability | Audit log of every decision (hash-chained in P1), trace events | Every attack in the demo appears in the audit log and is matched to its packet by request ID | Audit write cost per request (ms) |
| Availability | Token bucket, size cap, 10 s timeout, concurrency cap of 20 | Flood → `429`s while a normal student keeps loading marks | Requests/s served; normal client's p50/p95 latency during flood vs baseline |
| Authorisation (extra) | Role + ownership checks | Student requests a friend's roll number → `403 forbidden` | Check cost, reported |
| Replay resistance (extra) | Request ID + timestamp bound into AAD, seen-ID set | Replay a captured publish → `409 replay_detected`; replay after 30 s → `409 stale_request` | Seen-set lookup cost, reported |

## 2. Goals, non-goals and roles

The demo must prove all eight security goals from the synopsis on one machine, each visible in the inspector and in a capture.

**Goals**

- Confidentiality: marks travel and rest only as AES-GCM ciphertext.
- Integrity and authenticity: every marks record carries the teacher's Ed25519 signature, checked by the server and again by the student.
- Authentication and authorisation: Argon2 passwords, 15-minute JWTs, role checks on every call.
- Replay resistance: request ID + timestamp bound into the ciphertext; duplicates and stale requests rejected.
- Availability: per-client token bucket, payload size cap, request timeout, concurrency cap.
- Accountability: every decision in an audit log, cross-checked against captures.
- Visibility: a demo mode that shows each crypto step with real values.

**Non-goals:** a production portal, real university data, TLS implemented from scratch, an intrusion detection system, multi-machine deployment.

**Roles and seed accounts** (passwords are demo-only and go in the README)

| Role | Seed user | Simulated device IP | Can | Cannot |
| --- | --- | --- | --- | --- |
| Teacher | `t104` (teaches IT301) | 127.0.0.2 | Publish and update marks for own courses | Publish for other courses, read audit log |
| Student | `s608` (roll 240911608), `s612` (roll 240911612) | 127.0.0.3 | View own marks, verify the teacher's signature | View another roll number |
| Exam controller | `ctrl` | 127.0.0.4 | Verify signatures and hashes, read audit log | See marks plaintext, edit marks |
| Admin | `admin` | 127.0.0.5 | Rotate data keys, revoke signing keys, list keys | Edit marks |
| Attacker (scripts) | none or a stolen student token | 127.0.0.66 | Replay, tamper, flood | Anything that passes the checks |

## 3. Architecture

Four processes run on one Windows laptop: the FastAPI middleware, the Streamlit portal holding the client SDK, the attack scripts, and the capture-and-analysis pipeline. Every client gets its own loopback IP, so the capture shows five separate devices.

&#91;embedded content: SecureMarks architecture · 5 simulated devices, 5 checks, capture pipeline\]

Requests from the portal (and, in red, the attack scripts) pass the five checks top to bottom before anything touches keys or data; the dashed tap shows `dumpcap` recording all of it for PyShark.

| Process | How it runs | Port |
| --- | --- | --- |
| Middleware | `uvicorn middleware.main:app --workers 1` | 8000 (8443 with TLS, P1) |
| Portal + SDK | `streamlit run portal\Home.py` | 8501 |
| Attack scripts | `python -m attacks.<name>` or Attack lab buttons | — |
| Capture + analysis | `python -m analysis.capture`, `analysis.analyze`, `analysis.pcap_to_sqlite` | — |

## 4. Cryptography spec

X25519 (key exchange) and Ed25519 (signatures) replace RSA as the default; AES-GCM protects all data; SHA-256 fingerprints every record. RSA stays as a P1 policy option and in the benchmark, for the comparison the synopsis promises. All primitives come from the `cryptography` library: no hand-written crypto.

| Purpose | Algorithm and parameters | Where it runs | Python call |
| --- | --- | --- | --- |
| Key exchange | X25519, fresh keypair on both sides per session | SDK and `POST /api/session` | `X25519PrivateKey.generate()`, `.exchange(peer_pub)` |
| Key derivation | HKDF-SHA256; length 32 (confidential) or 16 (normal); salt = session ID bytes; info = `b"securemarks/v1/session"` | Both sides | `HKDF(...).derive(shared)` |
| Transport encryption | AES-GCM, new random 12-byte nonce per message, AAD binds request metadata (section 5) | Every protected request and response | `AESGCM(key).encrypt(nonce, data, aad)` |
| Encryption at rest | AES-256-GCM with the active data key (DEK); AAD = \`marks | {course} | {roll\_no}\` so rows can't be swapped |
| Key wrapping | DEK wrapped by the master key (KEK) with AES-256-GCM; KEK = 32 random bytes in `secrets/master.key`, never in the DB or git | Key manager | same |
| Hashing | SHA-256 over the canonical record bytes | Teacher SDK, server, student SDK | `hashlib.sha256(b).digest()` |
| Signature | Ed25519 over the SHA-256 digest (64-byte signature) | Teacher signs; server and student verify | `priv.sign(digest)`, `pub.verify(sig, digest)` |
| Passwords | Argon2id, library defaults | `users` table | `PasswordHasher().hash()` / `.verify()` |
| Login token | JWT HS256, 15-minute expiry, secret in `.env` | Auth | `jwt.encode()` / `jwt.decode()` |
| P1 comparison | RSA-OAEP-2048 (SHA-256) key transport + RSA-PSS-2048 signatures | Policy `legacy-rsa`, benchmark | `rsa.generate_private_key(65537, 2048)` |

**Canonical marks record** (what gets hashed and signed): `json.dumps(record, sort_keys=True, separators=(",", ":")).encode()` with fields `course`, `roll_no`, `midsem`, `endsem`, `total`, `teacher`, `published_at` (ISO 8601 UTC).

**Teacher signing key:** generated by `scripts/setup_demo.py`, private key saved to `client_keys/t104_ed25519.pem` (PKCS8, encrypted with the teacher's password); only the public key is stored on the server in `signing_keys`.

**Hard rules**

- Never reuse a nonce with the same key: always `os.urandom(12)`.
- Never log plaintext marks, passwords or keys. Demo mode shows keys only as first 4 and last 4 bytes in hex (`4c1e…9a02`).
- Every failed check raises, is caught once, and maps to an error code (section 5); no silent fallbacks.

## 5. Request lifecycle and wire format

Every protected call is a `POST` with an encrypted body, and the middleware runs the same checks in a fixed order, stopping at the first failure and auditing the outcome either way.

**Protected request on the wire**

| Part | Value |
| --- | --- |
| Method and type | `POST`, `Content-Type: application/octet-stream` |
| `Authorization` | `Bearer <JWT>` |
| `X-Session-ID` | From `POST /api/session` |
| `X-Request-ID` | `uuid4()` per request |
| `X-Timestamp` | Unix seconds (int) |
| `X-Nonce` | Base64 of the 12-byte AES-GCM nonce |
| `X-Policy` | `confidential` or `normal` |
| `X-Device` | `teacher-laptop`, `student-laptop`, `ctrl-pc`, `admin-pc`, `attacker` (fallback device label for the analyser) |
| Body | Raw AES-GCM ciphertext + 16-byte tag of the JSON payload. Raw bytes, not base64, so entropy measurements are honest |
| AAD | \`f"{method} |

**Response:** success = `200`, body is ciphertext under the same session key, new `X-Nonce` header, AAD = `f"resp|{request_id}".encode()`. Errors = plain JSON `{"error": "<code>", "detail": "...", "request_id": "..."}`, readable in Wireshark on purpose (no secrets in them).

**Check order**

1. Concurrency cap: `asyncio.Semaphore(20)`, none free → `503 busy`.
2. Size cap: `Content-Length` above the policy's max (global hard cap 5 MB) → `413 too_large`.
3. Rate limit: token bucket keyed on the JWT `sub` if a token parses, else the source IP → `429 rate_limited` + `Retry-After`.
4. Authentication: JWT valid and unexpired → else `401 auth_failed`.
5. Session: exists, same user, unexpired (15 min) → else `401 session_invalid`.
6. Freshness: `abs(now - X-Timestamp) <= replay_window` (30 s) → else `409 stale_request`.
7. Replay: `X-Request-ID` not already seen → else `409 replay_detected`.
8. Decrypt with session key + AAD → `InvalidTag` gives `400 integrity_failed`. Only after success is the request ID stored as seen (expiry = 2 × window), so forged garbage can't fill the table.
9. Role and ownership (RBAC) → `403 forbidden`.
10. Handler and policy rules: missing or bad Ed25519 signature → `400 bad_signature`; revoked signing key → `403 key_revoked`. Handler wrapped in `asyncio.wait_for(..., 10)` → `504 timeout`.
11. Audit entry for every outcome, and trace events when `DEMO_MODE=1`.

**Implementation notes**

- Steps 1–3 are Starlette middleware. FastAPI runs the last-added middleware first, so add them in reverse order.
- Steps 4–9 are one dependency, `secure_request(role, policy)`, that returns the decrypted payload dict to the route.
- Crypto-heavy routes are plain `def` (FastAPI runs them in a thread pool) so one big request can't freeze the event loop.
- Run Uvicorn with one worker: the seen-request set, sessions and token buckets live in memory.

## 6. API contract

Fifteen endpoints: four plain setup calls, seven protected calls that go through the full check order, and four demo-only helpers. "Payload" means the decrypted JSON for protected calls.

| Endpoint | Who | Wire | Policy | Payload in | Payload out |
| --- | --- | --- | --- | --- | --- |
| `POST /api/auth/login` | Anyone | Plain JSON | — | `{username, password}` | `{token, role, roll_no?, courses?, expires_in}` |
| `GET /api/policies` | Anyone | Plain | — | — | Contents of `policies.yaml` |
| `POST /api/session` | Any JWT | Plain JSON (public keys only) | Chosen by client | `{client_pub_b64, policy}` | `{session_id, server_pub_b64, kdf, key_len, expires_in}` |
| `GET /api/keys/signing/{username}` | Any JWT | Plain | — | — | `{alg, public_key_b64, status, fingerprint}` (first 8 bytes of SHA-256, hex) |
| `POST /api/marks/publish` | Teacher, own course only | Protected | confidential | `{record, signature_b64, sig_alg: "Ed25519"}` | `{record_id, version, sha256}` |
| `POST /api/marks/view` | Student (roll must equal the token's roll); teacher (own course) | Protected | confidential | `{roll_no}` | `{records: [{record, signature_b64, signer, sig_alg, sha256}]}` |
| `POST /api/marks/verify` | Exam controller | Protected | normal | `{record_id}` | `{sha256_ok, signature_ok, signer, key_status}`, no marks |
| `POST /api/audit/list` | Exam controller, admin | Protected | normal | `{limit, since_id}` | `{entries, chain_ok}` (`chain_ok` is P1) |
| `POST /api/admin/keys/list` | Admin | Protected | normal | `{}` | `{data_keys, signing_keys}` (metadata only) |
| `POST /api/admin/keys/rotate` | Admin | Protected | normal | `{}` | `{new_version}` (P1) |
| `POST /api/admin/signing/revoke` | Admin | Protected | normal | `{username}` | `{status: "revoked"}` |
| `GET /plain/marks/{roll_no}` | Anyone, `DEMO_MODE` only | Unprotected baseline | — | — | Plaintext record JSON |
| `POST /plain/publish` | Anyone, `DEMO_MODE` only | Unprotected baseline | — | Record JSON | `{ok: true}` |
| `GET /demo/trace/{request_id}` | Any JWT, `DEMO_MODE` only | Plain | — | — | `{steps: [{side, step, detail, ok, ts}]}` |
| `GET /health` | Anyone | Plain | — | — | `{ok: true}` |

**Behaviour notes**

- Publish never overwrites: a new row with `version + 1` is inserted and `view` returns the latest version. Old versions are what the replay "rollback" attack would try to restore.
- `view` for a student checks the roll number: if `roll_no` differs from the token's roll, it returns `403 forbidden` and audits `idor_blocked`. That is the "friend's marks" demo.
- Login sends the password as plain JSON. Over HTTP it is visible in Wireshark; that is a deliberate finding for the HTTP vs TLS experiment.

## 7. Data model, policies and key management

One SQLite file (`data/securemarks.db`) holds six tables; sessions, seen request IDs and token buckets live in memory because the demo runs one Uvicorn worker.

| Table | Columns |
| --- | --- |
| `users` | `id`, `username` (unique), `pw_hash` (Argon2id), `role` (teacher, student, ctrl, admin), `roll_no`, `courses` (comma list), `created_at` |
| `signing_keys` | `id`, `username`, `alg` (Ed25519), `public_key` (32 bytes), `fingerprint`, `status` (active, revoked), `created_at`, `revoked_at` |
| `data_keys` | `id`, `version`, `alg` (AES-256-GCM), `wrapped_key`, `wrap_nonce`, `status` (active, retired, revoked), `created_at`, `expires_at` |
| `marks` | `id`, `course`, `roll_no`, `version`, `ciphertext`, `nonce`, `dek_id`, `sha256` (hex), `signature` (64 bytes), `signer`, `sig_alg`, `published_at`, `request_id` |
| `audit_log` | `id`, `ts`, `request_id`, `actor`, `role`, `src_ip`, `device`, `action`, `outcome` (allowed, denied, error), `code`, `detail`, `prev_hash`, `entry_hash` |
| `trace_events` | `id`, `request_id`, `side` (client, server), `step`, `detail`, `ok`, `ts` |

**`config/policies.yaml`**

```yaml
confidential:
  cipher: AES-256-GCM
  key_exchange: X25519
  kdf: HKDF-SHA256
  key_len: 32
  signature: Ed25519        # required on publish
  max_payload_kb: 512
  rate_limit: {capacity: 10, refill_per_sec: 2}
  replay_window_s: 30
  audit: full
normal:
  cipher: AES-128-GCM
  key_exchange: X25519
  kdf: HKDF-SHA256
  key_len: 16
  signature: none
  max_payload_kb: 5120
  rate_limit: {capacity: 30, refill_per_sec: 10}
  replay_window_s: 60
  audit: decisions
legacy-rsa:                 # P1, for comparison only
  cipher: AES-256-GCM
  key_exchange: RSA-OAEP-2048
  signature: RSA-PSS-2048
  max_payload_kb: 512
  rate_limit: {capacity: 10, refill_per_sec: 2}
  replay_window_s: 30
  audit: full
```

Load it with a Pydantic model at startup; an unknown cipher or missing field stops the server. Each route declares its minimum policy; a session opened with a weaker one gets `403 policy_too_weak`.

**Key lifecycle**

- Setup creates the master key (KEK), data key v1 (active, expires in 180 days), the seed users and the teacher's Ed25519 keypair.
- Encrypt always uses the active data key. Decrypt looks up the record's `dek_id` and refuses a revoked key; an expired key is decrypt-only.
- Rotate (P1): the new version becomes active, the old one becomes retired. Old records still open; new publishes use the new key.
- Revoke a signing key: further publishes by that teacher get `403 key_revoked`. Records signed before `revoked_at` still verify, and the student view notes the revocation date.
- Audit chain (P1): `entry_hash = SHA-256(prev_hash + canonical entry)`; `audit/list` recomputes it and returns `chain_ok`.

## 8. Portal, inspector and demo mode

One Streamlit app (`portal/Home.py`) with role-based pages. For the demo, open two browser windows side by side, teacher on the left and student on the right; each Streamlit tab is its own session, so they behave as two separate devices.

| Page | Who sees it | What it does |
| --- | --- | --- |
| Login | Everyone | Username + password → JWT; the role picks the simulated device IP and label |
| Publish marks | Teacher | Form: course (own courses only), roll no, midsem, endsem. A toggle sends the same record to `/plain/publish` for the baseline run. Inspector below |
| My marks | Student | Marks card with a green "Verified · signed by t104 · fingerprint" or red "Signature invalid". A box to try another roll number (IDOR demo). Inspector below |
| Verify and audit | Exam controller | Verify a record by ID without seeing marks; audit log table filterable by action and outcome; `chain_ok` badge (P1) |
| Keys | Admin | Data keys and signing keys (metadata only); revoke `t104`; rotate data key (P1) |
| Crypto playground | Everyone, no login | Four panels, below |
| Attack lab | Everyone | One button per attack (section 10); shows the response code, the audit entry and the matching trace |
| Traffic lab | Everyone | Start/stop capture, list `.pcapng` files, run the analyser and PCAP → SQLite, show graphs, flags and the SQL join, "Open in Wireshark" button (`os.startfile`) |
| Benchmarks | Everyone | Run the quick benchmark, show the graphs |

**Crypto playground panels**

1. AES-GCM: type text → random key and nonce → ciphertext + tag in hex → decrypt back. A "flip one byte" checkbox makes decryption fail with `InvalidTag`.
2. SHA-256: two text boxes; change one character and see the two digests differ completely (avalanche effect), with the count of differing bits.
3. Ed25519: generate a keypair, sign a message, verify. Editing the message after signing makes verification fail.
4. X25519: Alice and Bob each generate a keypair; both compute the same shared secret; "Eve" sees only the two public keys and cannot compute it.

**Inspector** (`portal/components/inspector.py`, `render_trace(client_steps, request_id)`): merges the SDK's client-side steps with server steps from `GET /demo/trace/{request_id}` into one table: side, step, value (hex shortened to about 32 characters), and a pass / fail / skipped pill.

| Side | Steps recorded, in order |
| --- | --- |
| Teacher SDK | `build_record`, `canonicalize`, `sha256`, `ed25519_sign`, `x25519_keypair` and `hkdf_derive` (once per session), `aesgcm_encrypt` (nonce, ciphertext length, tag), `send` |
| Server | `rate_limit`, `auth_jwt`, `session_lookup`, `freshness`, `replay_check`, `aesgcm_decrypt`, `sig_verify`, `rbac`, `encrypt_at_rest`, `audit_write` |
| Student SDK | `aesgcm_decrypt_response`, `sha256_recompute`, `ed25519_verify` |

**Server console:** the middleware prints one coloured `rich` line per step, for example `[7f3a] PASS aesgcm_decrypt AES-256-GCM 812 B`. Keep this terminal visible as the third "screen".

**Demo mode** (`DEMO_MODE=1` in `.env`): turns on trace events, the `/plain/*` baseline endpoints and `/demo/trace`. With `0` they return 404 and nothing is traced. Keys are always shown truncated.

**Device simulation in the SDK:** `SecureClient(base_url, device_ip, device_label)` builds `httpx.Client(transport=httpx.HTTPTransport(local_address=device_ip))`. The role-to-IP map lives in `config/devices.yaml`. Every call returns `(payload, trace, request_id)`.

## 9. Traffic analysis module (ISL modules 7 and 4)

`dumpcap` captures the Npcap loopback adapter into one `.pcapng` per experiment. `analysis/analyze.py` reads it with PyShark, rebuilds every HTTP message from raw TCP payloads and writes CSVs and graphs. `analysis/pcap_to_sqlite.py` loads the same messages into SQLite and joins them with the audit log.

**Capture on Windows**

- Install Wireshark with Npcap and keep "Support loopback traffic capture" ticked.
- Find the adapter: `& "C:\Program Files\Wireshark\tshark.exe" -D` and look for "Adapter for loopback traffic capture" (`\Device\NPF_Loopback`).
- Capture: `& "C:\Program Files\Wireshark\dumpcap.exe" -i \Device\NPF_Loopback -f "tcp port 8000 or tcp port 8443" -w captures\exp1_plain_vs_protected.pcapng`
- `python -m analysis.capture start --name exp1` / `stop` wraps this with `subprocess.Popen`; the Traffic lab page calls it.
- Never run PyShark `LiveCapture` inside Streamlit (asyncio conflicts on Windows). Always analyse saved files in a separate `python -m` process.

**Analyser steps** (`python -m analysis.analyze captures\exp3_replay.pcapng --audit data\securemarks.db`)

1. `pyshark.FileCapture(path, display_filter="tcp.port==8000 && tcp.len>0", keep_packets=False)`. Per packet: frame time and length, IPs and ports, `tcp.stream`, `tcp.seq`, `tcp.payload` (hex → bytes). A second pass with `display_filter="tcp.analysis.retransmission"` counts retransmissions per stream.
2. Group payloads by stream and direction, join them in sequence order, and parse HTTP/1.1: start line, headers up to `\r\n\r\n`, body by `Content-Length`. Working from raw bytes avoids dissector quirks with binary bodies.
3. Pair the n-th request with the n-th response in each stream (keep-alive keeps them in order).
4. One row per request: request and response times, latency (ms), source IP, device (`X-Device` header, else the IP map), method, path, status, error code, `X-Request-ID`, `X-Timestamp`, body bytes, bytes on the wire (sum of frame lengths), body entropy.
5. Flags: `replay` = a request ID already seen in the capture within 30 s; `flood` = a source above 5 requests/s in any 1-second window.
6. Cross-check: each flagged request ID is looked up in `audit_log`; the output lists matched outcomes and any flag with no audit entry.

Body entropy, in bits per byte (p\_i = share of byte value i in the body):

```latex
H = -\sum_{i=0}^{255} p_i \log_2 p_i
```

Plaintext JSON lands around 4–5; ciphertext of 1 KB or more lands at 7.8 or above. Report bodies under 256 bytes separately, because small samples read low.

**Outputs** in `analysis/out/<capture name>/`: `messages.csv`, `flows.csv`, `flags.csv`, and four graphs: `entropy_plain_vs_protected.png`, `overhead_bytes.png` (body vs bytes on the wire per endpoint), `latency_by_device.png`, `rate_timeline.png` (requests/s per device with 429s marked).

**PCAP → SQLite (module 4):** `python -m analysis.pcap_to_sqlite captures\exp3_replay.pcapng` writes `packets(frame, ts, src, dst, sport, dport, stream, length, retrans)` and `http_messages(...)` to `data\capture_exp3_replay.db`, attaches the main DB and runs:

```sql
ATTACH 'data/securemarks.db' AS app;
SELECT m.ts, m.device, m.request_id, m.status, a.action, a.outcome, a.code
FROM http_messages m
LEFT JOIN app.audit_log a ON a.request_id = m.request_id
WHERE m.flag IN ('replay', 'flood')
ORDER BY m.ts;
```

**PCAP → XML (P1):** `tshark -r captures\exp1_plain_vs_protected.pcapng -T pdml > analysis\out\exp1.xml`.

**TLS captures:** HTTP can't be parsed, so the analyser reports per-stream packets, bytes, timing and TLS record entropy only. That is the point: content is hidden, metadata isn't.

**Experiments**

| # | Experiment | Steps | Capture file | Evidence |
| --- | --- | --- | --- | --- |
| 1 | Plain vs protected | Teacher publishes the same record to `/plain/publish` and `/api/marks/publish`; student views both | `exp1_plain_vs_protected` | Marks readable vs unreadable; entropy graph; overhead graph |
| 2 | HTTP vs TLS | Login + publish on port 8000, then on 8443 with TLS (P1) | `exp2_http`, `exp2_tls` | Password, JWT and headers visible over HTTP; only sizes and timing over TLS |
| 3 | Replay | Teacher publishes; attacker replays that packet at once, then after 30 s | `exp3_replay` | Same request ID twice; `409 replay_detected`, then `409 stale_request`; audit match in the SQL join |
| 4 | Result-day flood | Attacker floods `/api/marks/view` for 10 s while the student refreshes every second | `exp4_flood` | Rate spike, 429s, student latency stays close to baseline |
| 5 | Multi-device roles | Teacher publishes, student views own marks, student tries a friend's roll, controller verifies | `exp5_devices` | Five hosts in Conversations, `403` on the friend attempt, latency per device |

**Windows fallback:** if binding to `127.0.0.x` fails, or a capture shows every packet as `127.0.0.1`, the analyser still separates devices by the `X-Device` header, so no experiment depends on the loopback IPs.

## 10. Attack scripts and benchmarks

Eight attack scripts make up the security analysis and one benchmark script makes up the efficiency analysis. Each attack is an importable function with a CLI, so the Attack lab page and the terminal run the same code.

**Attacks** (`attacks/`, all from simulated IP 127.0.0.66, `X-Device: attacker`)

| Script | What it does | Expected result | Goal tested |
| --- | --- | --- | --- |
| `tamper_cipher.py` | Valid protected publish with one ciphertext byte flipped (SDK `mutate_body` hook) | `400 integrity_failed` + audit | Integrity |
| `tamper_db.py` | Plays a malicious server admin: decrypts t104's record for roll 240911608 with the data key, changes endsem 45 → 95, re-encrypts, writes it back; signature untouched. `--swap` instead copies another student's ciphertext into the row | Student page shows red "Signature invalid"; `--swap` fails decryption (AAD mismatch) → `500 record_integrity_failed` + audit | Integrity, authenticity |
| `replay.py` | `--pcap captures\exp3_replay.pcapng --path /api/marks/publish [--delay 35]` extracts the raw request with the analyser's parser and resends it byte for byte over a socket bound to 127.0.0.66. `--last` uses `captures\last_request.bin` saved by the SDK in demo mode | `409 replay_detected`; with `--delay 35`, `409 stale_request` | Replay resistance |
| `idor.py` | Logs in as s608 and asks for roll 240911612 | `403 forbidden`, audit `idor_blocked` | Authorisation |
| `forge_sig.py` | Signs a record with the attacker's own Ed25519 key and claims it is t104's | `400 bad_signature` | Authentication |
| `revoked_key.py` | After the admin revokes t104, publishes as t104 | `403 key_revoked` | Authentication, key management |
| `bad_login.py` | 20 wrong passwords for t104 in 5 s | `401`s, then `429` (rate limit keyed on IP before login) | Authentication, availability |
| `flood.py` | `--seconds 10 --rate 50` with a stolen s612 token on `/api/marks/view`; `--probe` runs s608 at 1 request/s and logs latency to CSV | Mostly `429`; s608 keeps getting `200` with latency close to baseline | Availability |

**Benchmarks** (`python -m bench.bench --quick` for P0, about a minute; `--full` adds 50 MB and the extra algorithms)

| Group | Compared | Sizes or runs | Metrics |
| --- | --- | --- | --- |
| Symmetric | AES-128-GCM vs AES-256-GCM, encrypt + decrypt | 1 KB, 10 KB, 100 KB, 1 MB, 10 MB (+ 50 MB full) | Median ms, MB/s |
| Hash | SHA-256 | Same sizes | Median ms, MB/s |
| Signatures | Ed25519 vs RSA-PSS-2048 (+ RSA-3072, ECDSA P-256 full) | 200 sign/verify, 20 keygens | Keygen, sign and verify ms; public key and signature bytes |
| Key exchange | X25519 vs ECDH P-256 vs RSA-OAEP-2048 wrap/unwrap vs DH-2048 (RFC 3526 group 14 parameters, so no slow parameter generation) | 200 runs | ms per exchange |
| Passwords | Argon2id hash and verify | 20 runs | ms |
| End to end | 200 protected publish + view round trips vs 200 plain | Through the SDK | p50/p95 latency; bytes on the wire per request (from the exp1 capture) |

Use `time.perf_counter()` with warm-up runs and medians; record the CPU from `platform.processor()`. Outputs: `bench/out/results.csv`, `sym_throughput.png`, `sig_compare.png`, `kex_compare.png`, `e2e_latency.png`.

## 11. Repo, requirements and Windows setup

One repo, one virtual environment, three terminals (server, portal, capture) plus Wireshark. No Docker.

```text
securemarks/
├── .env                      # DEMO_MODE, JWT_SECRET, DB path, ports
├── requirements.txt
├── README.md                 # demo accounts, run commands
├── config/
│   ├── policies.yaml
│   └── devices.yaml          # role -> loopback IP + device label
├── middleware/
│   ├── main.py               # app, middleware order, routers
│   ├── settings.py
│   ├── crypto/  aead.py  kex.py  sign.py  hashing.py  canonical.py
│   ├── keys/    manager.py   # KEK load, DEK wrap/unwrap, rotate, revoke
│   ├── policy/  engine.py
│   ├── auth/    passwords.py  tokens.py  rbac.py
│   ├── guards/  concurrency.py  size.py  ratelimit.py  replay.py  timeout.py
│   ├── secure.py             # secure_request() dependency, envelope encrypt/decrypt
│   ├── audit.py  trace.py
│   ├── api/     auth.py  session.py  marks.py  admin.py  audit.py  plain.py  demo.py
│   └── db/      models.py  session.py
├── sdk/
│   └── client.py             # SecureClient: login, handshake, call(), trace
├── portal/
│   ├── Home.py
│   ├── pages/   1_Publish.py  2_My_Marks.py  3_Verify_Audit.py  4_Keys.py
│   │            5_Crypto_Playground.py  6_Attack_Lab.py  7_Traffic_Lab.py  8_Benchmarks.py
│   └── components/inspector.py
├── attacks/  tamper_cipher.py  tamper_db.py  replay.py  idor.py  forge_sig.py
│             revoked_key.py  bad_login.py  flood.py
├── analysis/ capture.py  analyze.py  httpparse.py  pcap_to_sqlite.py  plots.py
├── bench/    bench.py
├── scripts/  setup_demo.py  make_cert.py
├── tests/    test_crypto.py  test_guards.py  test_flow.py
├── secrets/  master.key  server.key  server.crt   # gitignored
├── client_keys/  t104_ed25519.pem              # gitignored
├── data/     securemarks.db                    # gitignored
└── captures/                                   # gitignored
```

**`requirements.txt`**

```text
fastapi>=0.110
uvicorn[standard]>=0.29
pydantic>=2.6
cryptography>=42
argon2-cffi>=23.1
PyJWT>=2.8
SQLAlchemy>=2.0
httpx>=0.27
streamlit>=1.35
pyshark>=0.6
pandas>=2.2
matplotlib>=3.8
rich>=13.7
PyYAML>=6.0
python-dotenv>=1.0
pytest>=8.0
```

**`.env`**

```text
DEMO_MODE=1
JWT_SECRET=<64 random hex chars, written by setup_demo.py>
DB_PATH=data/securemarks.db
SERVER_URL=http://127.0.0.1:8000
TLS_URL=https://127.0.0.1:8443
```

**One-time setup (PowerShell)**

1. Install Python 3.11 or newer from python.org and tick "Add python.exe to PATH".
2. Install Wireshark; in the bundled Npcap installer keep "Support loopback traffic capture" ticked; include TShark.
3. In the project folder: `py -3.11 -m venv .venv`, then `.\.venv\Scripts\Activate.ps1`. If PowerShell blocks it, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
4. `pip install -r requirements.txt`
5. `python scripts\setup_demo.py`: writes `.env` secrets, the master key, data key v1, seed users, t104's Ed25519 keypair and (P1) the self-signed TLS certificate with SAN `IP:127.0.0.1`. Re-running it with `--reset` wipes the DB for a clean demo.
6. `pytest -q`: all tests green before any demo run.

**Run it (three terminals, venv active in each)**

| Terminal | Command |
| --- | --- |
| 1. Server | `uvicorn middleware.main:app --host 127.0.0.1 --port 8000 --workers 1` |
| 1b. TLS server (P1) | `uvicorn middleware.main:app --host 127.0.0.1 --port 8443 --workers 1 --ssl-keyfile secrets\server.key --ssl-certfile secrets\server.crt` |
| 2. Portal | `streamlit run portal\Home.py` (opens http://localhost:8501) |
| 3. Capture | `python -m analysis.capture start --name exp1_plain_vs_protected`, then `stop` |

Bind only to `127.0.0.1` so Windows Firewall never prompts. Keep the server and portal running on one PC clock, so timestamp checks never fail from clock drift.

## 12. Build order for tonight

About 11 hours of build in nine blocks. Each block ends with a check that must pass before the next starts. Build the server and SDK first and the UI last, so a half-finished night still leaves a demo-able terminal flow.

| Block | Hours | Build | Done when |
| --- | --- | --- | --- |
| 1. Setup + crypto core | 0–1 | Repo skeleton, `requirements.txt`, `middleware/crypto/*`, `tests/test_crypto.py` | Round trips pass; flipped byte → `InvalidTag`; wrong key fails; edited message → `InvalidSignature`; X25519 both sides derive equal keys |
| 2. DB, keys, policy, seed | 1–2 | Models, `keys/manager.py`, `policy/engine.py`, `config/*.yaml`, `scripts/setup_demo.py` | `setup_demo.py --reset` creates DB, five users, DEK v1, t104 keypair; policies load and validate |
| 3. Auth, session, envelope | 2–3.5 | Login, JWT, `/api/session`, `secure.py`, `sdk/client.py` with `call()` and trace | SDK logs in, handshakes, and a protected echo call round-trips |
| 4. Guards + audit + trace | 3.5–4.5 | Concurrency, size, rate, freshness, replay; `audit.py`, `trace.py`, `rich` console, error codes | `tests/test_guards.py`: duplicate ID → 409, old timestamp → 409, 11 fast calls → 429, 6 MB body → 413; every outcome audited |
| 5. Marks + admin + plain endpoints | 4.5–5.5 | Publish, view, verify, audit list, keys list, revoke, `/plain/*`, `/demo/trace` | `tests/test_flow.py`: t104 publishes, s608 sees verified marks, s608 → roll 612 is 403, revoked key → 403 |
| 6. Portal | 5.5–7.5 | Login, Publish, My marks, inspector, Crypto playground, then Verify/Audit and Keys | Teacher and student windows side by side; inspector shows client and server steps for one publish |
| 7. Attacks + Attack lab | 7.5–8.5 | All eight `attacks/*.py`, Attack lab page | Each button gives its expected code and audit entry |
| 8. Capture + analysis | 8.5–10 | `capture.py`, `httpparse.py`, `analyze.py`, `pcap_to_sqlite.py`, `plots.py`, Traffic lab page | exp1 and exp3 captured; four graphs drawn; SQL join matches the replay to its audit row |
| 9. Benchmark + rehearsal | 10–11 | `bench.py --quick`, Benchmarks page; full rehearsal of section 14; save the backup folder | Rehearsal runs end to end in under 12 minutes |

**Cut lines if you fall behind**

- Behind at hour 5.5: skip the Keys and Verify/Audit pages and show those calls from the terminal instead.
- Behind at hour 7.5: Attack lab buttons become terminal commands; the scripts are what matter.
- Behind at hour 10: drop TLS, RSA policy, PCAP → XML and the audit chain (all P1). Never drop the capture, the analyser, PCAP → SQLite or the quick benchmark: the ISL rules depend on them.

**Build tips for an AI coding agent:** feed it one block at a time with this PRD, ask it to write the block's tests first, run `pytest -q` after every block, and commit to git at every green check so a bad edit can be rolled back.

## 13. Acceptance checklist

The build is demo-ready when every box below is ticked on the demo laptop after a fresh `setup_demo.py --reset`.

**Core flow**

- [ ] `pytest -q` passes.
- [ ] t104 publishes IT301 marks for 240911608; s608 sees them with "Verified · signed by t104".
- [ ] The inspector shows every teacher, server and student step from section 8 with real values.
- [ ] The server terminal prints one coloured line per step.

**Security goals**

- [ ] Confidentiality: the exp1 capture shows readable marks on `/plain/*` and none on `/api/*`.
- [ ] Integrity: `tamper_cipher.py` → 400; `tamper_db.py` → student sees "Signature invalid"; `--swap` → 500 `record_integrity_failed`.
- [ ] Authentication: wrong password → 401; expired token → 401; `forge_sig.py` → 400; `revoked_key.py` → 403.
- [ ] Authorisation: `idor.py` → 403; teacher publishing for another course → 403.
- [ ] Replay: `replay.py` → 409 `replay_detected`; with `--delay 35` → 409 `stale_request`.
- [ ] Availability: `flood.py` → mostly 429; the s608 probe keeps getting 200s; `bad_login.py` ends in 429.
- [ ] Accountability: every attack above has an audit row with the same request ID.

**Traffic analysis and PCAP analysis**

- [ ] Five captures exist in `captures\` (exp2 TLS is P1).
- [ ] Analyser writes `messages.csv`, `flows.csv`, `flags.csv` and four graphs per capture.
- [ ] Entropy: plain bodies about 4–5 bits/byte, protected bodies of 1 KB or more at 7.8+.
- [ ] exp5 shows five separate devices (by IP, or by `X-Device` if loopback IPs collapse).
- [ ] PCAP → SQLite join lists each replay and flood flag with its matching audit outcome.

**Efficiency analysis**

- [ ] `bench.py --quick` writes `results.csv` and four graphs.
- [ ] Ed25519 vs RSA-2048 and X25519 vs RSA-OAEP rows are present, with key and signature sizes.
- [ ] End-to-end latency for protected vs plain calls is recorded (p50 and p95).

**Demo safety**

- [ ] Backup folder `demo_backup\` holds the rehearsal's captures, graphs, CSVs and screenshots.
- [ ] Full rehearsal of section 14 done once, end to end, without a restart.

## 14. Demo script, backup plan and risks

The demo runs about 12 minutes on one laptop. Screen layout: teacher window left, student window right, server terminal at the bottom, Wireshark on a second desktop (Win + Ctrl + arrow to switch).

**Before they arrive:** `setup_demo.py --reset`, start the server and portal, start capture `exp_live`, open the Crypto playground.

1. **Pitch (1 min).** One slide or the architecture diagram: apps say "confidential", the middleware does the rest, Wireshark/PyShark proves it. Name the ISL modules: Traffic Analysis and PCAP Analysis.
2. **Crypto playground (2 min).** AES-GCM encrypt/decrypt and flip a byte; SHA-256 avalanche; Ed25519 sign/verify and edit the message; X25519 shared secret that Eve can't compute.
3. **Publish (1.5 min).** t104 publishes marks; walk down the inspector: hash, signature, session key (truncated), nonce, ciphertext, then the server's ten checks.
4. **View (1 min).** s608 sees "Verified · signed by t104". Then s608 tries roll 240911612 → 403.
5. **Wireshark (1.5 min).** Follow the HTTP stream: `/plain/publish` shows the marks; `/api/marks/publish` shows random bytes; the handshake shows two public keys but no session key.
6. **Attacks (2.5 min).** Flip a ciphertext byte → 400; edit the DB 45 → 95 → student sees "Signature invalid"; replay the captured publish → 409; flood → 429s while the student page still loads; admin revokes t104 → publish refused.
7. **Evidence (2 min).** Stop the capture, run the analyser: entropy, overhead, latency and rate graphs; PCAP → SQLite join showing each attack matched to its audit row; benchmark graphs for Ed25519 vs RSA and X25519 vs RSA-OAEP.
8. **Close (0.5 min).** Recap the goal matrix from section 1a: each goal, its mechanism, its attack, its number.

**Backup plan:** during rehearsal, copy every capture, CSV, graph and the audit DB into `demo_backup\`, and take screenshots of each inspector state and each attack result. If anything fails live, say so, open the matching backup file, and carry on with the next step.

**Risks**

| Risk | Fallback |
| --- | --- |
| Npcap loopback adapter missing or captures nothing | Reinstall Npcap with loopback support; meanwhile use `demo_backup\` captures |
| Binding to `127.0.0.x` fails, or every packet shows `127.0.0.1` | Analyser groups by `X-Device`; mention the simulation in one line |
| PyShark slow or erroring inside Streamlit | Run `python -m analysis.analyze` in a terminal; keep captures under a few MB with the port filter |
| Streamlit session loses login on rerun | Keep the token and session in `st.session_state`; re-login takes five seconds |
| Port 8000 or 8501 already in use | `--port 8010` / `--server.port 8510`, and update `SERVER_URL` in `.env` |
| Rate limiter blocks your own demo clicks | Demo after the flood with a fresh token, or wait the 5 s refill; flood uses its own stolen-token identity |
| PowerShell blocks venv activation | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Late-night bug in a P1 feature | Leave it out; P1 is not part of the ISL requirements |

## 15. Likely viva questions

Short answers to rehearse; each points at something you can show.

| Question | Answer |
| --- | --- |
| Why Ed25519 instead of RSA? | Smaller keys (32 B vs 256 B) and signatures (64 B vs 256 B), much faster signing and keygen, about 128-bit security, and deterministic signing, so no random-number failure can leak the key. RSA is kept in the benchmark for comparison. |
| Ed25519 can't encrypt, so how do you exchange keys? | X25519, its sibling curve: Diffie-Hellman on Curve25519. HKDF turns the shared secret into the AES key. |
| Why both AES-GCM and a signature? | GCM proves the bytes weren't changed in transit under the session key. The signature proves the teacher wrote the marks, end to end, even if the server or DB is compromised (the `tamper_db` demo). |
| How exactly is replay stopped? | Request ID + timestamp go into the AAD, so they can't be edited without breaking decryption; the server rejects a seen ID or a timestamp older than 30 s. |
| Why not just use TLS? | TLS protects the pipe, not the data at rest or who signed it. Exp2 also shows TLS still leaks metadata (sizes, timing). Both layers together are the design. |
| Where are the keys stored? | Master key in `secrets\master.key`, outside the DB; data keys stored wrapped by it; teacher private key only on the teacher's "device", encrypted with their password. |
| How do you justify one laptop as "two devices"? | The ISL rules allow a simulation: five clients with separate IPs, logins, session keys and traffic, visible as five hosts in the capture. |
| What does PyShark add over Wireshark? | Repeatable, scripted analysis: entropy, overhead, latency, rate flags, and the PCAP → SQLite join with the audit log, all reproducible from saved captures. |
| What is the cost of security? | Read it off the graphs: per-request byte overhead, protected vs plain latency, and per-algorithm timings from the benchmark. |
| What are the limitations? | Single process (in-memory replay set and sessions), demo mode shows truncated keys, no TLS by default, the student trusts the server's copy of the teacher's public key (fix: pin the fingerprint), no real network latency on loopback. |
