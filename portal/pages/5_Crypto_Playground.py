"""Crypto playground (no login): the four primitives SecureMarks is built on,
running locally with the same wrappers the middleware uses."""
from __future__ import annotations

import streamlit as st

from components.common import esc, page, pill
from middleware.crypto import aead, kex, sign
from middleware.crypto.hashing import bit_difference, sha256

page("Crypto playground", "🧪", "Everything on this page runs locally in the portal with the `cryptography` library - "
                                "the same calls the middleware makes. Keys shown in full here because they are throwaway.")

S = st.session_state


def hexblock(label: str, data: bytes, limit: int = 96) -> None:
    h = data.hex()
    st.markdown(f"<div class='sm-muted'>{esc(label)} · {len(data)} B</div>"
                f"<div class='sm-mono' style='word-break:break-all'>{esc(h[:limit * 2])}{'…' if len(h) > limit * 2 else ''}</div>",
                unsafe_allow_html=True)


tab1, tab2, tab3, tab4 = st.tabs(["1 · AES-GCM", "2 · SHA-256 avalanche", "3 · Ed25519 signatures", "4 · X25519 key agreement"])

# --- 1. AES-GCM -------------------------------------------------------------------------------------
with tab1:
    st.markdown("**Authenticated encryption.** Random key and a fresh 12-byte nonce; the 16-byte tag makes any change "
                "to the ciphertext fail decryption with `InvalidTag`.")
    c1, c2 = st.columns([1, 1])
    with c1:
        text = st.text_area("Plaintext", '{"course":"IT301","roll_no":"240911608","midsem":27,"endsem":45}', height=90)
        bits = st.radio("Key size", [256, 128], horizontal=True, format_func=lambda b: f"AES-{b}-GCM")
        if st.button("New random key and nonce") or "pg_aes" not in S or len(S.pg_aes[0]) * 8 != bits:
            S.pg_aes = (aead.new_key(bits // 8), None)
        flip = st.checkbox("Flip one bit of the ciphertext before decrypting")
        aad = st.text_input("AAD (authenticated, not encrypted)", "marks|IT301|240911608")
    with c2:
        key = S.pg_aes[0]
        nonce, ct = aead.encrypt(key, text.encode(), aad.encode())
        hexblock("key", key)
        hexblock("nonce", nonce)
        hexblock("ciphertext", ct[:-16])
        hexblock("tag", ct[-16:])
        tampered = bytes([ct[0] ^ 0x01]) + ct[1:] if flip else ct
        try:
            out = aead.decrypt(key, nonce, tampered, aad.encode())
            st.markdown(f"{pill(True, 'decrypt OK')} <span class='sm-mono'>{esc(out.decode(errors='replace'))}</span>",
                        unsafe_allow_html=True)
        except aead.InvalidTag:
            st.markdown(f"{pill(False, 'InvalidTag')} the tag no longer matches: the middleware answers "
                        "<code>400 integrity_failed</code>", unsafe_allow_html=True)
    st.caption("Same plaintext, new nonce, completely different ciphertext every time - try pressing the button.")

# --- 2. SHA-256 ---------------------------------------------------------------------------------------
with tab2:
    st.markdown("**Avalanche effect.** Change one character and about half of the 256 output bits flip.")
    a, b = st.columns(2)
    m1 = a.text_input("Message A", "IT301 240911608 endsem=45")
    m2 = b.text_input("Message B", "IT301 240911608 endsem=95")
    d1, d2 = sha256(m1.encode()), sha256(m2.encode())
    diff = bit_difference(d1, d2)
    a.markdown(f"<div class='sm-mono' style='word-break:break-all'>{d1.hex()}</div>", unsafe_allow_html=True)
    b.markdown(f"<div class='sm-mono' style='word-break:break-all'>{d2.hex()}</div>", unsafe_allow_html=True)
    st.metric("Differing bits", f"{diff} / 256", f"{diff / 2.56:.0f}% of the digest")
    cells = []
    for i in range(256):
        x = (d1[i // 8] >> (7 - i % 8)) & 1
        y = (d2[i // 8] >> (7 - i % 8)) & 1
        cells.append(f"<span title='bit {i}' style='display:inline-block;width:11px;height:11px;margin:1px;border-radius:2px;"
                     f"background:{'#d03b3b' if x != y else '#e1e0d9'}'></span>")
    st.markdown("<div style='line-height:0;max-width:440px'>" + "".join(cells) + "</div>"
                "<div class='sm-muted' style='margin-top:6px'>red = bit differs (32 × 8 grid, one cell per output bit)</div>",
                unsafe_allow_html=True)

# --- 3. Ed25519 ------------------------------------------------------------------------------------------
with tab3:
    st.markdown("**Digital signatures.** The teacher signs the SHA-256 of the record with a private key; anyone with the "
                "32-byte public key can check it. Edit the message after signing and verification fails.")
    if st.button("Generate a new keypair") or "pg_ed" not in S:
        S.pg_ed = sign.ed25519_keypair()
        S.pop("pg_sig", None)
    priv, pub = S.pg_ed
    c1, c2 = st.columns(2)
    with c1:
        msg = st.text_area("Message to sign", "IT301 · 240911608 · midsem 27 · endsem 45 · total 72", height=80)
        if st.button("Sign", type="primary"):
            S.pg_sig = (msg, sign.ed25519_sign(priv, sha256(msg.encode())))
        hexblock("public key", pub)
        st.caption(f"fingerprint {sign.fingerprint(pub)} (first 8 bytes of SHA-256 of the public key)")
    with c2:
        if "pg_sig" in S:
            signed_msg, sig = S.pg_sig
            hexblock("signature", sig)
            check = st.text_area("Message the verifier received (edit me)", signed_msg, height=80)
            try:
                sign.ed25519_verify(pub, sig, sha256(check.encode()))
                st.markdown(pill(True, "signature valid"), unsafe_allow_html=True)
            except sign.InvalidSignature:
                st.markdown(f"{pill(False, 'InvalidSignature')} the message changed after signing: the student sees "
                            "<b>Signature invalid</b>", unsafe_allow_html=True)
        else:
            st.info("Sign a message first.")

# --- 4. X25519 ----------------------------------------------------------------------------------------------
with tab4:
    st.markdown("**Key agreement.** Alice (the client) and Bob (the server) each make a keypair and swap only public "
                "keys. Both compute the same shared secret; Eve, who sees both public keys on the wire, cannot.")
    if st.button("New keypairs") or "pg_x" not in S:
        S.pg_x = {"alice": kex.x25519_keypair(), "bob": kex.x25519_keypair(), "eve": kex.x25519_keypair()}
    (a_priv, a_pub), (b_priv, b_pub), (e_priv, e_pub) = S.pg_x["alice"], S.pg_x["bob"], S.pg_x["eve"]
    s_alice, s_bob = kex.x25519_shared(a_priv, b_pub), kex.x25519_shared(b_priv, a_pub)
    s_eve1, s_eve2 = kex.x25519_shared(e_priv, a_pub), kex.x25519_shared(e_priv, b_pub)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("##### Alice (client)")
        hexblock("public key (sent)", a_pub)
        hexblock("shared secret", s_alice)
    with c2:
        st.markdown("##### Bob (server)")
        hexblock("public key (sent)", b_pub)
        hexblock("shared secret", s_bob)
    with c3:
        st.markdown("##### Eve (on the wire)")
        st.caption("sees both public keys, has only her own private key")
        hexblock("Eve × Alice's public", s_eve1)
        hexblock("Eve × Bob's public", s_eve2)
    st.markdown(f"{pill(s_alice == s_bob, 'Alice = Bob')} &nbsp; {pill(s_eve1 != s_alice and s_eve2 != s_alice, 'Eve ≠ shared secret')}",
                unsafe_allow_html=True)
    salt = bytes(16)
    st.caption(f"HKDF-SHA256(shared, salt = session ID, info = securemarks/v1/session) → session key "
               f"{kex.hkdf_derive(s_alice, salt, 32).hex()[:16]}… (32 B for AES-256-GCM)")
