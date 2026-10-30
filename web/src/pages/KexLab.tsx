import { useEffect, useState } from "react";
import { post } from "../api";
import { Card, Hex, OkPill, PageHead } from "../ui";

export default function KexLab() {
  const [r, setR] = useState<any>(null);
  const run = async () => setR(await post("/api/lab/kex"));
  useEffect(() => { run(); }, []);
  return (
    <>
      <PageHead eyebrow="Crypto analysis · key exchange" title="Key agreement"
        sub="Alice (a client device) and Bob (the server) each make an X25519 keypair and swap only public keys. Both compute the same shared secret; Eve, who sees both public keys on the wire, cannot. HKDF-SHA256 turns the secret into the AES-256-GCM session key."
        strip="X25519(a, B) = X25519(b, A)" />
      <div className="row" style={{ marginBottom: 16 }}>
        <button className="btn primary" onClick={run}>New keypairs</button>
        {r && <><OkPill ok={r.match} yes="Alice = Bob" no="mismatch" /><OkPill ok={r.eve_fails} yes="Eve ≠ shared secret" no="Eve learned it" />
          <span className="muted small">shared-secret computation {r.shared_ms} ms</span></>}
      </div>
      {r && (
        <>
          <div className="grid g3">
            <Card title="Alice · client"><Hex label="Public key (sent)" hex={r.alice_pub} short /><Hex label="Shared secret" hex={r.alice_secret} short /></Card>
            <Card title="Bob · server"><Hex label="Public key (sent)" hex={r.bob_pub} short /><Hex label="Shared secret" hex={r.bob_secret} short /></Card>
            <Card title="Eve · on the wire" sub="sees both public keys, has only her own private key">
              <Hex label="Eve × Alice's public key" hex={r.eve_with_alice} short /><Hex label="Eve × Bob's public key" hex={r.eve_with_bob} short />
            </Card>
          </div>
          <Card className="section" title="Session key" sub="HKDF-SHA256(shared secret, salt = session ID, info = securemarks/v1/session) → 32 bytes for AES-256-GCM">
            <Hex label="Salt" hex={r.salt} short /><Hex label="Session key" hex={r.session_key} short />
          </Card>
        </>
      )}
    </>
  );
}
