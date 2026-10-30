import { useEffect, useState } from "react";
import { post } from "../api";
import { RequireRole } from "../auth";
import { Inspector, Outcome, type Call } from "../parts";
import { Card, DataTable, JsonView, PageHead } from "../ui";

export default function Keys() {
  return (
    <>
      <PageHead eyebrow="Admin · admin-pc" title="Keys"
        sub="Data keys are stored wrapped by the master key; only teachers' public keys are on the server. Metadata only: key bytes never leave the server." />
      <RequireRole roles={["admin"]}><Body /></RequireRole>
    </>
  );
}

function Body() {
  const [keys, setKeys] = useState<Call | null>(null);
  const [last, setLast] = useState<Call | null>(null);
  const [sure, setSure] = useState(false);
  const load = async () => setKeys(await post("/api/keys"));
  useEffect(() => { load(); }, []);
  const act = async (path: string, body?: unknown) => {
    setLast(await post(path, body));
    setSure(false);
    load();
  };

  return (
    <div className="stack" style={{ gap: 18 }}>
      {keys && !keys.ok && <Outcome res={keys} />}
      {keys?.ok && (
        <div className="grid g2">
          <Card title="Data keys" sub="AES-256-GCM, wrapped (encrypted) by the master key" className="flush">
            <div style={{ padding: "0 4px 4px" }}><DataTable rows={keys.payload.data_keys} /></div>
          </Card>
          <Card title="Signing keys" sub="Public halves only; private keys live on the teacher's device" className="flush">
            <div style={{ padding: "0 4px 4px" }}><DataTable rows={keys.payload.signing_keys} /></div>
          </Card>
        </div>
      )}
      <div className="grid g2">
        <Card title="Revoke a teacher's signing key" sub="Further publishes by that teacher get 403 key_revoked. Records signed earlier still verify, and the student view notes the revocation date.">
          <label className="check"><input type="checkbox" checked={sure} onChange={(e) => setSure(e.target.checked)} />
            I understand t104 cannot publish until re-keyed (<span className="mono">python scripts\setup_demo.py --rekey t104</span>)</label>
          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn danger" disabled={!sure} onClick={() => act("/api/keys/revoke", { username: "t104" })}>Revoke t104's key</button>
          </div>
        </Card>
        <Card title="Rotate the data key" sub="The new version encrypts new publishes; the old one is retired and still decrypts old records.">
          <button className="btn" onClick={() => act("/api/keys/rotate")}>Rotate data key</button>
        </Card>
      </div>
      {last && (
        <div className="stack fade-in">
          <Outcome res={last} okText="done" />
          {last.ok && <JsonView data={last.payload} />}
          <Inspector res={last} role="admin" />
        </div>
      )}
    </div>
  );
}
