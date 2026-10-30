import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, BarChart3, FileSignature, FileText, Fingerprint, Gauge, Hash, Home, Image as ImageIcon, KeyRound, Lock,
  Menu, Radio, ScrollText, ShieldAlert, ShieldCheck, Users,
} from "lucide-react";
import { get } from "./api";
import { useAuth } from "./auth";

type Item = { to: string; label: string; icon: ReactNode; roles?: string[] };
const NAV: { title: string; items: Item[] }[] = [
  { title: "Overview", items: [{ to: "/", label: "Home", icon: <Home size={17} /> }] },
  {
    title: "Marks portal",
    items: [
      { to: "/publish", label: "Publish marks", icon: <FileSignature size={17} />, roles: ["teacher"] },
      { to: "/marks", label: "My marks", icon: <ScrollText size={17} />, roles: ["student"] },
      { to: "/verify", label: "Verify & audit", icon: <ShieldCheck size={17} />, roles: ["ctrl", "admin"] },
      { to: "/keys", label: "Keys", icon: <KeyRound size={17} />, roles: ["admin"] },
    ],
  },
  {
    title: "Crypto analysis",
    items: [
      { to: "/lab/text", label: "Text encryption", icon: <FileText size={17} /> },
      { to: "/lab/image", label: "Image encryption", icon: <ImageIcon size={17} /> },
      { to: "/lab/hash", label: "Hashing", icon: <Hash size={17} /> },
      { to: "/lab/signatures", label: "Digital signatures", icon: <Fingerprint size={17} /> },
      { to: "/lab/kex", label: "Key agreement", icon: <Users size={17} /> },
    ],
  },
  {
    title: "Network & attacks",
    items: [
      { to: "/attacks", label: "Attack lab", icon: <ShieldAlert size={17} /> },
      { to: "/traffic", label: "Traffic lab", icon: <Radio size={17} /> },
    ],
  },
  {
    title: "Results",
    items: [
      { to: "/report", label: "Analysis report", icon: <BarChart3 size={17} /> },
      { to: "/benchmarks", label: "Benchmarks", icon: <Gauge size={17} /> },
    ],
  },
];

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const health = useQuery({ queryKey: ["health"], queryFn: () => get("/api/health"), refetchInterval: 5000 });
  const mw = health.data?.middleware;
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  useEffect(() => {
    setOpen(false);
    document.querySelector(".main")?.scrollTo?.(0, 0);
    window.scrollTo(0, 0);
  }, [loc.pathname]);

  return (
    <div className="shell">
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
      <nav className={`sidebar${open ? " open" : ""}`} aria-label="Main">
        <div className="brand">
          <img className="brand-mark" src="/favicon.svg" alt="" />
          <div>
            <div className="brand-name">SecureMarks</div>
            <div className="brand-sub">Security middleware lab</div>
          </div>
        </div>
        {NAV.map((sec) => (
          <div key={sec.title}>
            <div className="nav-section">{sec.title}</div>
            {sec.items.map((it) => {
              const locked = it.roles && (!user || !it.roles.includes(user.role));
              return (
                <NavLink key={it.to} to={it.to} end={it.to === "/"} className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
                  {it.icon}
                  <span>{it.label}</span>
                  {locked && <Lock size={12} className="lock" aria-label="needs another role" />}
                </NavLink>
              );
            })}
          </div>
        ))}
        <div className="sidebar-foot">
          {user ? (
            <div className="profile">
              <div className={`avatar ${user.role}`} aria-hidden="true">{user.username.slice(0, 2).toUpperCase()}</div>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="profile-name">{user.username}</div>
                <div className="profile-meta">{user.label} · {user.device}</div>
                <div className="profile-meta mono">{user.ip}{user.bound ? "" : " · unbound"}</div>
              </div>
              <button className="btn plain sm" onClick={logout}>Sign out</button>
            </div>
          ) : (
            <div className="profile-meta" style={{ padding: "0 8px" }}>Not signed in. The labs work without an account.</div>
          )}
          <div className="status-line">
            <span className={`dot${mw ? "" : " off"}`} aria-hidden="true" />
            {mw ? <>Middleware online · {mw.sessions} sessions</> : <>Middleware offline</>}
            <Activity size={12} style={{ marginLeft: "auto" }} aria-hidden="true" />
          </div>
        </div>
      </nav>
      <div className="main">
        <div className="topbar">
          <button className="btn plain icon-btn" onClick={() => setOpen(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <img className="brand-mark" src="/favicon.svg" alt="" style={{ width: 24, height: 24 }} />
          <b>SecureMarks</b>
        </div>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
