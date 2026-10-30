import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Link as RouterLink, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart3, ChevronDown, ChevronsUpDown, FileSignature, FileText, Fingerprint, Gauge, Hash, Home, Image as ImageIcon,
  KeyRound, LogIn, LogOut, Menu, Monitor, Moon, PanelLeftClose, PanelLeftOpen, Radio, ScrollText, ShieldAlert, ShieldCheck,
  Sun, UserRound, Users,
} from "lucide-react";
import { get } from "./api";
import { useAuth } from "./auth";
import { ErrorBoundary } from "./ErrorBoundary";
import { useTheme, type Theme } from "./theme";

type Item = { to: string; label: string; icon: ReactNode; roles?: string[] };
type Section = { id: string; title: string; items: Item[] };

/* Marks-portal pages appear only for the roles that can use them. */
const PORTAL: Item[] = [
  { to: "/publish", label: "Publish marks", icon: <FileSignature size={17} />, roles: ["teacher"] },
  { to: "/marks", label: "My marks", icon: <ScrollText size={17} />, roles: ["student"] },
  { to: "/verify", label: "Verify & audit", icon: <ShieldCheck size={17} />, roles: ["ctrl"] },
  { to: "/keys", label: "Keys", icon: <KeyRound size={17} />, roles: ["admin"] },
  { to: "/verify", label: "Audit log", icon: <ShieldCheck size={17} />, roles: ["admin"] },
];
const SECTIONS: Section[] = [
  {
    id: "crypto", title: "Crypto analysis",
    items: [
      { to: "/lab/text", label: "Text encryption", icon: <FileText size={17} /> },
      { to: "/lab/image", label: "Image encryption", icon: <ImageIcon size={17} /> },
      { to: "/lab/hash", label: "Hashing", icon: <Hash size={17} /> },
      { to: "/lab/signatures", label: "Digital signatures", icon: <Fingerprint size={17} /> },
      { to: "/lab/kex", label: "Key agreement", icon: <Users size={17} /> },
    ],
  },
  {
    id: "net", title: "Network & attacks",
    items: [
      { to: "/attacks", label: "Attack lab", icon: <ShieldAlert size={17} /> },
      { to: "/traffic", label: "Traffic lab", icon: <Radio size={17} /> },
    ],
  },
  {
    id: "results", title: "Results",
    items: [
      { to: "/report", label: "Analysis report", icon: <BarChart3 size={17} /> },
      { to: "/benchmarks", label: "Benchmarks", icon: <Gauge size={17} /> },
    ],
  },
];

const THEMES: { value: Theme; label: string; icon: ReactNode }[] = [
  { value: "system", label: "Auto", icon: <Monitor size={13} /> },
  { value: "light", label: "Light", icon: <Sun size={13} /> },
  { value: "dark", label: "Dark", icon: <Moon size={13} /> },
];
const IS_MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
const SHORTCUT = IS_MAC ? "⌘\\" : "Ctrl+\\";

function stored<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}
function store(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage blocked: preference lasts for this page only */
  }
}

function useMedia(query: string): boolean {
  const [m, setM] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const on = () => setM(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [query]);
  return m;
}

function NavItem({ it }: { it: Item }) {
  return (
    <NavLink to={it.to} end={it.to === "/"} data-tip={it.label} aria-label={it.label}
      className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
      {it.icon}
      <span>{it.label}</span>
    </NavLink>
  );
}

function Group({ id, title, items, open, onToggle }: { id: string; title: string; items: Item[]; open: boolean; onToggle: (id: string) => void }) {
  const loc = useLocation();
  const holdsCurrent = items.some((it) => it.to === loc.pathname);
  const shown = open || holdsCurrent; // never hide the page you are on
  return (
    <div className="nav-group">
      <button className="nav-section" aria-expanded={shown} aria-controls={`nav-${id}`} onClick={() => onToggle(id)}>
        <span className="label">{title}</span>
        <ChevronDown size={13} aria-hidden="true" />
      </button>
      <div className="nav-items" id={`nav-${id}`} hidden={!shown}>
        {items.map((it) => <NavItem key={it.label} it={it} />)}
      </div>
    </div>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout, signingOut } = useAuth();
  const navigate = useNavigate();
  const loc = useLocation();
  const mobile = useMedia("(max-width: 900px)");
  const health = useQuery({ queryKey: ["health"], queryFn: () => get("/api/health"), refetchInterval: 5000 });
  const mw = health.data?.middleware;
  const [theme, setTheme] = useTheme();
  const [drawer, setDrawer] = useState(false);
  const [rail, setRail] = useState<boolean>(() => stored("sm-rail", window.innerWidth < 1200));
  const [closed, setClosed] = useState<string[]>(() => stored("sm-closed-sections", []));
  const [menu, setMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const acctRef = useRef<HTMLButtonElement>(null);

  const toggleRail = useCallback(() => setRail((r) => { store("sm-rail", !r); return !r; }), []);
  const toggleSection = (id: string) => setClosed((c) => {
    const next = c.includes(id) ? c.filter((x) => x !== id) : [...c, id];
    store("sm-closed-sections", next);
    return next;
  });

  useEffect(() => { setDrawer(false); setMenu(false); window.scrollTo(0, 0); }, [loc.pathname]);

  // Ctrl+\ (⌘\ on Mac) collapses / expands the sidebar; Escape closes the menu and the drawer.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "\\" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        if (mobile) setDrawer((d) => !d); else toggleRail();
      } else if (e.key === "Escape") {
        if (menu) { setMenu(false); acctRef.current?.focus(); }
        setDrawer(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mobile, menu, toggleRail]);

  // close the account menu on an outside click
  useEffect(() => {
    if (!menu) return;
    const onDown = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node) && !acctRef.current?.contains(e.target as Node)) setMenu(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [menu]);

  const signOut = async () => {
    setMenu(false);
    await logout();
    navigate("/", { replace: true });
  };
  const portal = user ? PORTAL.filter((it) => it.roles!.includes(user.role)) : [];
  const railOn = rail && !mobile;
  const sections: Section[] = [
    ...(portal.length ? [{ id: "portal", title: user!.label, items: portal }] : []),
    ...SECTIONS,
  ];

  return (
    <div className={`shell${railOn ? " rail" : ""}`}>
      {drawer && <div className="scrim" onClick={() => setDrawer(false)} />}
      <nav className={`sidebar${drawer ? " open" : ""}`} aria-label="Main">
        <div className="sb-head">
          <RouterLink to="/" className="brand" aria-label="SecureMarks home">
            <img className="brand-mark" src="/favicon.svg" alt="" />
            <span className="brand-text">
              <span className="brand-name" style={{ display: "block" }}>SecureMarks</span>
              <span className="brand-sub" style={{ display: "block" }}>Security middleware lab</span>
            </span>
          </RouterLink>
          <button className="sb-toggle desktop" onClick={toggleRail} aria-pressed={railOn}
            aria-label={railOn ? "Expand sidebar" : "Collapse sidebar"} title={`${railOn ? "Expand" : "Collapse"} sidebar (${SHORTCUT})`}>
            {railOn ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
          </button>
        </div>

        <div className="sb-nav">
          <div className="nav-group"><NavItem it={{ to: "/", label: user ? "Dashboard" : "Home", icon: <Home size={17} /> }} /></div>
          {sections.map((s) => (
            <Group key={s.id} id={s.id} title={s.title} items={s.items} open={!closed.includes(s.id)} onToggle={toggleSection} />
          ))}
        </div>

        <div className="sb-foot">
          <div className="status-line" title={mw ? `Middleware online · ${mw.sessions} sessions` : "Middleware offline"}>
            <span className={`dot${mw ? "" : " off"}`} aria-hidden="true" />
            <span className="label">{mw ? <>Middleware online · {mw.sessions} sessions</> : <>Middleware offline</>}</span>
          </div>
          <button ref={acctRef} className="acct" onClick={() => setMenu((m) => !m)} aria-haspopup="menu" aria-expanded={menu}
            aria-label={user ? `Account: ${user.username}, ${user.label}` : "Account and appearance"}>
            {user
              ? <span className={`avatar ${user.role}`} aria-hidden="true">{user.username.slice(0, 2).toUpperCase()}</span>
              : <span className="acct-icon" aria-hidden="true"><UserRound size={17} /></span>}
            <span className="grow">
              <span className="profile-name" style={{ display: "block" }}>{user ? user.username : "Not signed in"}</span>
              <span className="profile-meta" style={{ display: "block" }}>{user ? `${user.label} · ${user.device}` : "Labs need no account"}</span>
            </span>
            <ChevronsUpDown size={15} className="chev" aria-hidden="true" />
          </button>
          {menu && (
            <div ref={menuRef} className="menu" role="menu" aria-label="Account">
              {user && (
                <div className="menu-head">
                  <span className={`avatar md ${user.role}`} aria-hidden="true">{user.username.slice(0, 2).toUpperCase()}</span>
                  <div style={{ minWidth: 0 }}>
                    <div className="profile-name">{user.username}</div>
                    <div className="profile-meta">{user.label} · {user.device}</div>
                    <div className="profile-meta mono">{user.ip} · token {Math.floor(user.token_expires_in / 60)} min</div>
                  </div>
                </div>
              )}
              <div className="menu-label">Appearance</div>
              <div className="seg" role="group" aria-label="Appearance">
                {THEMES.map((t) => (
                  <button key={t.value} type="button" aria-pressed={theme === t.value} onClick={() => setTheme(t.value)}>{t.icon}{t.label}</button>
                ))}
              </div>
              <hr />
              {user ? (
                <button className="menu-item danger" role="menuitem" onClick={signOut} disabled={signingOut}>
                  <LogOut size={15} /> {signingOut ? "Signing out…" : "Sign out"}
                </button>
              ) : (
                <RouterLink className="menu-item" role="menuitem" to="/" onClick={() => setMenu(false)}><LogIn size={15} /> Sign in</RouterLink>
              )}
            </div>
          )}
        </div>
      </nav>
      <div className="main">
        <div className="topbar">
          <button className="btn plain icon-btn" onClick={() => setDrawer(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <img className="brand-mark" src="/favicon.svg" alt="" style={{ width: 24, height: 24 }} />
          <b>SecureMarks</b>
        </div>
        <main className="content">
          <ErrorBoundary resetKey={loc.pathname}>{children}</ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
