import { createContext, useContext, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { LogIn } from "lucide-react";
import { get, post } from "./api";
import { Empty, Notice } from "./ui";

export type User = {
  username: string; role: "teacher" | "student" | "ctrl" | "admin"; roll_no?: string; courses: string[];
  device: string; ip: string; bound: boolean; label: string; token_expires_in: number;
  session: { id: string; kex: string; policy: string; expires_in: number } | null;
};

type Auth = { user: User | null; loading: boolean; login: (u: string, p: string) => Promise<void>; logout: () => Promise<void>; refresh: () => void };
const Ctx = createContext<Auth>({ user: null, loading: true, login: async () => {}, logout: async () => {}, refresh: () => {} });

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["me"], queryFn: () => get<{ user: User | null }>("/api/me"), refetchInterval: 15000 });
  const value: Auth = {
    user: q.data?.user ?? null,
    loading: q.isLoading,
    login: async (u, p) => {
      const me = await post<User>("/api/login", { username: u, password: p });
      qc.setQueryData(["me"], { user: me });
    },
    logout: async () => {
      await post("/api/logout");
      qc.clear();
      qc.setQueryData(["me"], { user: null });
    },
    refresh: () => q.refetch(),
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);

export const ROLE_LABEL: Record<string, string> = { teacher: "Teacher", student: "Student", ctrl: "Exam controller", admin: "Admin" };

/** Renders children only for the given roles; otherwise explains who the page is for. */
export function RequireRole({ roles, children }: { roles: User["role"][]; children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) {
    return (
      <div className="card">
        <Empty icon={<LogIn size={28} />} title="Sign in to continue">
          <p style={{ marginBottom: 12 }}>This page is for {roles.map((r) => ROLE_LABEL[r]).join(" / ")}. Each role signs in from its own simulated device.</p>
          <Link className="btn primary" to="/">Go to sign in</Link>
        </Empty>
      </div>
    );
  }
  if (!roles.includes(user.role)) {
    return <Notice tone="warn">This page is for {roles.map((r) => ROLE_LABEL[r]).join(" / ")}. You are signed in as <b>{user.username}</b> ({user.label}). Open a new browser tab to sign in as another device.</Notice>;
  }
  return <>{children}</>;
}
