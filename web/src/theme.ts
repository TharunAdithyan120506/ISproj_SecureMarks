/* Appearance: "system" (follow the OS), "light" or "dark". Stored per browser; applied as
   <html data-theme> before first paint by the inline script in index.html. */
import { useEffect, useState } from "react";

export type Theme = "system" | "light" | "dark";
const KEY = "sm-theme";
export const THEME_EVENT = "sm-theme-change";

export function readTheme(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

export function applyTheme(t: Theme): void {
  const root = document.documentElement;
  if (t === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", t);
  try {
    if (t === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, t);
  } catch {
    /* storage blocked: the choice lasts for this page only */
  }
  window.dispatchEvent(new Event(THEME_EVENT));
}

export function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(readTheme);
  useEffect(() => { applyTheme(theme); }, [theme]);
  return [theme, setTheme];
}
