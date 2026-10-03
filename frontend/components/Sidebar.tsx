"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

import { authService } from "@/services/auth";
import type { User } from "@/types/api";

// Items without an href are not built yet; they are shown disabled, never as fake pages.
const NAV: { label: string; href?: string }[] = [
  { label: "Dashboard", href: "/dashboard" },
  { label: "Targets" },
  { label: "Audits" },
  { label: "Findings" },
  { label: "Reports" },
  { label: "Activity" },
  { label: "Settings", href: "/settings" },
];

export function Sidebar({ user }: { user: User | null }) {
  const pathname = usePathname();
  const router = useRouter();

  async function logout() {
    await authService.logout().catch(() => undefined);
    router.replace("/login");
  }

  return (
    <aside className="flex w-full shrink-0 flex-col border-b border-border bg-surface md:min-h-screen md:w-60 md:border-r md:border-b-0">
      <div className="px-5 py-5">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-accent">SecureAgent</p>
        <p className="mt-1 text-xs text-muted">AI Security Auditor</p>
      </div>
      <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-col md:pb-0">
        {NAV.map(({ label, href }) =>
          href ? (
            <Link
              key={label}
              href={href}
              aria-current={pathname.startsWith(href) ? "page" : undefined}
              className={`whitespace-nowrap rounded-lg px-3 py-2 text-sm transition ${
                pathname.startsWith(href)
                  ? "bg-surface-raised text-accent"
                  : "text-foreground hover:bg-surface-raised"
              }`}
            >
              {label}
            </Link>
          ) : (
            <span
              key={label}
              aria-disabled="true"
              title="Not implemented yet"
              className="flex items-center justify-between gap-2 whitespace-nowrap rounded-lg px-3 py-2 text-sm text-muted/60"
            >
              {label}
              <span className="rounded border border-border px-1.5 text-[10px] uppercase">soon</span>
            </span>
          ),
        )}
      </nav>
      <div className="mt-auto hidden border-t border-border px-5 py-4 md:block">
        <p className="truncate text-sm">{user?.name ?? "…"}</p>
        <p className="truncate text-xs text-muted">{user?.email}</p>
        <button onClick={logout} className="mt-3 text-xs text-muted hover:text-accent">
          Sign out
        </button>
      </div>
    </aside>
  );
}
