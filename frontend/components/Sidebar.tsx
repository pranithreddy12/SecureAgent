"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

import { authService } from "@/services/auth";
import type { User } from "@/types/api";

// Only pages that exist are listed (ADR-014): findings, logs and reports live on each audit page.
const NAV: { label: string; href?: string }[] = [
  { label: "Run", href: "/run" },
  { label: "Dashboard", href: "/dashboard" },
  { label: "Projects", href: "/projects" },
  { label: "Targets", href: "/targets" },
  { label: "Audits", href: "/audits" },
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
      <div className="border-b border-border px-5 py-5">
        <p className="font-serif text-lg text-foreground">SecureAgent</p>
        <p className="mt-0.5 text-xs text-muted">Application Security Auditor</p>
      </div>
      <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-3 py-3 md:flex-col">
        {NAV.map(({ label, href }) =>
          href ? (
            <Link
              key={label}
              href={href}
              aria-current={pathname.startsWith(href) ? "page" : undefined}
              className={`whitespace-nowrap rounded-sm border-l-2 px-3 py-2 text-sm transition ${
                pathname.startsWith(href)
                  ? "border-accent bg-surface-raised text-accent"
                  : "border-transparent text-foreground hover:bg-surface-raised"
              }`}
            >
              {label}
            </Link>
          ) : (
            <span
              key={label}
              aria-disabled="true"
              title="Not implemented yet"
              className="flex items-center justify-between gap-2 whitespace-nowrap rounded-sm border-l-2 border-transparent px-3 py-2 text-sm text-muted/60"
            >
              {label}
              <span className="rounded-sm border border-border px-1.5 text-[10px] uppercase">
                soon
              </span>
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
