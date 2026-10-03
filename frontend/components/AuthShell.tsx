import type { ReactNode } from "react";

export function AuthShell({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main className="flex flex-1 items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <p className="font-mono text-xs uppercase tracking-[0.3em] text-accent">SecureAgent</p>
          <h1 className="mt-2 text-2xl font-semibold">{title}</h1>
          <p className="mt-1 text-sm text-muted">Multi-Agent AI Application Security Auditor</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-6">{children}</div>
        <p className="mt-6 text-center text-xs text-muted">
          For authorized security testing only.
        </p>
      </div>
    </main>
  );
}
