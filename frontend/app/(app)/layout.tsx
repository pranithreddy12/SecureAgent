"use client";

import type { ReactNode } from "react";

import { Sidebar } from "@/components/Sidebar";
import { useCurrentUser } from "@/hooks/useCurrentUser";

export default function AppLayout({ children }: { children: ReactNode }) {
  const user = useCurrentUser();
  return (
    <div className="flex flex-1 flex-col md:flex-row">
      <Sidebar user={user} />
      <main className="flex-1 px-4 py-6 md:px-8">
        {user ? children : <p className="text-sm text-muted">Loading…</p>}
      </main>
    </div>
  );
}
