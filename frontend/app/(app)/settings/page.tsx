"use client";

import { SystemStatus } from "@/components/SystemStatus";
import { Card } from "@/components/ui";
import { useCurrentUser } from "@/hooks/useCurrentUser";

export default function SettingsPage() {
  const user = useCurrentUser();
  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="mt-1 text-sm text-muted">Account and system information</p>
      </header>
      <Card title="Account">
        {user && (
          <dl className="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
            <dt className="text-muted">Name</dt>
            <dd>{user.name}</dd>
            <dt className="text-muted">Email</dt>
            <dd>{user.email}</dd>
            <dt className="text-muted">Role</dt>
            <dd className="capitalize">{user.role}</dd>
            <dt className="text-muted">Member since</dt>
            <dd>{new Date(user.created_at).toLocaleDateString()}</dd>
          </dl>
        )}
      </Card>
      <SystemStatus />
    </div>
  );
}
