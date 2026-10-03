import { SystemStatus } from "@/components/SystemStatus";
import { Card } from "@/components/ui";

export default function DashboardPage() {
  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="mt-1 text-sm text-muted">Security audit overview</p>
      </header>
      <div className="grid gap-4 md:grid-cols-2">
        <SystemStatus />
        <Card title="Audit overview">
          {/* No metrics are shown until real audit data exists; nothing here is simulated. */}
          <p className="text-sm text-muted">
            No audit data yet. Target management and the audit pipeline are still being built,
            so statistics, charts and recent findings will appear here once audits can run.
          </p>
        </Card>
      </div>
    </div>
  );
}
