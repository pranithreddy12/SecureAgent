import { expect, test, type Page } from "@playwright/test";

const PASSWORD = "correct-horse-battery-staple";

function uniqueEmail(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
}

async function register(page: Page, email: string) {
  await page.goto("/register");
  // Exact labels double as an accessibility check: hints must not leak into the field name.
  await page.getByLabel("Name", { exact: true }).fill("E2E Tester");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/dashboard/);
}

async function startAudit(page: Page, path: string, label: string) {
  await page.goto("/audits");
  await page.getByLabel(/Source directory/).fill(path);
  await page.getByLabel(/Label/).fill(label);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Start audit" }).click();
}

test.describe("register, audit and review", () => {
  test("a visitor is sent to sign in before reaching the app", async ({ page }) => {
    await page.goto("/audits");
    await expect(page).toHaveURL(/\/login\?next=%2Faudits/);
  });

  test("full journey: register, run a source audit, read findings, chains and report", async ({
    page,
    context,
  }) => {
    const email = uniqueEmail("journey");
    await register(page, email);

    // Dashboard starts empty and says so (no fabricated metrics).
    await expect(page.getByText("No audits yet")).toBeVisible();

    // The authorization statement gates the submit button.
    await page.goto("/audits");
    await page.getByLabel(/Source directory/).fill("/workspace/shop");
    const start = page.getByRole("button", { name: "Start audit" });
    await expect(start).toBeDisabled();
    await page.getByRole("checkbox").check();
    await expect(start).toBeEnabled();
    await start.click();

    // Detail page: progress reaches a terminal state without a manual reload.
    await expect(page).toHaveURL(/\/audits\/[0-9a-f-]{36}$/);
    await expect(page.getByText("completed", { exact: true })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText("✓ Analyse source")).toBeVisible();
    await expect(page.getByText("✓ Generate report")).toBeVisible();

    // Findings are real and honestly labelled (suspicious, never "confirmed").
    await expect(page.getByText(/Findings \(\d+\)/)).toBeVisible();
    await expect(page.getByText(/SQL injection/).first()).toBeVisible();
    await expect(page.getByText("Confirmed", { exact: true })).toHaveCount(0);

    // Expanding a finding shows evidence, remediation and honest CVE/CVSS text.
    const sqli = page.locator("details").filter({ hasText: "CWE-89" }).first();
    await sqli.locator("summary").click();
    await expect(sqli.getByText(/CVSS not determined/)).toBeVisible();
    await expect(sqli.getByText(/no specific CVE/)).toBeVisible();
    await expect(sqli.getByText("Fix:")).toBeVisible();

    // Attack chains are present with a fix-first recommendation.
    await expect(page.getByText(/Attack chains \(\d+\)/)).toBeVisible();
    await page.getByText(/reachable without authentication/).first().click();
    await expect(page.getByText("Fix first:").first()).toBeVisible();

    // Static reconnaissance model is shown and says no live system was contacted.
    await expect(page.getByText("Source reconnaissance")).toBeVisible();
    await expect(page.getByText(/no running\s+system was contacted/)).toBeVisible();

    // Activity log shows the staged run.
    await expect(page.getByText(/scan_completed/)).toBeVisible();

    // Report opens in a new tab and is labelled as a static audit.
    const [report] = await Promise.all([
      context.waitForEvent("page"),
      page.getByRole("link", { name: "View report" }).click(),
    ]);
    await report.waitForLoadState();
    await expect(report.locator("body")).toContainText("SecureAgent");
    await expect(report.locator("body")).toContainText("Attack chains");
    await expect(report.locator("body")).toContainText("Authorization matrix");
    await report.close();

    // HTML download endpoint serves an attachment.
    const href = await page.getByRole("link", { name: "Download HTML" }).getAttribute("href");
    const res = await page.request.get(href!);
    expect(res.status()).toBe(200);
    expect(res.headers()["content-disposition"]).toContain("attachment");
    expect(res.headers()["content-security-policy"]).toContain("default-src 'none'");

    // History and dashboard now reflect the audit.
    await page.goto("/audits");
    await expect(page.getByRole("link", { name: "shop" })).toBeVisible();
    await page.goto("/dashboard");
    await expect(page.getByText("Recent audits")).toBeVisible();
  });

  test("a path outside the allowed roots is rejected with a clear message", async ({ page }) => {
    await register(page, uniqueEmail("outside"));
    await startAudit(page, "/etc", "etc");
    await expect(page.locator("p[role='alert']")).toContainText("outside the allowed roots");
    await expect(page).toHaveURL(/\/audits$/);
  });

  test("another user cannot open someone else's audit", async ({ page, browser }) => {
    await register(page, uniqueEmail("owner"));
    await startAudit(page, "/workspace/shop", "private");
    await expect(page).toHaveURL(/\/audits\/[0-9a-f-]{36}$/);
    const auditUrl = page.url();

    const other = await browser.newContext();
    const otherPage = await other.newPage();
    await register(otherPage, uniqueEmail("intruder"));
    await otherPage.goto(auditUrl);
    await expect(otherPage.locator("p[role='alert']")).toContainText("Audit not found");
    const api = await otherPage.request.get(
      `/api/audits/${auditUrl.split("/").pop()}/report`,
    );
    expect(api.status()).toBe(404);
    await other.close();
  });

  test("signing out ends the session", async ({ page }) => {
    await register(page, uniqueEmail("logout"));
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/login/);
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login/);
  });

  test("wrong credentials show an error and repeated failures are throttled", async ({ page }) => {
    const email = uniqueEmail("throttle");
    await register(page, email);
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.goto("/login");
    for (let i = 0; i < 5; i++) {
      await page.locator('input[name="email"]').fill(email);
      await page.locator('input[name="password"]').fill(`wrong-password-${i}-xxxx`);
      await page.getByRole("button", { name: "Sign in" }).click();
      await expect(page.locator("p[role='alert']")).toContainText("Invalid email or password");
    }
    await page.locator('input[name="email"]').fill(email);
    await page.locator('input[name="password"]').fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.locator("p[role='alert']")).toContainText("Too many failed sign-in attempts");
  });
});
