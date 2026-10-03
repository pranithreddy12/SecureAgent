// Same-origin fetch wrapper: Next rewrites /api/* to FastAPI, so the httpOnly auth
// cookie is sent automatically and never touched by JavaScript.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

type FastApiDetail = string | { msg: string }[] | undefined;

function detailMessage(detail: FastApiDetail, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return fallback;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...init.headers },
  });
  if (!res.ok) {
    let message = res.statusText || "Request failed";
    try {
      message = detailMessage((await res.json()).detail, message);
    } catch {
      // non-JSON error body; keep status text
    }
    throw new ApiError(res.status, message);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

/** Only allow same-site relative redirects (prevents open redirects via ?next=). */
export function safeNextPath(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/dashboard";
}
