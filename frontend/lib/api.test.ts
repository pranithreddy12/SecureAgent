import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, safeNextPath } from "./api";

function mockFetch(response: Partial<Response> & { json?: () => Promise<unknown> }) {
  const fn = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => ({}),
    ...response,
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => vi.unstubAllGlobals());

describe("safeNextPath", () => {
  it("keeps same-site relative paths", () => {
    expect(safeNextPath("/audits/123")).toBe("/audits/123");
  });

  it.each([null, "", "https://evil.example", "//evil.example", "javascript:alert(1)", "audits"])(
    "falls back to the dashboard for %s",
    (value) => {
      expect(safeNextPath(value)).toBe("/dashboard");
    },
  );
});

describe("api", () => {
  it("sends same-origin credentials to the /api prefix", async () => {
    const fn = mockFetch({ json: async () => ({ ok: 1 }) });
    await expect(api("/audits")).resolves.toEqual({ ok: 1 });
    expect(fn).toHaveBeenCalledWith(
      "/api/audits",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("returns undefined for 204 responses", async () => {
    mockFetch({ status: 204 });
    await expect(api("/auth/logout", { method: "POST" })).resolves.toBeUndefined();
  });

  it("surfaces a string detail as the error message", async () => {
    mockFetch({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      json: async () => ({ detail: "path is outside the allowed roots" }),
    });
    const err = await api<never>("/audits/source", { method: "POST" }).catch((e: unknown) => e as ApiError);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(400);
    expect(err.message).toBe("path is outside the allowed roots");
  });

  it("joins validation error messages from FastAPI", async () => {
    mockFetch({
      ok: false,
      status: 422,
      json: async () => ({ detail: [{ msg: "field required" }, { msg: "too short" }] }),
    });
    const err = await api<never>("/x").catch((e: unknown) => e as ApiError);
    expect(err.message).toBe("field required; too short");
  });

  it("falls back to the status text for non-JSON error bodies", async () => {
    mockFetch({
      ok: false,
      status: 502,
      statusText: "Bad Gateway",
      json: async () => {
        throw new Error("not json");
      },
    });
    const err = await api<never>("/x").catch((e: unknown) => e as ApiError);
    expect(err.message).toBe("Bad Gateway");
    expect(err.status).toBe(502);
  });
});
