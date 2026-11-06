import type { NextConfig } from "next";

// Browser talks to the same origin; Next proxies /api/* to FastAPI so the auth
// cookie stays first-party. Read at build time (baked into standalone output).
const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  // The proxy truncates request bodies at 10MB by default, which kills zip uploads; keep this
  // above the backend's MAX_UPLOAD_MB so the backend returns the clean 413 for oversized files.
  experimental: { proxyClientMaxBodySize: "30mb" },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backendUrl}/api/:path*` }];
  },
};

export default nextConfig;
