import type { NextConfig } from "next";

// Browser talks to the same origin; Next proxies /api/* to FastAPI so the auth
// cookie stays first-party. Read at build time (baked into standalone output).
const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backendUrl}/api/:path*` }];
  },
};

export default nextConfig;
