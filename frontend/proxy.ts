import { NextResponse, type NextRequest } from "next/server";

// Fast redirect for visitors with no session cookie. This is a UX convenience only:
// the backend verifies the JWT on every API call, and pages redirect on a 401.
export function proxy(request: NextRequest) {
  if (request.cookies.has("access_token")) return NextResponse.next();
  const login = new URL("/login", request.url);
  login.searchParams.set("next", request.nextUrl.pathname);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/targets/:path*",
    "/audits/:path*",
    "/findings/:path*",
    "/reports/:path*",
    "/activity/:path*",
    "/settings/:path*",
  ],
};
