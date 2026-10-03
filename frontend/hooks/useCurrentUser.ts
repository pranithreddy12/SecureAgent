"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { ApiError } from "@/lib/api";
import { authService } from "@/services/auth";
import type { User } from "@/types/api";

/** Loads the signed-in user; an expired/invalid session redirects to /login. */
export function useCurrentUser(): User | null {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    let cancelled = false;
    authService
      .me()
      .then((u) => !cancelled && setUser(u))
      .catch((err) => {
        if (!cancelled && err instanceof ApiError && err.status === 401) {
          const next = encodeURIComponent(window.location.pathname);
          router.replace(`/login?next=${next}`);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [router]);

  return user;
}
