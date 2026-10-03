import { api } from "@/lib/api";
import type { Health, TokenResponse, User } from "@/types/api";

export const authService = {
  register: (name: string, email: string, password: string) =>
    api<User>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ name, email, password }),
    }),
  login: (email: string, password: string) =>
    api<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  logout: () => api<void>("/auth/logout", { method: "POST" }),
  me: () => api<User>("/auth/me"),
};

export const systemService = {
  health: () => api<Health>("/health"),
};
