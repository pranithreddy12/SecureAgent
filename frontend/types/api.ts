// Mirrors backend Pydantic schemas (backend/app/schemas).

export type UserRole = "admin" | "auditor";

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface Health {
  status: string;
  demo_mode: boolean;
  llm_configured: boolean;
}
