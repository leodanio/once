import { createClient, type SupabaseClient } from "@supabase/supabase-js";

if (typeof window !== "undefined") {
  throw new Error(
    "SECURITY VIOLATION: src/lib/supabase/server.ts must never be imported in client-side code."
  );
}

export interface DatabaseLinkRow {
  id: string;
  slug: string;
  destination_url: string;
  custom_message: string | null;
  max_views: number;
  views_count: number;
  expires_at: string | null;
  created_at: string;
  used_at: string | null;
}

export interface ConsumeLinkRpcRow {
  status: "valid" | "expired" | "max_views_reached" | "not_found";
  destination_url: string | null;
  custom_message: string | null;
  views_count: number;
  max_views: number;
  expires_at: string | null;
}

export interface CheckRateLimitRpcRow {
  allowed: boolean;
  current_count: number;
  reset_at: string;
}

let cachedServerClient: SupabaseClient | null = null;

/**
 * Returns true if the server-side Supabase environment variables are configured.
 */
export function isSupabaseConfigured(): boolean {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const serviceRoleKey = (
    process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SECRET_KEY
  )?.trim();

  return Boolean(
    supabaseUrl &&
      serviceRoleKey &&
      !supabaseUrl.includes("your-project-ref") &&
      serviceRoleKey !== "your-service-role-secret-key"
  );
}

/**
 * Creates or returns a singleton server-side Supabase client authenticated
 * with SUPABASE_SERVICE_ROLE_KEY.
 *
 * This client must ONLY be used inside server contexts (Route Handlers,
 * Server Components, Server Actions).
 */
export function getServerSupabaseClient(): SupabaseClient {
  if (cachedServerClient) {
    return cachedServerClient;
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const serviceRoleKey = (
    process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SECRET_KEY
  )?.trim();

  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error(
      "Missing Supabase server configuration: NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required."
    );
  }

  cachedServerClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  return cachedServerClient;
}
