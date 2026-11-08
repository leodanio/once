import path from "node:path";
import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV !== "production";

// Restrictive CSP for SEGRETI: excludes 'unsafe-eval' in production
const SECRETS_CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join("; ");

const COMMON_SECURITY_HEADERS = [
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "Referrer-Policy",
    value: "no-referrer",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), geolocation=(), microphone=()",
  },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  outputFileTracingRoot: path.join(__dirname),
  async redirects() {
    return [
      {
        source: "/secrets",
        destination: "/",
        permanent: true,
      },
    ];
  },
  async headers() {
    return [
      // 1. Global security headers applied to ALL application routes
      {
        source: "/:path*",
        headers: COMMON_SECURITY_HEADERS,
      },
      // 2. API Routes: zero caching
      {
        source: "/api/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "no-store, no-cache, must-revalidate, max-age=0",
          },
          {
            key: "Pragma",
            value: "no-cache",
          },
        ],
      },
      // 3. SEGRETI homepage (/): strict CSP + zero caching
      {
        source: "/",
        headers: [
          {
            key: "Cache-Control",
            value: "no-store, no-cache, must-revalidate, max-age=0",
          },
          {
            key: "Pragma",
            value: "no-cache",
          },
          {
            key: "Content-Security-Policy",
            value: SECRETS_CONTENT_SECURITY_POLICY,
          },
        ],
      },
      // 4. SEGRETI subpaths (/secrets/:token): strict CSP + zero caching
      {
        source: "/secrets/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "no-store, no-cache, must-revalidate, max-age=0",
          },
          {
            key: "Pragma",
            value: "no-cache",
          },
          {
            key: "Content-Security-Policy",
            value: SECRETS_CONTENT_SECURITY_POLICY,
          },
        ],
      },
      // 5. Dynamic link redirects: zero caching to prevent intermediate proxy view caching
      {
        source: "/:slug((?!_next|about|secrets|links|favicon\\.ico).*)",
        headers: [
          {
            key: "Cache-Control",
            value: "no-store, no-cache, must-revalidate, max-age=0",
          },
          {
            key: "Pragma",
            value: "no-cache",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
