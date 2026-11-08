/**
 * ONCE — Trusted Client IP Resolution Utility
 *
 * Designed for secure deployment on Vercel and behind modern reverse proxies
 * (Cloudflare, Nginx, AWS ALB).
 *
 * Security Considerations:
 * 1. Attackers can forge incoming `X-Forwarded-For` headers by prepending arbitrary IPs.
 * 2. On Vercel, `x-vercel-ip` and `x-real-ip` are set directly by the edge infrastructure
 *    and CANNOT be spoofed by external clients.
 * 3. On Cloudflare, `cf-connecting-ip` is authoritative.
 * 4. If `x-forwarded-for` is used as a fallback, taking the first (leftmost) IP allows
 *    spoofing; instead, trusted edge proxies append the connecting IP to the end.
 *    We prioritize authoritative headers (`x-vercel-ip`, `cf-connecting-ip`, `x-real-ip`)
 *    and inspect the rightmost valid IP from `x-forwarded-for` as fallback.
 */

const IPV4_REGEX =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

const IPV6_REGEX =
  /^((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?(?:(?:25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(2[0-4]|1?[0-9])?[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;

/**
 * Validates whether a string is a well-formed IPv4 or IPv6 address.
 */
export function isValidIp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  return IPV4_REGEX.test(trimmed) || IPV6_REGEX.test(trimmed);
}

/**
 * Extracts a trusted client IP address from incoming HTTP request headers.
 */
export function extractClientIp(
  source: Headers | { headers: Headers } | { get: (name: string) => string | null }
): string {
  const getHeader = (name: string): string | null => {
    if ("headers" in source && source.headers && typeof source.headers.get === "function") {
      return source.headers.get(name);
    }
    if ("get" in source && typeof source.get === "function") {
      return source.get(name);
    }
    return null;
  };

  // 1. Authoritative Vercel edge IP header (cannot be spoofed by clients on Vercel)
  const vercelIp = getHeader("x-vercel-ip")?.trim();
  if (vercelIp && isValidIp(vercelIp)) {
    return vercelIp;
  }

  // 2. Authoritative Cloudflare connecting IP (cannot be spoofed if behind Cloudflare)
  const cfIp = getHeader("cf-connecting-ip")?.trim();
  if (cfIp && isValidIp(cfIp)) {
    return cfIp;
  }

  // 3. Authoritative reverse proxy real IP (Nginx / ALB with proxy_set_header)
  const realIp = getHeader("x-real-ip")?.trim();
  if (realIp && isValidIp(realIp)) {
    return realIp;
  }

  // 4. Fallback: inspect X-Forwarded-For.
  // When an attacker sends a spoofed `X-Forwarded-For: 1.2.3.4`, edge proxies append the
  // real client IP: `1.2.3.4, <real-client-ip>`. We take the rightmost valid entry.
  const forwardedFor = getHeader("x-forwarded-for");
  if (forwardedFor) {
    const parts = forwardedFor
      .split(",")
      .map((p) => p.trim())
      .filter((p) => p.length > 0);

    // Scan backwards from right to left to get the IP appended by the edge proxy
    for (let i = parts.length - 1; i >= 0; i--) {
      const candidate = parts[i];
      if (isValidIp(candidate)) {
        return candidate;
      }
    }
  }

  // 5. Default fallback for local dev / loopback
  return "127.0.0.1";
}
