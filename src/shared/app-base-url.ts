/** Origin of the UI, used in mail links when APP_BASE_URL is not configured. */
export const DEFAULT_APP_BASE_URL = 'https://creatorcredentials.app';

type Warn = (message: string) => void;

/**
 * The public origin of the UI (APP_BASE_URL), without a trailing slash.
 * Falls back to the default origin and reports the fallback through `warn`.
 */
export function resolveAppBaseUrl(warn: Warn): string {
  const configured = readOrigin('APP_BASE_URL');
  if (configured) {
    return configured;
  }
  warn(`APP_BASE_URL is not set, links use ${DEFAULT_APP_BASE_URL}`);
  return DEFAULT_APP_BASE_URL;
}

/**
 * The public origin of this backend (API_BASE_URL): every URL the backend
 * issues about itself, such as the status list, is built on it. Falls back
 * to APP_BASE_URL and reports the fallback through `warn`.
 */
export function resolveApiBaseUrl(warn: Warn): string {
  const configured = readOrigin('API_BASE_URL');
  if (configured) {
    return configured;
  }
  warn('API_BASE_URL is not set, status-list URLs use APP_BASE_URL');
  return resolveAppBaseUrl(warn);
}

function readOrigin(variable: string): string | undefined {
  const value = process.env[variable]?.trim();
  return value ? value.replace(/\/+$/, '') : undefined;
}
