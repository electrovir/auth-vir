/* eslint-disable unicorn/no-document-cookie */

import {assertWrap} from '@augment-vir/assert';
import {AuthCookie, resolveCookieName} from './cookie.js';

/** Clear the CSRF cookie from the browser. Use at the start of tests to ensure a clean slate. */
export function clearCsrfCookieInBrowser(cookieNameSuffix?: string | undefined) {
    const resolvedName = resolveCookieName(AuthCookie.Csrf, cookieNameSuffix);
    globalThis.document.cookie = `${resolvedName}=; Path=/; SameSite=Strict; Max-Age=0`;
}

/** Simulate the browser storing a CSRF token cookie, as if it came from a Set-Cookie header. */
export function simulateCsrfCookie(csrfToken: string, cookieNameSuffix?: string | undefined) {
    const resolvedName = resolveCookieName(AuthCookie.Csrf, cookieNameSuffix);
    globalThis.document.cookie = `${resolvedName}=${csrfToken}; Path=/; SameSite=Strict`;
}

/**
 * Simulates the browser storing cookies from Set-Cookie response headers. Extracts the CSRF cookie
 * and sets it in `document.cookie` so that `getCurrentCsrfToken()` can read it.
 */
export function simulateBrowserCookieStorage(
    setCookies: ReadonlyArray<string>,
    cookieNameSuffix?: string | undefined,
) {
    const resolvedName = resolveCookieName(AuthCookie.Csrf, cookieNameSuffix);
    const csrfSetCookie = setCookies.find((cookie) => cookie.startsWith(resolvedName));
    if (csrfSetCookie) {
        const csrfValue = assertWrap.isTruthy(csrfSetCookie.split(';')[0]).split('=')[1];
        simulateCsrfCookie(assertWrap.isTruthy(csrfValue), cookieNameSuffix);
    }
}

/**
 * Extracts `name=value` from each Set-Cookie string and joins them into a single Cookie request
 * header, simulating what the browser sends to the server.
 */
export function setCookiesToRequestCookie(setCookies: ReadonlyArray<string>): string {
    return setCookies.map((cookie) => cookie.split(';')[0]).join('; ');
}
