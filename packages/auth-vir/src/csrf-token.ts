import {check} from '@augment-vir/assert';
import {
    escapeStringForRegExp,
    randomString,
    safeMatch,
    type RequireExactlyOne,
} from '@augment-vir/common';
import {AuthCookie, resolveCookieName} from './cookie.js';

/**
 * Generates a random, cryptographically secure CSRF token string.
 *
 * @category Internal
 */
export function generateCsrfToken(): string {
    return randomString(256);
}

/**
 * Options for specifying the CSRF token header name.
 *
 * @category Auth : Client
 * @category Auth : Host
 */
export type CsrfHeaderNameOption = RequireExactlyOne<{
    /** Prefix used to generate the header name: `${prefix}-auth-vir-csrf-token`. */
    csrfHeaderPrefix: string;
    /** Overrides the entire CSRF header name. */
    csrfHeaderName: string;
}>;

/**
 * Resolves a {@link CsrfHeaderNameOption} to the actual header name string.
 *
 * @category Auth : Client
 * @category Auth : Host
 */
export function resolveCsrfHeaderName(options: Readonly<CsrfHeaderNameOption>): string {
    if ('csrfHeaderName' in options && options.csrfHeaderName) {
        return options.csrfHeaderName;
    } else {
        return [
            options.csrfHeaderPrefix,
            'auth-vir',
            'csrf-token',
        ]
            .filter(check.isTruthy)
            .join('-');
    }
}

/**
 * Used in client (frontend) code to retrieve the current CSRF token from the browser cookie in
 * order to send it with requests to the host (backend).
 *
 * @category Auth : Client
 */
export function getCurrentCsrfToken(cookieNameSuffix?: string | undefined): string | undefined {
    const resolvedName = resolveCookieName(AuthCookie.Csrf, cookieNameSuffix);
    const cookieRegExp = new RegExp(`${escapeStringForRegExp(resolvedName)}=([^;]+)`);
    const [
        ,
        value,
    ] = safeMatch(globalThis.document.cookie, cookieRegExp);
    return value || undefined;
}
