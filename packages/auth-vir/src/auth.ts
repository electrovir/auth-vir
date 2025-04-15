import {CookieConfig, extractCookieJwt, generateCookie} from './cookie.js';
import {csrfTokenHeaderName, generateCsrfToken} from './csrf-token.js';
import type {CreateJwtParams} from './jwt.js';

function readHeader(
    headers: Record<string, string[] | undefined | string> | Headers,
    headerName: string,
): string | undefined {
    if (headers instanceof Headers) {
        return headers.get(headerName) || undefined;
    } else {
        const value = headers[headerName];

        if (Array.isArray(value)) {
            return value[0];
        } else {
            return value;
        }
    }
}

/**
 * Extract the user id from a request by checking both the request cookie and CSRF token. This is
 * used by host (backend) code to help verify a request. After extracting the user id using this,
 * you should compare it to users stored in your database.
 *
 * @category Auth : Host
 * @returns The extracted user id or `undefined` if no valid auth headers exist.
 */
export async function extractUserIdFromRequestHeaders(
    headers: Record<string, string[] | undefined | string> | Headers,
    jwtParams: Readonly<CreateJwtParams>,
): Promise<string | undefined> {
    try {
        const csrfToken = readHeader(headers, csrfTokenHeaderName);
        const cookie = readHeader(headers, 'cookie');

        if (!cookie || !csrfToken) {
            return undefined;
        }

        const jwt = await extractCookieJwt(cookie, jwtParams);

        if (!jwt || jwt.csrfToken !== csrfToken) {
            return undefined;
        }

        return jwt.userId;
    } catch {
        return undefined;
    }
}

/**
 * Used by host (backend) code to set headers on a response object.
 *
 * @category Auth : Host
 */
export async function generateSuccessfulLoginHeaders(
    userId: string,
    cookieConfig: Readonly<CookieConfig>,
) {
    const csrfToken = generateCsrfToken();

    return {
        'set-cookie': await generateCookie(
            {
                csrfToken,
                userId,
            },
            cookieConfig,
        ),
        [csrfTokenHeaderName]: csrfToken,
    };
}

/**
 * Set auth data on a client (frontend) after receiving an auth response from the host (backend).
 *
 * @category Auth : Client
 */
export function handleAuthResponse(
    response: Readonly<Pick<Response, 'ok' | 'headers'>>,
    overrides: {
        /**
         * Allows mocking or overriding the global `localStorage`.
         *
         * @default globalThis.localStorage
         */
        localStorage?: Pick<Storage, 'setItem' | 'removeItem'>;
    } = {},
) {
    if (!response.ok) {
        wipeCurrentCsrfToken(overrides);
        return;
    }

    const csrfToken = response.headers.get(csrfTokenHeaderName);

    if (!csrfToken) {
        wipeCurrentCsrfToken(overrides);
        throw new Error('Did not receive any CSRF token.');
    }

    (overrides.localStorage || globalThis.localStorage).setItem(csrfTokenHeaderName, csrfToken);
}

/**
 * Used in client (frontend) code to retrieve the current CSRF token in order to send it with
 * requests to the host (backend).
 *
 * @category Auth : Client
 */
export function getCurrentCsrfToken(
    overrides: {
        /**
         * Allows mocking or overriding the global `localStorage`.
         *
         * @default globalThis.localStorage
         */
        localStorage?: Pick<Storage, 'getItem'>;
    } = {},
) {
    return (overrides.localStorage || globalThis.localStorage).getItem(csrfTokenHeaderName);
}

/**
 * Wipes the current stored CSRF token. This should be used by client (frontend) code to logout a
 * user or react to a session timeout.
 *
 * @category Auth : Client
 */
export function wipeCurrentCsrfToken(
    overrides: {
        /**
         * Allows mocking or overriding the global `localStorage`.
         *
         * @default globalThis.localStorage
         */
        localStorage?: Pick<Storage, 'removeItem'>;
    } = {},
) {
    return (overrides.localStorage || globalThis.localStorage).removeItem(csrfTokenHeaderName);
}
