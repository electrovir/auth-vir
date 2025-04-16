import {CookieParams, extractCookieJwt, generateCookie} from './cookie.js';
import {csrfTokenHeaderName, generateCsrfToken} from './csrf-token.js';
import {ParseJwtParams} from './jwt.js';

/**
 * All possible headers container types supported by {@link extractUserIdFromRequestHeaders}.
 *
 * @category Internal
 */
export type HeaderContainer = Record<string, string[] | undefined | string | number> | Headers;

function readHeader(headers: HeaderContainer, headerName: string): string | undefined {
    if (headers instanceof Headers) {
        return headers.get(headerName) || undefined;
    } else {
        const value = headers[headerName];

        if (value == undefined) {
            return undefined;
        } else if (Array.isArray(value)) {
            return value[0];
        } else {
            return String(value);
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
    headers: HeaderContainer,
    jwtParams: Readonly<ParseJwtParams>,
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
    /** The id from your database of the user you're authenticating. */
    cookieConfig: Readonly<CookieParams>,
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
 * Store auth data on a client (frontend) after receiving an auth response from the host (backend).
 * Specifically, this stores the CSRF token into local storage (which doesn't need to be a secret).
 * Alternatively, if the given response failed, this will wipe the existing (if anyone) stored CSRF
 * token.
 *
 * @category Auth : Client
 * @throws Error if no CSRF token header is found.
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
        /** Override the default CSRF token header name. */
        csrfHeaderName?: string;
    } = {},
) {
    if (!response.ok) {
        wipeCurrentCsrfToken(overrides);
        return;
    }
    const headerName = overrides.csrfHeaderName || csrfTokenHeaderName;

    const csrfToken = response.headers.get(headerName);

    if (!csrfToken) {
        wipeCurrentCsrfToken(overrides);
        throw new Error('Did not receive any CSRF token.');
    }

    (overrides.localStorage || globalThis.localStorage).setItem(headerName, csrfToken);
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
        /** Override the default CSRF token header name. */
        csrfHeaderName?: string;
    } = {},
): string | undefined {
    return (
        (overrides.localStorage || globalThis.localStorage).getItem(
            overrides.csrfHeaderName || csrfTokenHeaderName,
        ) || undefined
    );
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
        /** Override the default CSRF token header name. */
        csrfHeaderName?: string;
    } = {},
) {
    return (overrides.localStorage || globalThis.localStorage).removeItem(
        overrides.csrfHeaderName || csrfTokenHeaderName,
    );
}
