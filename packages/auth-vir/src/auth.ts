import {type FullDate, type UtcTimezone} from 'date-vir';
import {
    AuthCookieName,
    clearAuthCookie,
    type CookieParams,
    extractCookieJwt,
    generateAuthCookie,
} from './cookie.js';
import {generateCsrfToken} from './csrf-token.js';
import {AuthHeaderName} from './headers.js';
import {type ParseJwtParams} from './jwt/jwt.js';

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
 * Output from {@link extractUserIdFromRequestHeaders}.
 *
 * @category Internal
 */
export type UserIdResult<UserId extends string | number> = {
    userId: UserId;
    jwtExpiration: FullDate<UtcTimezone>;
    cookieName: string;
};

/**
 * Extract the user id from a request by checking both the request cookie and CSRF token. This is
 * used by host (backend) code to help verify a request. After extracting the user id using this,
 * you should compare it to users stored in your database.
 *
 * @category Auth : Host
 * @returns The extracted user id or `undefined` if no valid auth headers exist.
 */
export async function extractUserIdFromRequestHeaders<UserId extends string | number>(
    headers: HeaderContainer,
    jwtParams: Readonly<ParseJwtParams>,
    cookieName: string = AuthCookieName.Auth,
): Promise<Readonly<UserIdResult<UserId>> | undefined> {
    try {
        const csrfToken = readHeader(headers, AuthHeaderName.CsrfToken);
        const cookie = readHeader(headers, 'cookie');

        if (!cookie || !csrfToken) {
            return undefined;
        }

        const jwt = await extractCookieJwt(cookie, jwtParams, cookieName);

        if (!jwt || jwt.data.csrfToken !== csrfToken) {
            return undefined;
        }

        return {
            userId: jwt.data.userId as UserId,
            jwtExpiration: jwt.jwtExpiration,
            cookieName,
        };
    } catch {
        return undefined;
    }
}

/**
 * Extract a user id from just the cookie, without CSRF token validation. This is _less secure_ than
 * {@link extractUserIdFromRequestHeaders} as a result. This should only be used in rare
 * circumstances where you cannot rely on client-side JavaScript to insert the CSRF token.
 *
 * @deprecated Prefer {@link extractUserIdFromRequestHeaders} instead: it is more secure.
 */
export async function insecureExtractUserIdFromCookieAlone<UserId extends string | number>(
    headers: HeaderContainer,
    jwtParams: Readonly<ParseJwtParams>,
    cookieName: string = AuthCookieName.Auth,
): Promise<Readonly<UserIdResult<UserId>> | undefined> {
    try {
        const cookie = readHeader(headers, 'cookie');

        if (!cookie) {
            return undefined;
        }

        const jwt = await extractCookieJwt(cookie, jwtParams, cookieName);

        if (!jwt) {
            return undefined;
        }

        return {
            userId: jwt.data.userId as UserId,
            jwtExpiration: jwt.jwtExpiration,
            cookieName,
        };
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
    /** The id from your database of the user you're authenticating. */
    userId: string | number,
    cookieConfig: Readonly<CookieParams>,
): Promise<{
    'set-cookie': string;
    [AuthHeaderName.CsrfToken]: string;
}> {
    const csrfToken = generateCsrfToken();

    return {
        'set-cookie': await generateAuthCookie(
            {
                csrfToken,
                userId,
            },
            cookieConfig,
        ),
        [AuthHeaderName.CsrfToken]: csrfToken,
    };
}

/**
 * Used by host (backend) code to set headers on a response object when the user has logged out or
 * failed to authorize.
 *
 * @category Auth : Host
 */
export function generateLogoutHeaders(...params: Parameters<typeof clearAuthCookie>) {
    return {
        'set-cookie': clearAuthCookie(...params),
        [AuthHeaderName.CsrfToken]: 'redacted',
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
    const headerName = overrides.csrfHeaderName || AuthHeaderName.CsrfToken;

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
            overrides.csrfHeaderName || AuthHeaderName.CsrfToken,
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
        overrides.csrfHeaderName || AuthHeaderName.CsrfToken,
    );
}
