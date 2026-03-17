import {type PartialWithUndefined} from '@augment-vir/common';
import {type FullDate, type UtcTimezone} from 'date-vir';
import {
    AuthCookieName,
    clearAuthCookie,
    type CookieParams,
    extractCookieJwt,
    generateAuthCookie,
} from './cookie.js';
import {type CsrfTokenStore} from './csrf-token-store.js';
import {
    type CsrfHeaderNameOption,
    extractCsrfTokenHeader,
    generateCsrfToken,
    resolveCsrfHeaderName,
    storeCsrfToken,
} from './csrf-token.js';
import {type ParseJwtParams} from './jwt/jwt.js';
import {type JwtUserData} from './jwt/user-jwt.js';

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
    /** When the JWT was issued (`iat` claim). */
    jwtIssuedAt: FullDate<UtcTimezone>;
    cookieName: string;
    /** The CSRF token embedded in the JWT. */
    csrfToken: string;
    /**
     * Unix timestamp (in milliseconds) when the session was originally started. Used to enforce max
     * session duration.
     */
    sessionStartedAt: JwtUserData['sessionStartedAt'];
};

function readCsrfTokenHeader(
    headers: HeaderContainer,
    csrfHeaderNameOption: Readonly<CsrfHeaderNameOption>,
): string | undefined {
    return readHeader(headers, resolveCsrfHeaderName(csrfHeaderNameOption));
}

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
    csrfHeaderNameOption: Readonly<CsrfHeaderNameOption>,
    cookieName: string = AuthCookieName.Auth,
): Promise<Readonly<UserIdResult<UserId>> | undefined> {
    try {
        const csrfToken = readCsrfTokenHeader(headers, csrfHeaderNameOption);
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
            jwtIssuedAt: jwt.jwtIssuedAt,
            cookieName,
            csrfToken: jwt.data.csrfToken,
            sessionStartedAt: jwt.data.sessionStartedAt,
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
 * @category Auth : Host
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
            jwtIssuedAt: jwt.jwtIssuedAt,
            cookieName,
            csrfToken: jwt.data.csrfToken,
            sessionStartedAt: jwt.data.sessionStartedAt,
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
    csrfHeaderNameOption: Readonly<CsrfHeaderNameOption>,
    /**
     * The timestamp (in seconds) when the session originally started. If not provided, the current
     * time will be used (for new sessions).
     */
    sessionStartedAt?: number | undefined,
): Promise<Record<string, string>> {
    const csrfToken = generateCsrfToken();
    const csrfHeaderName = resolveCsrfHeaderName(csrfHeaderNameOption);

    const {cookie} = await generateAuthCookie(
        {
            csrfToken,
            userId,
            sessionStartedAt: sessionStartedAt ?? Date.now(),
        },
        cookieConfig,
    );

    return {
        'set-cookie': cookie,
        [csrfHeaderName]: csrfToken,
    };
}

/**
 * Used by host (backend) code to set headers on a response object when the user has logged out or
 * failed to authorize.
 *
 * @category Auth : Host
 */
export function generateLogoutHeaders(
    cookieConfig: Readonly<Pick<CookieParams, 'cookieName' | 'hostOrigin' | 'isDev'>>,
): Record<string, string> {
    return {
        'set-cookie': clearAuthCookie(cookieConfig),
    };
}

/**
 * Store auth data on a client (frontend) after receiving an auth response from the host (backend).
 * Specifically, this stores the CSRF token into IndexedDB (which doesn't need to be a secret).
 * Alternatively, if the given response failed, this will wipe the existing (if any) stored CSRF
 * token.
 *
 * @category Auth : Client
 * @throws Error if no CSRF token header is found.
 */
export async function handleAuthResponse(
    response: Readonly<Pick<Response, 'ok' | 'headers'>>,
    options: Readonly<CsrfHeaderNameOption> &
        PartialWithUndefined<{
            /**
             * Allows mocking or overriding the default CSRF token store.
             *
             * @default getDefaultCsrfTokenStore()
             */
            csrfTokenStore: CsrfTokenStore;
        }>,
): Promise<void> {
    if (!response.ok) {
        return;
    }

    const csrfToken = extractCsrfTokenHeader(response, options);

    if (!csrfToken) {
        throw new Error('Did not receive any CSRF token.');
    }

    await storeCsrfToken(csrfToken, options);
}
