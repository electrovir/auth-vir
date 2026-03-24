import {type PartialWithUndefined, type SelectFrom} from '@augment-vir/common';
import {type FullDate, type UtcTimezone} from 'date-vir';
import {
    type AuthCookie,
    clearAuthCookie,
    clearCsrfCookie,
    type CookieParams,
    extractCookieJwt,
    generateAuthCookie,
    generateCsrfCookie,
} from './cookie.js';
import {type CsrfHeaderNameOption, generateCsrfToken, resolveCsrfHeaderName} from './csrf-token.js';
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
    cookieName: AuthCookie;
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
export async function extractUserIdFromRequestHeaders<UserId extends string | number>({
    headers,
    jwtParams,
    csrfHeaderNameOption,
    cookieName,
    cookieNameSuffix,
}: Readonly<{
    headers: HeaderContainer;
    jwtParams: Readonly<ParseJwtParams>;
    csrfHeaderNameOption: Readonly<CsrfHeaderNameOption>;
    cookieName: AuthCookie;
    cookieNameSuffix?: string | undefined;
}>): Promise<Readonly<UserIdResult<UserId>> | undefined> {
    try {
        const csrfToken = readCsrfTokenHeader(headers, csrfHeaderNameOption);
        const cookie = readHeader(headers, 'cookie');

        if (!cookie || !csrfToken) {
            return undefined;
        }

        const jwt = await extractCookieJwt({
            rawCookie: cookie,
            jwtParams,
            cookieName,
            cookieNameSuffix,
        });

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
export async function insecureExtractUserIdFromCookieAlone<UserId extends string | number>({
    headers,
    jwtParams,
    cookieName,
    cookieNameSuffix,
}: Readonly<{
    headers: HeaderContainer;
    jwtParams: Readonly<ParseJwtParams>;
    cookieName: AuthCookie;
    cookieNameSuffix?: string | undefined;
}>): Promise<Readonly<UserIdResult<UserId>> | undefined> {
    try {
        const cookie = readHeader(headers, 'cookie');

        if (!cookie) {
            return undefined;
        }

        const jwt = await extractCookieJwt({
            rawCookie: cookie,
            jwtParams,
            cookieName,
            cookieNameSuffix,
        });

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
 * Used by host (backend) code to set headers on a response object. Sets both the auth JWT cookie
 * and the CSRF token cookie. The CSRF cookie is not `HttpOnly` so that frontend JavaScript can read
 * it and inject the value as a request header.
 *
 * @category Auth : Host
 */
export async function generateSuccessfulLoginHeaders(
    /** The id from your database of the user you're authenticating. */
    userId: string | number,
    cookieConfig: Readonly<CookieParams>,
    /**
     * The timestamp (in seconds) when the session originally started. If not provided, the current
     * time will be used (for new sessions).
     */
    sessionStartedAt?: number | undefined,
): Promise<Record<string, string[]>> {
    const csrfToken = generateCsrfToken();

    const authCookie = await generateAuthCookie(
        {
            csrfToken,
            userId,
            sessionStartedAt: sessionStartedAt ?? Date.now(),
        },
        cookieConfig,
    );

    const csrfCookie = generateCsrfCookie(csrfToken, cookieConfig);

    return {
        'set-cookie': [
            authCookie,
            csrfCookie,
        ],
    };
}

/**
 * Used by host (backend) code to set headers on a response object when the user has logged out or
 * failed to authorize.
 *
 * @category Auth : Host
 */
export function generateLogoutHeaders(
    cookieConfig: Readonly<SelectFrom<CookieParams, {hostOrigin: true; isDev: true}>> &
        PartialWithUndefined<{cookieNameSuffix: string}>,
    options?: Readonly<
        PartialWithUndefined<{
            /**
             * When `true`, the CSRF cookie is preserved (not cleared). Use this when clearing only
             * one cookie type (e.g., the auth cookie) while keeping the other active session (e.g.,
             * sign-up) that still needs its CSRF token.
             */
            preserveCsrf: boolean;
        }>
    >,
): Record<string, string[]> {
    return {
        'set-cookie': [
            clearAuthCookie(cookieConfig),
            ...(options?.preserveCsrf
                ? []
                : [
                      clearCsrfCookie(cookieConfig),
                  ]),
        ],
    };
}
