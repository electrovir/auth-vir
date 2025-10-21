import {type PartialWithUndefined} from '@augment-vir/common';
import {type FullDate, type UtcTimezone} from 'date-vir';
import {
    AuthCookieName,
    clearAuthCookie,
    type CookieParams,
    extractCookieJwt,
    generateAuthCookie,
} from './cookie.js';
import {
    extractCsrfTokenHeader,
    generateCsrfToken,
    parseCsrfToken,
    storeCsrfToken,
    wipeCurrentCsrfToken,
} from './csrf-token.js';
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

function readCsrfTokenHeader(
    headers: HeaderContainer,
    overrides: PartialWithUndefined<{
        csrfHeaderName: string;
    }>,
): string | undefined {
    const rawCsrfToken = readHeader(headers, overrides.csrfHeaderName || AuthHeaderName.CsrfToken);

    if (!rawCsrfToken) {
        return undefined;
    }

    return parseCsrfToken(rawCsrfToken).csrfToken?.token || rawCsrfToken;
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
    cookieName: string = AuthCookieName.Auth,
    overrides: PartialWithUndefined<{
        csrfHeaderName: string;
    }> = {},
): Promise<Readonly<UserIdResult<UserId>> | undefined> {
    try {
        const csrfToken = readCsrfTokenHeader(headers, overrides);
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
export async function generateSuccessfulLoginHeaders<
    CsrfHeaderName extends string = AuthHeaderName.CsrfToken,
>(
    /** The id from your database of the user you're authenticating. */
    userId: string | number,
    cookieConfig: Readonly<CookieParams>,
    overrides: PartialWithUndefined<{
        csrfHeaderName: CsrfHeaderName;
    }> = {},
): Promise<
    {
        'set-cookie': string;
    } & Record<CsrfHeaderName, string>
> {
    const csrfToken = generateCsrfToken(cookieConfig.cookieDuration);
    const csrfHeaderName = (overrides.csrfHeaderName || AuthHeaderName.CsrfToken) as CsrfHeaderName;

    return {
        'set-cookie': await generateAuthCookie(
            {
                csrfToken: csrfToken.token,
                userId,
            },
            cookieConfig,
        ),
        [csrfHeaderName]: JSON.stringify(csrfToken),
    } as {
        'set-cookie': string;
    } & Record<CsrfHeaderName, string>;
}

/**
 * Used by host (backend) code to set headers on a response object when the user has logged out or
 * failed to authorize.
 *
 * @category Auth : Host
 */
export function generateLogoutHeaders<CsrfHeaderName extends string = AuthHeaderName.CsrfToken>(
    cookieConfig: Readonly<Pick<CookieParams, 'cookieName' | 'hostOrigin' | 'isDev'>>,
    overrides: PartialWithUndefined<{
        csrfHeaderName: CsrfHeaderName;
    }> = {},
): {
    'set-cookie': string;
} & Record<CsrfHeaderName, string> {
    const csrfHeaderName = (overrides.csrfHeaderName || AuthHeaderName.CsrfToken) as CsrfHeaderName;

    return {
        'set-cookie': clearAuthCookie(cookieConfig),
        [csrfHeaderName]: 'redacted',
    } as {
        'set-cookie': string;
    } & Record<CsrfHeaderName, string>;
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
    overrides: PartialWithUndefined<{
        /**
         * Allows mocking or overriding the global `localStorage`.
         *
         * @default globalThis.localStorage
         */
        localStorage: Pick<Storage, 'setItem' | 'removeItem'>;
        /** Override the default CSRF token header name. */
        csrfHeaderName: string;
    }> = {},
) {
    if (!response.ok) {
        wipeCurrentCsrfToken(overrides);
        return;
    }

    const {csrfToken} = extractCsrfTokenHeader(response, overrides);

    if (!csrfToken) {
        wipeCurrentCsrfToken(overrides);
        throw new Error('Did not receive any CSRF token.');
    }

    storeCsrfToken(csrfToken, overrides);
}
