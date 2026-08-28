import {check} from '@augment-vir/assert';
import {
    escapeStringForRegExp,
    safeMatch,
    type PartialWithUndefined,
    type Primitive,
    type SelectFrom,
} from '@augment-vir/common';
import {convertDuration, type AnyDuration} from 'date-vir';
import {parseUrl} from 'url-vir';
import {type CreateJwtParams, type ParseJwtParams, type ParsedJwt} from './jwt/jwt.js';
import {createUserJwt, parseUserJwt, type JwtUserData} from './jwt/user-jwt.js';

/**
 * Cookie header names supported by default.
 *
 * @category Internal
 */
export enum AuthCookie {
    /** Used for a full user login auth. */
    Auth = 'auth',
    /** Use for a temporary "just signed up" auth. */
    SignUp = 'sign-up',
    /** Used for storing the CSRF token. Not `HttpOnly` so that frontend JS can read it. */
    Csrf = 'auth-vir-csrf',
}

/**
 * Resolves a cookie name by appending a suffix when provided. When `cookieNameSuffix` is
 * `undefined`, the base name is returned unchanged.
 *
 * @category Internal
 */
export function resolveCookieName(
    baseCookieName: AuthCookie,
    cookieNameSuffix?: string | undefined,
): string {
    return [
        baseCookieName,
        cookieNameSuffix,
    ]
        .filter(check.isTruthy)
        .join('-');
}

/**
 * Parameters for {@link generateAuthCookie}.
 *
 * @category Internal
 */
export type CookieParams = {
    /**
     * The origin of the host (backend) service that cookies will be included in all requests to.
     * This should be restricted to just your host (backend) origin for security purposes.
     *
     * @example 'https://www.example.com'
     */
    hostOrigin: string;
    /**
     * The max duration of this cookie. Or, in other words, the max user session duration before
     * they're logged out.
     */
    cookieDuration: AnyDuration;
    /**
     * All JWT parameters required for generating the encrypted JWT that will be embedded in the
     * Cookie. Note that all JWT keys contained herein should never shared with any frontend,
     * client, etc.
     */
    jwtParams: Readonly<CreateJwtParams>;
} & PartialWithUndefined<{
    /**
     * Which auth cookie name to use.
     *
     * @default AuthCookie.Auth
     */
    authCookie: AuthCookie;
    /**
     * Is set to `true` (which should only be done in development environments), the cookie will be
     * allowed in insecure requests (non HTTPS requests).
     *
     * @default false
     */
    isDev: boolean;
    /**
     * Optional suffix appended to cookie names (e.g., `'staging'` produces `auth-staging`). When
     * `undefined`, cookie names are unchanged. Useful for running multiple environments on the same
     * domain without cookie collisions.
     */
    cookieNameSuffix: string;
}>;

function generateSetCookie({
    name,
    value,
    httpOnly,
    cookieConfig,
}: {
    name: string;
    value: string;
    httpOnly: boolean;
    cookieConfig: Readonly<SelectFrom<CookieParams, {hostOrigin: true; isDev: true}>> &
        PartialWithUndefined<SelectFrom<CookieParams, {cookieDuration: true}>>;
}): string {
    return generateCookie({
        [name]: value,
        Domain: parseUrl(cookieConfig.hostOrigin).hostname,
        HttpOnly: httpOnly,
        Path: '/',
        SameSite: 'Strict',
        'MAX-AGE': cookieConfig.cookieDuration
            ? convertDuration(cookieConfig.cookieDuration, {
                  seconds: true,
              }).seconds
            : 0,
        Secure: !cookieConfig.isDev,
    });
}

/**
 * Generate a secure cookie that stores the user JWT data. Used in host (backend) code.
 *
 * @category Internal
 */
export async function generateAuthCookie(
    userJwtData: Readonly<JwtUserData>,
    cookieConfig: Readonly<CookieParams>,
): Promise<string> {
    return generateSetCookie({
        name: resolveCookieName(
            cookieConfig.authCookie || AuthCookie.Auth,
            cookieConfig.cookieNameSuffix,
        ),
        value: await createUserJwt(userJwtData, cookieConfig.jwtParams),
        httpOnly: true,
        cookieConfig,
    });
}

/**
 * Generate a CSRF token cookie. This cookie is intentionally not `HttpOnly` so that frontend
 * JavaScript can read it and inject the value as a request header for double-submit verification.
 *
 * The CSRF cookie uses a fixed 400-day MAX-AGE rather than matching the auth cookie duration. 400
 * days is the cross-browser safe maximum (Chrome caps cookie lifetimes at 400 days; other browsers
 * accept it as-is). The CSRF token is only meaningful when paired with a valid JWT, so it doesn't
 * need its own expiration management. It gets regenerated on every fresh login.
 *
 * @category Internal
 */
export function generateCsrfCookie(
    csrfToken: string,
    cookieConfig: Readonly<SelectFrom<CookieParams, {hostOrigin: true; isDev: true}>> &
        PartialWithUndefined<{cookieNameSuffix: string}>,
): string {
    return generateSetCookie({
        name: resolveCookieName(AuthCookie.Csrf, cookieConfig.cookieNameSuffix),
        value: csrfToken,
        httpOnly: false,
        cookieConfig: {
            ...cookieConfig,
            cookieDuration: {
                days: 400,
            },
        },
    });
}

/**
 * Generate a cookie value that will clear the previous auth cookie. Use this when signing out.
 *
 * @category Internal
 */
export function clearAuthCookie(
    cookieConfig: Readonly<SelectFrom<CookieParams, {hostOrigin: true; isDev: true}>> &
        PartialWithUndefined<{authCookie: AuthCookie; cookieNameSuffix: string}>,
) {
    return generateSetCookie({
        name: resolveCookieName(
            cookieConfig.authCookie || AuthCookie.Auth,
            cookieConfig.cookieNameSuffix,
        ),
        value: 'redacted',
        httpOnly: true,
        cookieConfig: {
            ...cookieConfig,
            /** Force `MAX-AGE=0` so the browser deletes the cookie. */
            cookieDuration: undefined,
        },
    });
}

/**
 * Generate a cookie value that will clear the CSRF token cookie. Use this when signing out.
 *
 * @category Internal
 */
export function clearCsrfCookie(
    cookieConfig: Readonly<SelectFrom<CookieParams, {hostOrigin: true; isDev: true}>> &
        PartialWithUndefined<{cookieNameSuffix: string}>,
) {
    return generateSetCookie({
        name: resolveCookieName(AuthCookie.Csrf, cookieConfig.cookieNameSuffix),
        value: 'redacted',
        httpOnly: false,
        cookieConfig: {
            ...cookieConfig,
            /** Same `MAX-AGE=0` reasoning as {@link clearAuthCookie}. */
            cookieDuration: undefined,
        },
    });
}

/**
 * Generate a cookie string from a raw set of parameters.
 *
 * @category Internal
 */
export function generateCookie(
    params: Readonly<Record<string, Exclude<Primitive, symbol>>>,
): string {
    return Object.entries(params)
        .map(
            ([
                key,
                value,
            ]): string | undefined => {
                if (value == undefined || value === false) {
                    return undefined;
                } else if (value === '' || value === true) {
                    return key;
                } else {
                    return [
                        key,
                        value,
                    ].join('=');
                }
            },
        )
        .filter(check.isTruthy)
        .join('; ');
}

/**
 * Extract an auth cookie from a cookie string. Used in host (backend) code.
 *
 * @category Internal
 * @returns The extracted auth Cookie JWT data or `undefined` if no valid auth JWT data was found.
 */
export async function extractCookieJwt({
    rawCookie,
    jwtParams,
    cookieName,
    cookieNameSuffix,
}: {
    rawCookie: string;
    jwtParams: Readonly<ParseJwtParams>;
    cookieName: AuthCookie;
} & PartialWithUndefined<{
    cookieNameSuffix: string;
}>): Promise<undefined | ParsedJwt<JwtUserData>> {
    const resolvedName = resolveCookieName(cookieName, cookieNameSuffix);
    const cookieRegExp = new RegExp(`${escapeStringForRegExp(resolvedName)}=[^;]+(?:;|$)`);

    const [cookieValue] = safeMatch(rawCookie, cookieRegExp);

    if (!cookieValue) {
        return undefined;
    }

    const rawJwt = cookieValue.replace(`${resolvedName}=`, '').replace(';', '');

    const jwt = await parseUserJwt(rawJwt, jwtParams);

    return jwt;
}
