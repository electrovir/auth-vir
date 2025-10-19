import {check} from '@augment-vir/assert';
import {safeMatch, type PartialWithUndefined} from '@augment-vir/common';
import {convertDuration, type AnyDuration} from 'date-vir';
import {type Primitive} from 'type-fest';
import {parseUrl} from 'url-vir';
import {type CreateJwtParams, type ParseJwtParams, type ParsedJwt} from './jwt/jwt.js';
import {createUserJwt, parseUserJwt, type JwtUserData} from './jwt/user-jwt.js';

/**
 * Cookie header names supported by default.
 *
 * @category Internal
 */
export enum AuthCookieName {
    /** Used for a full user login auth. */
    Auth = 'auth',
    /** Use for a temporary "just signed up" auth. */
    SignUp = 'sign-up',
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
    cookieName?: string;
} & PartialWithUndefined<{
    /**
     * Is set to `true` (which should only be done in development environments), the cookie will be
     * allowed in insecure requests (non HTTPS requests).
     *
     * @default false
     */
    isDev: boolean;
}>;

/**
 * Generate a secure cookie that stores the user JWT data. Used in host (backend) code.
 *
 * @category Internal
 */
export async function generateAuthCookie(
    userJwtData: Readonly<JwtUserData>,
    cookieConfig: Readonly<CookieParams>,
): Promise<string> {
    return generateCookie({
        [cookieConfig.cookieName || 'auth']: await createUserJwt(
            userJwtData,
            cookieConfig.jwtParams,
        ),
        Domain: parseUrl(cookieConfig.hostOrigin).hostname,
        HttpOnly: true,
        Path: '/',
        SameSite: 'Strict',
        'MAX-AGE': convertDuration(cookieConfig.cookieDuration, {seconds: true}).seconds,
        Secure: !cookieConfig.isDev,
    });
}

/**
 * Generate a cookie value that will clear the previous auth cookie. Use this when signing out.
 *
 * @category Internal
 */
export function clearAuthCookie(
    cookieConfig: Readonly<Pick<CookieParams, 'cookieName' | 'hostOrigin' | 'isDev'>>,
) {
    return generateCookie({
        [cookieConfig.cookieName || 'auth']: 'redacted',
        Domain: parseUrl(cookieConfig.hostOrigin).hostname,
        HttpOnly: true,
        Path: '/',
        SameSite: 'Strict',
        'MAX-AGE': 0,
        Secure: !cookieConfig.isDev,
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
export async function extractCookieJwt(
    rawCookie: string,
    jwtParams: Readonly<ParseJwtParams>,
    cookieName: string = AuthCookieName.Auth,
): Promise<undefined | ParsedJwt<JwtUserData>> {
    const cookieRegExp = new RegExp(`${cookieName}=[^;]+(?:;|$)`);

    const [cookieValue] = safeMatch(rawCookie, cookieRegExp);

    if (!cookieValue) {
        return undefined;
    }

    const rawJwt = cookieValue.replace(`${cookieName}=`, '').replace(';', '');

    const jwt = await parseUserJwt(rawJwt, jwtParams);

    return jwt;
}
