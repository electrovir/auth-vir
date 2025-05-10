import {check} from '@augment-vir/assert';
import {safeMatch, type PartialWithUndefined} from '@augment-vir/common';
import {convertDuration, type AnyDuration} from 'date-vir';
import {parseUrl} from 'url-vir';
import {type CreateJwtParams, type ParseJwtParams} from './jwt.js';
import {createUserJwt, parseUserJwt, type UserJwtData} from './user-jwt.js';

/**
 * Parameters for {@link generateCookie}.
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
export async function generateCookie(
    userJwtData: Readonly<UserJwtData>,
    cookieConfig: Readonly<CookieParams>,
) {
    return [
        `auth=${await createUserJwt(userJwtData, cookieConfig.jwtParams)}`,
        `Domain=${parseUrl(cookieConfig.hostOrigin).hostname}`,
        'HttpOnly',
        'Path=/',
        'SameSite=Strict',
        `MAX-AGE=${convertDuration(cookieConfig.cookieDuration, {seconds: true}).seconds}`,
        cookieConfig.isDev ? '' : 'Secure',
    ]
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
): Promise<undefined | UserJwtData> {
    const [auth] = safeMatch(rawCookie, /auth=[^;]+(?:;|$)/);

    if (!auth) {
        return undefined;
    }

    const rawJwt = auth.replace('auth=', '').replace(';', '');

    const jwt = await parseUserJwt(rawJwt, jwtParams);

    return jwt;
}
