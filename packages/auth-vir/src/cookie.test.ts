import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {extractCookieJwt, generateCookie} from './cookie.js';
import {generateNewJwtKeys, parseJwtKeys} from './jwt-keys.js';
import {mockJwtParams} from './jwt.mock.js';
import type {UserJwtData} from './user-jwt.js';

async function setCookieParams() {
    const mockJwt: UserJwtData = {
        csrfToken: 'fake token',
        userId: 'fake id',
    };

    const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

    return {
        mockJwt,
        jwtKeys,
        cookieParams: {
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
            cookieDuration: {
                days: 20,
            },
            hostOrigin: 'https://example.com',
        },
    };
}

describe('cookie', () => {
    it('sets and extracts a cookie', async () => {
        const {jwtKeys, mockJwt, cookieParams} = await setCookieParams();

        assert.deepEquals(
            await extractCookieJwt(await generateCookie(mockJwt, cookieParams), {
                ...mockJwtParams,
                jwtKeys,
            }),
            mockJwt,
        );
    });
});

describe(generateCookie.name, () => {
    it('generates a secure cookie by default', async () => {
        const {mockJwt, cookieParams} = await setCookieParams();

        const cookie = await generateCookie(mockJwt, cookieParams);
        assert.endsWith(cookie, '; Secure');
    });
    it('can generate an insecure cookie', async () => {
        const {mockJwt, cookieParams} = await setCookieParams();

        const cookie = await generateCookie(mockJwt, {
            ...cookieParams,
            isDev: true,
        });
        assert.lacksValue(cookie, 'Secure');
    });
});
