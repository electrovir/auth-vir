import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {clearAuthCookie, extractCookieJwt, generateAuthCookie} from './cookie.js';
import {generateNewJwtKeys, parseJwtKeys} from './jwt/jwt-keys.js';
import {mockJwtParams} from './jwt/jwt.mock.js';
import {type UserJwtData} from './jwt/user-jwt.js';

async function getCookieParams() {
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

describe(clearAuthCookie.name, () => {
    it('creates a clear cookie', () => {
        assert.strictEquals(
            clearAuthCookie({
                hostOrigin: 'my origin',
                isDev: true,
            }),
            'auth=redacted; Domain=my origin; HttpOnly; Path=/; SameSite=Strict; MAX-AGE=0',
        );
    });
    it('uses a custom cookie name', () => {
        assert.strictEquals(
            clearAuthCookie({
                hostOrigin: 'my origin',
                cookieName: 'fake',
                isDev: true,
            }),
            'fake=redacted; Domain=my origin; HttpOnly; Path=/; SameSite=Strict; MAX-AGE=0',
        );
    });
});

describe('cookie', () => {
    it('sets and extracts a cookie', async () => {
        const {jwtKeys, mockJwt, cookieParams} = await getCookieParams();

        assert.deepEquals(
            await extractCookieJwt(await generateAuthCookie(mockJwt, cookieParams), {
                ...mockJwtParams,
                jwtKeys,
            }),
            mockJwt,
        );
    });
});

describe(generateAuthCookie.name, () => {
    it('generates a secure cookie by default', async () => {
        const {mockJwt, cookieParams} = await getCookieParams();

        const cookie = await generateAuthCookie(mockJwt, cookieParams);
        assert.endsWith(cookie, '; Secure');
    });
    it('can generate an insecure cookie', async () => {
        const {mockJwt, cookieParams} = await getCookieParams();

        const cookie = await generateAuthCookie(mockJwt, {
            ...cookieParams,
            isDev: true,
        });
        assert.lacksValue(cookie, 'Secure');
    });
    it('can use a custom cookie name', async () => {
        const {mockJwt, cookieParams} = await getCookieParams();

        const cookie = await generateAuthCookie(mockJwt, {
            ...cookieParams,
            cookieName: 'my-name',
        });
        assert.lacksValue(cookie, 'auth=');
        assert.hasValue(cookie, 'my-name=');
    });
});
