/* eslint-disable @typescript-eslint/no-deprecated */

import {assert, assertWrap} from '@augment-vir/assert';
import {omitObjectKeys} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {
    extractUserIdFromRequestHeaders,
    generateLogoutHeaders,
    generateSuccessfulLoginHeaders,
    insecureExtractUserIdFromCookieAlone,
} from './auth.js';
import {AuthCookie, resolveCookieName} from './cookie.js';
import {getCurrentCsrfToken, resolveCsrfHeaderName} from './csrf-token.js';
import {
    clearCsrfCookieInBrowser,
    setCookiesToRequestCookie,
    simulateBrowserCookieStorage,
} from './csrf-token.mock.js';
import {generateNewJwtKeys, parseJwtKeys} from './jwt/jwt-keys.js';
import {mockJwtParams} from './jwt/jwt.mock.js';

const testCsrfOption = {
    csrfHeaderPrefix: 'test',
};
const testCsrfHeaderName = resolveCsrfHeaderName(testCsrfOption);

const mockUserId = 'mock-id';

async function setupHeaders() {
    clearCsrfCookieInBrowser();
    const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

    const serverHeaders = await generateSuccessfulLoginHeaders(mockUserId, {
        cookieDuration: {
            days: 20,
        },
        hostOrigin: 'https://www.example.com',
        jwtParams: {
            ...mockJwtParams,
            jwtKeys,
        },
    });

    const setCookies = assertWrap.isArray(serverHeaders['set-cookie']);
    simulateBrowserCookieStorage(setCookies);

    const clientHeaders = {
        cookie: setCookiesToRequestCookie(setCookies),
        [testCsrfHeaderName]: assertWrap.isTruthy(getCurrentCsrfToken()),
    };

    return {
        headers: clientHeaders,
        setCookies,
        jwtParams: {
            ...mockJwtParams,
            jwtKeys,
        },
    };
}

describe(extractUserIdFromRequestHeaders.name, () => {
    it('works on valid auth', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.strictEquals(
            (
                await extractUserIdFromRequestHeaders({
                    headers,
                    jwtParams,
                    csrfHeaderNameOption: testCsrfOption,
                    cookieName: AuthCookie.Auth,
                })
            )?.userId,
            mockUserId,
        );
    });
    it('works on valid auth with an array header', async () => {
        const {headers, jwtParams} = await setupHeaders();
        const csrfTokenHeaderName = headers[testCsrfHeaderName];
        assert.isDefined(csrfTokenHeaderName);

        assert.strictEquals(
            (
                await extractUserIdFromRequestHeaders({
                    headers: {
                        cookie: headers.cookie,
                        [testCsrfHeaderName]: [csrfTokenHeaderName],
                    },
                    jwtParams,
                    csrfHeaderNameOption: testCsrfOption,
                    cookieName: AuthCookie.Auth,
                })
            )?.userId,
            mockUserId,
        );
    });
    it('works on valid auth with Headers object', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const headersObject = new Headers(headers);

        assert.strictEquals(
            (
                await extractUserIdFromRequestHeaders({
                    headers: headersObject,
                    jwtParams,
                    csrfHeaderNameOption: testCsrfOption,
                    cookieName: AuthCookie.Auth,
                })
            )?.userId,
            mockUserId,
        );
    });
    it('rejects missing cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders({
                headers: omitObjectKeys(headers, ['cookie']),
                jwtParams,
                csrfHeaderNameOption: testCsrfOption,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
    it('rejects missing cookie with headers object', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders({
                headers: new Headers(omitObjectKeys(headers, ['cookie'])),
                jwtParams,
                csrfHeaderNameOption: testCsrfOption,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
    it('rejects missing CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders({
                headers: omitObjectKeys(headers, [testCsrfHeaderName]),
                jwtParams,
                csrfHeaderNameOption: testCsrfOption,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
    it('rejects mismatched CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders({
                headers: {
                    ...headers,
                    [testCsrfHeaderName]: 'invalid token',
                },
                jwtParams,
                csrfHeaderNameOption: testCsrfOption,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
    it('rejects invalid JWT', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const cookie = [
            'auth=asdf;',
            'HttpOnly;',
            'SameSite=Strict;',
        ].join(' ');

        assert.isUndefined(
            await extractUserIdFromRequestHeaders({
                headers: {
                    ...headers,
                    cookie,
                },
                jwtParams,
                csrfHeaderNameOption: testCsrfOption,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
    it('rejects invalid cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const cookie = [
            'HttpOnly;',
            'SameSite=Strict;',
        ].join(' ');

        assert.isUndefined(
            await extractUserIdFromRequestHeaders({
                headers: {
                    ...headers,
                    cookie,
                },
                jwtParams,
                csrfHeaderNameOption: testCsrfOption,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
});

describe(insecureExtractUserIdFromCookieAlone.name, () => {
    it('rejects missing cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await insecureExtractUserIdFromCookieAlone({
                headers: omitObjectKeys(headers, ['cookie']),
                jwtParams,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
    it('accepts missing CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.strictEquals(
            (
                await insecureExtractUserIdFromCookieAlone({
                    headers: omitObjectKeys(headers, [testCsrfHeaderName]),
                    jwtParams,
                    cookieName: AuthCookie.Auth,
                })
            )?.userId,
            mockUserId,
        );
    });
    it('accepts cookie and CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.strictEquals(
            (
                await insecureExtractUserIdFromCookieAlone({
                    headers,
                    jwtParams,
                    cookieName: AuthCookie.Auth,
                })
            )?.userId,
            mockUserId,
        );
    });
    it('rejects invalid JWT', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const cookie = [
            'auth=asdf;',
            'HttpOnly;',
            'SameSite=Strict;',
        ].join(' ');

        assert.isUndefined(
            await insecureExtractUserIdFromCookieAlone({
                headers: {
                    ...headers,
                    cookie,
                },
                jwtParams,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
    it('rejects invalid cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const cookie = [
            'HttpOnly;',
            'SameSite=Strict;',
        ].join(' ');

        assert.isUndefined(
            await insecureExtractUserIdFromCookieAlone({
                headers: {
                    ...headers,
                    cookie,
                },
                jwtParams,
                cookieName: AuthCookie.Auth,
            }),
        );
    });
});

describe(generateLogoutHeaders.name, () => {
    it('generates headers', () => {
        assert.deepEquals(
            generateLogoutHeaders({
                hostOrigin: 'my-origin',
                isDev: true,
            }),
            {
                'set-cookie': [
                    'auth=redacted; Domain=my-origin; HttpOnly; Path=/; SameSite=Strict; MAX-AGE=0',
                    'auth-vir-csrf=redacted; Domain=my-origin; Path=/; SameSite=Strict; MAX-AGE=0',
                ],
            },
        );
    });

    it('preserves CSRF cookie when preserveCsrf is true', () => {
        assert.deepEquals(
            generateLogoutHeaders(
                {
                    hostOrigin: 'my-origin',
                    isDev: true,
                },
                {
                    preserveCsrf: true,
                },
            ),
            {
                'set-cookie': [
                    'auth=redacted; Domain=my-origin; HttpOnly; Path=/; SameSite=Strict; MAX-AGE=0',
                ],
            },
        );
    });
});

describe('sign-up then login flow', () => {
    it('signs up, stores CSRF, and validates authenticated request', async () => {
        clearCsrfCookieInBrowser();
        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        /** Step 1: Backend generates sign-up response headers (both cookies). */
        const signUpHeaders = await generateSuccessfulLoginHeaders(mockUserId, {
            cookieDuration: {
                hours: 2,
            },
            hostOrigin: 'https://www.example.com',
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
        });

        /** Step 2: Simulate browser storing the CSRF cookie from Set-Cookie. */
        const setCookies = assertWrap.isArray(signUpHeaders['set-cookie']);
        simulateBrowserCookieStorage(setCookies);

        /** Step 3: Frontend retrieves the stored CSRF token from the cookie. */
        const csrfToken = assertWrap.isDefined(getCurrentCsrfToken(), 'CSRF token should exist.');

        /** Step 4: Backend validates the authenticated request. */
        const requestHeaders = {
            cookie: setCookiesToRequestCookie(setCookies),
            [testCsrfHeaderName]: csrfToken,
        };

        const userIdResult = await extractUserIdFromRequestHeaders({
            headers: requestHeaders,
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
            csrfHeaderNameOption: testCsrfOption,
            cookieName: AuthCookie.Auth,
        });
        assert.strictEquals(userIdResult?.userId, mockUserId);
    });

    it('can login after sign-up and logout', async () => {
        clearCsrfCookieInBrowser();
        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());
        const cookieConfig = {
            cookieDuration: {
                hours: 2,
            },
            hostOrigin: 'https://www.example.com',
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
        };

        /** Step 1: Sign up. */
        const signUpHeaders = await generateSuccessfulLoginHeaders(mockUserId, cookieConfig);
        simulateBrowserCookieStorage(assertWrap.isArray(signUpHeaders['set-cookie']));

        /** Step 2: Verify sign-up stored the CSRF token. */
        assert.isDefined(getCurrentCsrfToken(), 'CSRF token should exist after sign-up.');

        /**
         * Step 3: "Logout" - the CSRF token is NOT wiped anymore (recent change). Cookie still
         * exists in the browser.
         */

        /** Step 4: Login (generates new login headers). */
        const loginHeaders = await generateSuccessfulLoginHeaders(mockUserId, cookieConfig);
        const loginSetCookies = assertWrap.isArray(loginHeaders['set-cookie']);
        simulateBrowserCookieStorage(loginSetCookies);

        /** Step 5: Verify login stored the new CSRF token. */
        const loginCsrfToken = assertWrap.isDefined(
            getCurrentCsrfToken(),
            'CSRF token should exist after login.',
        );

        /** Step 6: Verify the new CSRF token works for authentication. */
        const requestHeaders = {
            cookie: setCookiesToRequestCookie(loginSetCookies),
            [testCsrfHeaderName]: loginCsrfToken,
        };

        const userIdResult = await extractUserIdFromRequestHeaders({
            headers: requestHeaders,
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
            csrfHeaderNameOption: testCsrfOption,
            cookieName: AuthCookie.Auth,
        });
        assert.strictEquals(userIdResult?.userId, mockUserId);
    });
});

describe('cookieNameSuffix', () => {
    const testSuffix = 'staging';

    async function setupSuffixedHeaders(cookieNameSuffix?: string | undefined) {
        clearCsrfCookieInBrowser();
        clearCsrfCookieInBrowser(testSuffix);
        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        const serverHeaders = await generateSuccessfulLoginHeaders(mockUserId, {
            cookieDuration: {
                days: 20,
            },
            hostOrigin: 'https://www.example.com',
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
            cookieNameSuffix,
        });

        const setCookies = assertWrap.isArray(serverHeaders['set-cookie']);
        simulateBrowserCookieStorage(setCookies, cookieNameSuffix);

        const clientHeaders = {
            cookie: setCookiesToRequestCookie(setCookies),
            [testCsrfHeaderName]: assertWrap.isTruthy(getCurrentCsrfToken(cookieNameSuffix)),
        };

        return {
            headers: clientHeaders,
            setCookies,
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
        };
    }

    it('extractUserIdFromRequestHeaders with suffix reads a suffixed cookie', async () => {
        const {headers, jwtParams} = await setupSuffixedHeaders(testSuffix);

        assert.strictEquals(
            (
                await extractUserIdFromRequestHeaders({
                    headers,
                    jwtParams,
                    csrfHeaderNameOption: testCsrfOption,
                    cookieName: AuthCookie.Auth,
                    cookieNameSuffix: testSuffix,
                })
            )?.userId,
            mockUserId,
        );
    });

    it('extractUserIdFromRequestHeaders with suffix cannot read a cookie without a suffix', async () => {
        const {headers, jwtParams} = await setupSuffixedHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders({
                headers,
                jwtParams,
                csrfHeaderNameOption: testCsrfOption,
                cookieName: AuthCookie.Auth,
                cookieNameSuffix: testSuffix,
            }),
        );
    });

    it('extractUserIdFromRequestHeaders without suffix cannot read a suffixed cookie', async () => {
        const {headers, jwtParams} = await setupSuffixedHeaders(testSuffix);

        assert.isUndefined(
            await extractUserIdFromRequestHeaders({
                headers,
                jwtParams,
                csrfHeaderNameOption: testCsrfOption,
                cookieName: AuthCookie.Auth,
            }),
        );
    });

    it('generateLogoutHeaders with suffix produces suffixed cookie names', () => {
        const logoutHeaders = generateLogoutHeaders({
            hostOrigin: 'my-origin',
            isDev: true,
            cookieNameSuffix: testSuffix,
        });

        const setCookies = logoutHeaders['set-cookie'];
        const resolvedAuthName = resolveCookieName(AuthCookie.Auth, testSuffix);
        const resolvedCsrfName = resolveCookieName(AuthCookie.Csrf, testSuffix);

        assert.deepEquals(setCookies, [
            `${resolvedAuthName}=redacted; Domain=my-origin; HttpOnly; Path=/; SameSite=Strict; MAX-AGE=0`,
            `${resolvedCsrfName}=redacted; Domain=my-origin; Path=/; SameSite=Strict; MAX-AGE=0`,
        ]);
    });
});
