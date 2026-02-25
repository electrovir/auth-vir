/* eslint-disable @typescript-eslint/no-deprecated */

import {assert, assertWrap} from '@augment-vir/assert';
import {omitObjectKeys} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {
    extractUserIdFromRequestHeaders,
    generateLogoutHeaders,
    generateSuccessfulLoginHeaders,
    handleAuthResponse,
    insecureExtractUserIdFromCookieAlone,
} from './auth.js';
import {generateCsrfToken, getCurrentCsrfToken, resolveCsrfHeaderName} from './csrf-token.js';
import {generateNewJwtKeys, parseJwtKeys} from './jwt/jwt-keys.js';
import {mockJwtParams} from './jwt/jwt.mock.js';
import {
    createEmptyMockLocalStorageAccessRecord,
    createMockLocalStorage,
} from './mock-local-storage.js';

const testCsrfOption = {csrfHeaderPrefix: 'test'};
const testCsrfHeaderName = resolveCsrfHeaderName(testCsrfOption);

const mockUserId = 'mock-id';
async function setupHeaders() {
    const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

    const serverHeaders = await generateSuccessfulLoginHeaders(
        mockUserId,
        {
            cookieDuration: {days: 20},
            hostOrigin: 'https://www.example.com',
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
        },
        testCsrfOption,
    );

    const clientHeaders = {
        cookie: assertWrap.isTruthy(serverHeaders['set-cookie']),
        [testCsrfHeaderName]: assertWrap.isTruthy(serverHeaders[testCsrfHeaderName]),
    };

    return {
        headers: clientHeaders,
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
            (await extractUserIdFromRequestHeaders(headers, jwtParams, testCsrfOption))?.userId,
            mockUserId,
        );
    });
    it('works on valid auth with an array header', async () => {
        const {headers, jwtParams} = await setupHeaders();
        const csrfTokenHeaderName = headers[testCsrfHeaderName];
        assert.isDefined(csrfTokenHeaderName);

        assert.strictEquals(
            (
                await extractUserIdFromRequestHeaders(
                    {
                        cookie: headers.cookie,
                        [testCsrfHeaderName]: [csrfTokenHeaderName],
                    },
                    jwtParams,
                    testCsrfOption,
                )
            )?.userId,
            mockUserId,
        );
    });
    it('works on valid auth with Headers object', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const headersObject = new Headers(headers);

        assert.strictEquals(
            (await extractUserIdFromRequestHeaders(headersObject, jwtParams, testCsrfOption))
                ?.userId,
            mockUserId,
        );
    });
    it('rejects missing cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                omitObjectKeys(headers, ['cookie']),
                jwtParams,
                testCsrfOption,
            ),
        );
    });
    it('rejects missing cookie with headers object', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                new Headers(omitObjectKeys(headers, ['cookie'])),
                jwtParams,
                testCsrfOption,
            ),
        );
    });
    it('rejects missing CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                omitObjectKeys(headers, [testCsrfHeaderName]),
                jwtParams,
                testCsrfOption,
            ),
        );
    });
    it('rejects mismatched CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                {
                    ...headers,
                    [testCsrfHeaderName]: 'invalid token',
                },
                jwtParams,
                testCsrfOption,
            ),
        );
    });
    it('rejects invalid JWT', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const cookie = [
            `auth=asdf;`,
            'HttpOnly;',
            'SameSite=Strict;',
        ].join(' ');

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                {
                    ...headers,
                    cookie,
                },
                jwtParams,
                testCsrfOption,
            ),
        );
    });
    it('rejects invalid cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const cookie = [
            'HttpOnly;',
            'SameSite=Strict;',
        ].join(' ');

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                {
                    ...headers,
                    cookie,
                },
                jwtParams,
                testCsrfOption,
            ),
        );
    });
});

describe(insecureExtractUserIdFromCookieAlone.name, () => {
    it('rejects missing cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await insecureExtractUserIdFromCookieAlone(
                omitObjectKeys(headers, ['cookie']),
                jwtParams,
            ),
        );
    });
    it('accepts missing CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.strictEquals(
            (
                await insecureExtractUserIdFromCookieAlone(
                    omitObjectKeys(headers, [testCsrfHeaderName]),
                    jwtParams,
                )
            )?.userId,
            mockUserId,
        );
    });
    it('accepts cookie and CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.strictEquals(
            (await insecureExtractUserIdFromCookieAlone(headers, jwtParams))?.userId,
            mockUserId,
        );
    });
    it('rejects invalid JWT', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const cookie = [
            `auth=asdf;`,
            'HttpOnly;',
            'SameSite=Strict;',
        ].join(' ');

        assert.isUndefined(
            await insecureExtractUserIdFromCookieAlone(
                {
                    ...headers,
                    cookie,
                },
                jwtParams,
            ),
        );
    });
    it('rejects invalid cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const cookie = [
            'HttpOnly;',
            'SameSite=Strict;',
        ].join(' ');

        assert.isUndefined(
            await insecureExtractUserIdFromCookieAlone(
                {
                    ...headers,
                    cookie,
                },
                jwtParams,
            ),
        );
    });
});

describe(handleAuthResponse.name, () => {
    it('handles failed auth with mock localStorage', () => {
        const {accessRecord, localStorage} = createMockLocalStorage();

        const headers = new Headers();

        // fails because `ok` is false
        handleAuthResponse({ok: false, headers}, {localStorage, ...testCsrfOption});
        // fails because CSRF header is missing
        assert.throws(() =>
            handleAuthResponse({ok: true, headers}, {localStorage, ...testCsrfOption}),
        );
        assert.deepEquals(accessRecord, {
            ...createEmptyMockLocalStorageAccessRecord(),
            removeItem: [
                testCsrfHeaderName,
                testCsrfHeaderName,
            ],
        });
    });
    it('handles failed auth with default localStorage', () => {
        const headers = new Headers();

        // fails because `ok` is false
        handleAuthResponse({ok: false, headers}, testCsrfOption);
        // fails because CSRF header is missing
        assert.throws(() => handleAuthResponse({ok: true, headers}, testCsrfOption));
    });
    it('handles successful auth with mock localStorage', () => {
        const mockCsrfToken = generateCsrfToken({days: 2});

        const {accessRecord, localStorage} = createMockLocalStorage();

        const headers = new Headers({
            [testCsrfHeaderName]: JSON.stringify(mockCsrfToken),
        });

        handleAuthResponse({ok: true, headers}, {localStorage, ...testCsrfOption});
        assert.deepEquals(accessRecord, {
            ...createEmptyMockLocalStorageAccessRecord(),
            setItem: [
                {
                    key: testCsrfHeaderName,
                    value: JSON.stringify(mockCsrfToken),
                },
            ],
        });

        assert.strictEquals(
            getCurrentCsrfToken({localStorage, ...testCsrfOption}).csrfToken?.token,
            mockCsrfToken.token,
        );
    });
    it('handles successful auth with default localStorage', () => {
        const mockCsrfToken = generateCsrfToken({days: 2});
        const headers = new Headers({
            [testCsrfHeaderName]: JSON.stringify(mockCsrfToken),
        });
        handleAuthResponse({ok: true, headers}, testCsrfOption);
        assert.strictEquals(
            getCurrentCsrfToken(testCsrfOption).csrfToken?.token,
            mockCsrfToken.token,
        );
    });
});

describe(generateLogoutHeaders.name, () => {
    it('generates headers', () => {
        assert.deepEquals(
            generateLogoutHeaders(
                {
                    hostOrigin: 'my-origin',
                    cookieName: 'my-name',
                    isDev: true,
                },
                testCsrfOption,
            ),
            {
                [testCsrfHeaderName]: 'redacted',
                'set-cookie':
                    'my-name=redacted; Domain=my-origin; HttpOnly; Path=/; SameSite=Strict; MAX-AGE=0',
            },
        );
    });
});
