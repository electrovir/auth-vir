/* eslint-disable @typescript-eslint/no-deprecated */

import {assert} from '@augment-vir/assert';
import {omitObjectKeys} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {
    extractUserIdFromRequestHeaders,
    generateLogoutHeaders,
    generateSuccessfulLoginHeaders,
    handleAuthResponse,
    insecureExtractUserIdFromCookieAlone,
} from './auth.js';
import {generateCsrfToken, getCurrentCsrfToken} from './csrf-token.js';
import {AuthHeaderName} from './headers.js';
import {generateNewJwtKeys, parseJwtKeys} from './jwt/jwt-keys.js';
import {mockJwtParams} from './jwt/jwt.mock.js';
import {
    createEmptyMockLocalStorageAccessRecord,
    createMockLocalStorage,
} from './mock-local-storage.js';

const mockUserId = 'mock-id';
async function setupHeaders() {
    const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

    const serverHeaders = await generateSuccessfulLoginHeaders(mockUserId, {
        cookieDuration: {days: 20},
        hostOrigin: 'https://www.example.com',
        jwtParams: {
            ...mockJwtParams,
            jwtKeys,
        },
    });

    const clientHeaders = {
        cookie: serverHeaders['set-cookie'],
        [AuthHeaderName.CsrfToken]: serverHeaders[AuthHeaderName.CsrfToken],
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
            (await extractUserIdFromRequestHeaders(headers, jwtParams))?.userId,
            mockUserId,
        );
    });
    it('works on valid auth with an array header', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.strictEquals(
            (
                await extractUserIdFromRequestHeaders(
                    {
                        cookie: headers.cookie,
                        [AuthHeaderName.CsrfToken]: [headers[AuthHeaderName.CsrfToken]],
                    },
                    jwtParams,
                )
            )?.userId,
            mockUserId,
        );
    });
    it('works on valid auth with Headers object', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const headersObject = new Headers(headers);

        assert.strictEquals(
            (await extractUserIdFromRequestHeaders(headersObject, jwtParams))?.userId,
            mockUserId,
        );
    });
    it('rejects missing cookie', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(omitObjectKeys(headers, ['cookie']), jwtParams),
        );
    });
    it('rejects missing cookie with headers object', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                new Headers(omitObjectKeys(headers, ['cookie'])),
                jwtParams,
            ),
        );
    });
    it('rejects missing CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                omitObjectKeys(headers, [AuthHeaderName.CsrfToken]),
                jwtParams,
            ),
        );
    });
    it('rejects mismatched CSRF token', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.isUndefined(
            await extractUserIdFromRequestHeaders(
                {
                    ...headers,
                    [AuthHeaderName.CsrfToken]: 'invalid token',
                },
                jwtParams,
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
                    omitObjectKeys(headers, [AuthHeaderName.CsrfToken]),
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
        handleAuthResponse({ok: false, headers}, {localStorage});
        // fails because CSRF header is missing
        assert.throws(() => handleAuthResponse({ok: true, headers}, {localStorage}));
        assert.deepEquals(accessRecord, {
            ...createEmptyMockLocalStorageAccessRecord(),
            removeItem: [
                AuthHeaderName.CsrfToken,
                AuthHeaderName.CsrfToken,
            ],
        });
    });
    it('handles failed auth with default localStorage', () => {
        const headers = new Headers();

        // fails because `ok` is false
        handleAuthResponse({ok: false, headers});
        // fails because CSRF header is missing
        assert.throws(() => handleAuthResponse({ok: true, headers}));
    });
    it('handles successful auth with mock localStorage', () => {
        const mockCsrfToken = generateCsrfToken({days: 2});

        const {accessRecord, localStorage} = createMockLocalStorage();

        const headers = new Headers({
            [AuthHeaderName.CsrfToken]: JSON.stringify(mockCsrfToken),
        });

        handleAuthResponse({ok: true, headers}, {localStorage});
        assert.deepEquals(accessRecord, {
            ...createEmptyMockLocalStorageAccessRecord(),
            setItem: [
                {
                    key: AuthHeaderName.CsrfToken,
                    value: JSON.stringify(mockCsrfToken),
                },
            ],
        });

        assert.strictEquals(
            getCurrentCsrfToken({localStorage}).csrfToken?.token,
            mockCsrfToken.token,
        );
    });
    it('handles successful auth with default localStorage', () => {
        const mockCsrfToken = generateCsrfToken({days: 2});
        const headers = new Headers({
            [AuthHeaderName.CsrfToken]: JSON.stringify(mockCsrfToken),
        });
        handleAuthResponse({ok: true, headers});
        assert.strictEquals(getCurrentCsrfToken().csrfToken?.token, mockCsrfToken.token);
    });
});

describe(generateLogoutHeaders.name, () => {
    it('generates headers', () => {
        assert.deepEquals(
            generateLogoutHeaders({
                hostOrigin: 'my-origin',
                cookieName: 'my-name',
                isDev: true,
            }),
            {
                'csrf-token': 'redacted',
                'set-cookie':
                    'my-name=redacted; Domain=my-origin; HttpOnly; Path=/; SameSite=Strict; MAX-AGE=0',
            },
        );
    });
});
