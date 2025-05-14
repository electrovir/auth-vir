import {assert} from '@augment-vir/assert';
import {omitObjectKeys} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {
    extractUserIdFromRequestHeaders,
    generateLogoutHeaders,
    generateSuccessfulLoginHeaders,
    getCurrentCsrfToken,
    handleAuthResponse,
    wipeCurrentCsrfToken,
} from './auth.js';
import {csrfTokenHeaderName} from './csrf-token.js';
import {generateNewJwtKeys, parseJwtKeys} from './jwt-keys.js';
import {mockJwtParams} from './jwt.mock.js';
import {
    createEmptyMockLocalStorageAccessRecord,
    createMockLocalStorage,
} from './mock-local-storage.js';

describe(getCurrentCsrfToken.name, () => {
    it('can override the localstorage key', () => {
        const mockKey = 'mock-key';
        const mockCsrfToken = 'token here';

        const {localStorage} = createMockLocalStorage();
        localStorage.setItem(mockKey, mockCsrfToken);

        assert.strictEquals(
            getCurrentCsrfToken({localStorage, csrfHeaderName: mockKey}),
            mockCsrfToken,
        );
        wipeCurrentCsrfToken({localStorage, csrfHeaderName: mockKey});
        assert.isUndefined(getCurrentCsrfToken({localStorage, csrfHeaderName: mockKey}));
    });
});

describe(extractUserIdFromRequestHeaders.name, () => {
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
            [csrfTokenHeaderName]: serverHeaders['csrf-token'],
        };

        return {
            headers: clientHeaders,
            jwtParams: {
                ...mockJwtParams,
                jwtKeys,
            },
        };
    }

    it('works on valid auth', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.strictEquals(await extractUserIdFromRequestHeaders(headers, jwtParams), mockUserId);
    });
    it('works on valid auth with an array header', async () => {
        const {headers, jwtParams} = await setupHeaders();

        assert.strictEquals(
            await extractUserIdFromRequestHeaders(
                {
                    cookie: headers.cookie,
                    [csrfTokenHeaderName]: [headers[csrfTokenHeaderName]],
                },
                jwtParams,
            ),
            mockUserId,
        );
    });
    it('works on valid auth with Headers object', async () => {
        const {headers, jwtParams} = await setupHeaders();

        const headersObject = new Headers(headers);

        assert.strictEquals(
            await extractUserIdFromRequestHeaders(headersObject, jwtParams),
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
                omitObjectKeys(headers, [csrfTokenHeaderName]),
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
                    [csrfTokenHeaderName]: 'invalid token',
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
                csrfTokenHeaderName,
                csrfTokenHeaderName,
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
        const mockCsrfToken = 'token here';

        const {accessRecord, localStorage} = createMockLocalStorage();

        const headers = new Headers({
            [csrfTokenHeaderName]: mockCsrfToken,
        });

        handleAuthResponse({ok: true, headers}, {localStorage});
        assert.deepEquals(accessRecord, {
            ...createEmptyMockLocalStorageAccessRecord(),
            setItem: [
                {key: csrfTokenHeaderName, value: mockCsrfToken},
            ],
        });

        assert.strictEquals(getCurrentCsrfToken({localStorage}), mockCsrfToken);
    });
    it('handles successful auth with default localStorage', () => {
        const mockCsrfToken = 'token here';
        const headers = new Headers({
            [csrfTokenHeaderName]: mockCsrfToken,
        });
        handleAuthResponse({ok: true, headers});
        assert.strictEquals(getCurrentCsrfToken(), mockCsrfToken);
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
