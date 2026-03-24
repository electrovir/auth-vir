import {assert} from '@augment-vir/assert';
import {
    HttpStatus,
    randomString,
    type JsonCompatibleObject,
    type SelectFrom,
} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {type EmptyObject} from 'type-fest';
import {
    generateCsrfToken,
    getCurrentCsrfToken,
    resolveCsrfHeaderName,
    type CsrfHeaderNameOption,
} from '../csrf-token.js';
import {clearCsrfCookieInBrowser, simulateCsrfCookie} from '../csrf-token.mock.js';
import {type User} from '../generated/client.js';
import {AuthHeaderName, FrontendAuthClient, type FrontendAuthClientConfig} from '../index.js';

const testCsrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'test',
};
const testCsrfHeaderName = resolveCsrfHeaderName(testCsrfOption);

function createMockLocalStorage(init: Record<string, string> = {}) {
    const store: Record<string, string> = init;

    const mockLocalStorage: Pick<Storage, 'setItem' | 'removeItem' | 'getItem'> = {
        getItem(key) {
            return store[key] ?? null;
        },
        removeItem(key) {
            delete store[key];
        },
        setItem(key, value) {
            store[key] = value;
        },
    };

    return {
        localStorage: mockLocalStorage,
        store,
    };
}

describe(FrontendAuthClient.name, () => {
    function createMockFrontendAuthClient<
        AssumedUserParams extends JsonCompatibleObject = EmptyObject,
    >(
        canAssumeUser?: FrontendAuthClientConfig['canAssumeUser'],
        csrfHeaderNameOption: Readonly<CsrfHeaderNameOption> = testCsrfOption,
        overrides?: Partial<FrontendAuthClientConfig>,
    ) {
        clearCsrfCookieInBrowser();
        const mockLocalStorage = createMockLocalStorage();
        const callCounts = {
            authCleared: 0,
        };

        const frontendAuthClient = new FrontendAuthClient<AssumedUserParams>({
            csrf: csrfHeaderNameOption,
            authClearedCallback() {
                ++callCounts.authCleared;
            },
            canAssumeUser,
            overrides: {
                localStorage: mockLocalStorage.localStorage,
            },
            ...overrides,
        });

        return {
            frontendAuthClient,
            mockLocalStorage,
            callCounts,
        };
    }

    it('uses global localstorage', async () => {
        const mockCsrfHeaderName = `mock-csrf-${randomString()}`;
        const mockAssumedUserHeaderName = `mock-assumed-user-${randomString()}`;
        const mockUser = {
            id: 'mock-user',
        };
        const mockUser2 = {
            id: 'mock-user-2',
        };

        const frontendAuthClient = new FrontendAuthClient<{id: string}>({
            csrf: {
                csrfHeaderName: mockCsrfHeaderName,
            },
            canAssumeUser() {
                return true;
            },
            assumedUserHeaderName: mockAssumedUserHeaderName,
        });

        globalThis.localStorage.setItem(mockAssumedUserHeaderName, JSON.stringify(mockUser));

        assert.deepEquals(frontendAuthClient.getAssumedUser(), mockUser);
        assert.notDeepEquals(frontendAuthClient.getAssumedUser(), mockUser2);

        await frontendAuthClient.assumeUser(mockUser2);

        assert.deepEquals(frontendAuthClient.getAssumedUser(), mockUser2);
        assert.notDeepEquals(frontendAuthClient.getAssumedUser(), mockUser);
    });

    it('saves a CSRF token', async () => {
        const {frontendAuthClient} = createMockFrontendAuthClient();

        assert.deepEquals(
            frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {},
                credentials: 'include',
            },
            'Should not be authenticated yet.',
        );
        assert.isUndefined(getCurrentCsrfToken(), 'CSRF token should not be stored yet.');

        const csrfToken = generateCsrfToken();
        simulateCsrfCookie(csrfToken);

        const loginResponse: Readonly<
            SelectFrom<
                Response,
                {
                    ok: true;
                    status: true;
                }
            >
        > = {
            status: HttpStatus.Ok,
            ok: true,
        };

        await frontendAuthClient.handleLoginResponse(loginResponse);

        assert.deepEquals(
            frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {
                    [testCsrfHeaderName]: csrfToken,
                },
                credentials: 'include',
            },
            'Should be authenticated now.',
        );
        await frontendAuthClient.verifyResponseAuth({
            ...loginResponse,
            headers: new Headers(),
        });
        assert.strictEquals(getCurrentCsrfToken(), csrfToken, 'CSRF token should be stored now.');
    });

    it('rejects failed login response', async () => {
        const {frontendAuthClient, callCounts} = createMockFrontendAuthClient();

        await assert.throws(
            () =>
                frontendAuthClient.handleLoginResponse({
                    ok: false,
                }),
            {
                matchMessage: 'response failed',
            },
        );
        assert.strictEquals(callCounts.authCleared, 1);
    });

    it('stores and retrieves a CSRF token from cookie', () => {
        createMockFrontendAuthClient();

        const csrfToken = generateCsrfToken();
        simulateCsrfCookie(csrfToken);

        assert.strictEquals(getCurrentCsrfToken(), csrfToken);
    });

    it('is constructable with only csrf header name option', () => {
        assert.isDefined(
            new FrontendAuthClient({
                csrf: testCsrfOption,
            }),
        );
    });

    it('logs out on unauthorized response', async () => {
        const {frontendAuthClient} = createMockFrontendAuthClient();

        assert.isUndefined(getCurrentCsrfToken(), 'CSRF token should not be stored yet.');

        const csrfToken = generateCsrfToken();
        simulateCsrfCookie(csrfToken);

        await frontendAuthClient.handleLoginResponse({
            ok: true,
        });
        assert.strictEquals(getCurrentCsrfToken(), csrfToken, 'CSRF token should be stored now.');

        await frontendAuthClient.verifyResponseAuth({
            status: HttpStatus.Unauthorized,
            headers: new Headers(),
        });

        assert.strictEquals(
            getCurrentCsrfToken(),
            csrfToken,
            'CSRF token should still be stored after logout.',
        );
    });

    it('cannot assume a user', async () => {
        const {frontendAuthClient} = createMockFrontendAuthClient<{
            userId: User['id'];
        }>();
        const assumedMockUser = {
            userId: 'yo' as User['id'],
        };

        assert.isFalse(await frontendAuthClient.assumeUser(assumedMockUser));

        assert.deepEquals(
            frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {},
                credentials: 'include',
            },
            'Should not pass assumed user.',
        );
    });
    it('can assume a user', async () => {
        const {frontendAuthClient} = createMockFrontendAuthClient<{
            userId: User['id'];
        }>(() => true);
        const assumedMockUser = {
            userId: 'yo' as User['id'],
        };

        assert.isTrue(await frontendAuthClient.assumeUser(assumedMockUser));

        assert.deepEquals(
            frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {
                    [AuthHeaderName.AssumedUser]: JSON.stringify(assumedMockUser),
                },
                credentials: 'include',
            },
            'Should pass assumed user.',
        );

        assert.isDefined(frontendAuthClient.getAssumedUser());

        assert.isTrue(await frontendAuthClient.assumeUser(undefined));

        assert.isUndefined(frontendAuthClient.getAssumedUser());
    });
    it('fails on invalid assumed user', () => {
        const {frontendAuthClient, mockLocalStorage} = createMockFrontendAuthClient<{
            userId: User['id'];
        }>(() => true);
        const assumedMockUser = {
            userId: 'yo' as User['id'],
        };

        mockLocalStorage.store[AuthHeaderName.AssumedUser] = JSON.stringify(assumedMockUser);

        assert.deepEquals(
            frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {
                    [AuthHeaderName.AssumedUser]: JSON.stringify(assumedMockUser),
                },
                credentials: 'include',
            },
            'Should pass assumed user.',
        );

        mockLocalStorage.store[AuthHeaderName.AssumedUser] = 'INVALID }{';

        assert.deepEquals(
            frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {},
                credentials: 'include',
            },
            'Should not pass invalid assumed user.',
        );
    });
    it('uses an assumed user with custom header', async () => {
        const mockHeaderName = 'mock-assumed-user';

        const {frontendAuthClient} = createMockFrontendAuthClient<{
            userId: User['id'];
        }>(() => true, testCsrfOption, {
            assumedUserHeaderName: mockHeaderName,
        });
        const assumedMockUser = {
            userId: 'yo' as User['id'],
        };

        assert.isTrue(await frontendAuthClient.assumeUser(assumedMockUser));

        assert.deepEquals(
            frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {
                    [mockHeaderName]: JSON.stringify(assumedMockUser),
                },
                credentials: 'include',
            },
            'Should pass assumed user.',
        );
    });
    it('returns any stored CSRF token string as-is', () => {
        const {callCounts} = createMockFrontendAuthClient<{
            userId: User['id'];
        }>();

        simulateCsrfCookie('any-raw-token-string');

        assert.strictEquals(getCurrentCsrfToken(), 'any-raw-token-string');
        assert.strictEquals(callCounts.authCleared, 0);
    });

    it('reads from suffixed CSRF cookie when cookieNameSuffix is configured', () => {
        const testSuffix = 'staging';
        const {frontendAuthClient} = createMockFrontendAuthClient(undefined, testCsrfOption, {
            cookieNameSuffix: testSuffix,
        });

        const csrfToken = generateCsrfToken();
        simulateCsrfCookie(csrfToken, testSuffix);

        assert.deepEquals(frontendAuthClient.createAuthenticatedRequestInit(), {
            headers: {
                [testCsrfHeaderName]: csrfToken,
            },
            credentials: 'include',
        });
    });
});
