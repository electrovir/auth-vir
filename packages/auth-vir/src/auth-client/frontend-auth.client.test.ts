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
    resolveCsrfHeaderName,
    type CsrfHeaderNameOption,
} from '../csrf-token.js';
import {type User} from '../generated/client.js';
import {
    AuthHeaderName,
    createMockCsrfTokenStore,
    createMockLocalStorage,
    FrontendAuthClient,
    type FrontendAuthClientConfig,
} from '../index.js';

const testCsrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'test',
};
const testCsrfHeaderName = resolveCsrfHeaderName(testCsrfOption);

describe(FrontendAuthClient.name, () => {
    function createMockFrontendAuthClient<
        AssumedUserParams extends JsonCompatibleObject = EmptyObject,
    >(
        canAssumeUser?: FrontendAuthClientConfig['canAssumeUser'],
        csrfHeaderNameOption: Readonly<CsrfHeaderNameOption> = testCsrfOption,
        overrides?: Partial<FrontendAuthClientConfig>,
    ) {
        const mockLocalStorage = createMockLocalStorage();
        const mockStore = createMockCsrfTokenStore();
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
                csrfTokenStore: mockStore.csrfTokenStore,
            },
            ...overrides,
        });

        return {
            frontendAuthClient,
            mockLocalStorage,
            mockStore,
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
        const {frontendAuthClient, mockStore} = createMockFrontendAuthClient();

        assert.deepEquals(
            await frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {},
                credentials: 'include',
            },
            'Should not be authenticated yet.',
        );
        assert.isUndefined(mockStore.storedValue as any, 'CSRF token should not be stored yet.');

        const csrfToken = generateCsrfToken();

        const loginResponse: Readonly<
            SelectFrom<
                Response,
                {
                    ok: true;
                    headers: true;
                    status: true;
                }
            >
        > = {
            status: HttpStatus.Ok,
            ok: true,
            headers: new Headers({
                [testCsrfHeaderName]: csrfToken,
            }),
        };

        await frontendAuthClient.handleLoginResponse(loginResponse);

        assert.deepEquals(
            await frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {
                    [testCsrfHeaderName]: csrfToken,
                },
                credentials: 'include',
            },
            'Should be authenticated now.',
        );
        await frontendAuthClient.verifyResponseAuth(loginResponse);
        assert.strictEquals(mockStore.storedValue, csrfToken, 'CSRF token should be stored now.');
    });

    it('rejects failed login response', async () => {
        const {frontendAuthClient, callCounts} = createMockFrontendAuthClient();

        await assert.throws(
            () =>
                frontendAuthClient.handleLoginResponse({
                    ok: false,
                    headers: new Headers(),
                }),
            {
                matchMessage: 'response failed',
            },
        );
        assert.strictEquals(callCounts.authCleared, 1);
    });

    it('rejects login missing CSRF', async () => {
        const {frontendAuthClient, callCounts} = createMockFrontendAuthClient();

        await assert.throws(
            () =>
                frontendAuthClient.handleLoginResponse({
                    ok: true,
                    headers: new Headers(),
                }),
            {
                matchMessage: 'Did not receive any CSRF token',
            },
        );
        assert.strictEquals(callCounts.authCleared, 1);
    });

    it('stores and retrieves a CSRF token from header', async () => {
        const {frontendAuthClient} = createMockFrontendAuthClient();

        const csrfToken = generateCsrfToken();

        await frontendAuthClient.handleLoginResponse({
            ok: true,
            headers: new Headers({
                [testCsrfHeaderName]: csrfToken,
            }),
        });

        assert.strictEquals(await frontendAuthClient.getCurrentCsrfToken(), csrfToken);
    });

    it('is constructable with only csrf header name option', () => {
        assert.isDefined(
            new FrontendAuthClient({
                csrf: testCsrfOption,
            }),
        );
    });

    it('logs out on unauthorized response', async () => {
        const {frontendAuthClient, mockStore} = createMockFrontendAuthClient();

        assert.isUndefined(mockStore.storedValue as any, 'CSRF token should not be stored yet.');

        const csrfToken = generateCsrfToken();

        await frontendAuthClient.handleLoginResponse({
            ok: true,
            headers: new Headers({
                [testCsrfHeaderName]: csrfToken,
            }),
        });
        assert.strictEquals(mockStore.storedValue, csrfToken, 'CSRF token should be stored now.');

        await frontendAuthClient.verifyResponseAuth({
            status: HttpStatus.Unauthorized,
            headers: new Headers(),
        });

        assert.strictEquals(
            mockStore.storedValue,
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
            await frontendAuthClient.createAuthenticatedRequestInit(),
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
            await frontendAuthClient.createAuthenticatedRequestInit(),
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
    it('fails on invalid assumed user', async () => {
        const {frontendAuthClient, mockLocalStorage} = createMockFrontendAuthClient<{
            userId: User['id'];
        }>(() => true);
        const assumedMockUser = {
            userId: 'yo' as User['id'],
        };

        mockLocalStorage.store[AuthHeaderName.AssumedUser] = JSON.stringify(assumedMockUser);

        assert.deepEquals(
            await frontendAuthClient.createAuthenticatedRequestInit(),
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
            await frontendAuthClient.createAuthenticatedRequestInit(),
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
            await frontendAuthClient.createAuthenticatedRequestInit(),
            {
                headers: {
                    [mockHeaderName]: JSON.stringify(assumedMockUser),
                },
                credentials: 'include',
            },
            'Should pass assumed user.',
        );
    });
    it('returns any stored CSRF token string as-is', async () => {
        const {frontendAuthClient, callCounts, mockStore} = createMockFrontendAuthClient<{
            userId: User['id'];
        }>();

        await mockStore.csrfTokenStore.setCsrfToken('any-raw-token-string');

        assert.strictEquals(await frontendAuthClient.getCurrentCsrfToken(), 'any-raw-token-string');

        assert.strictEquals(callCounts.authCleared, 0);
        assert.strictEquals(mockStore.storedValue, 'any-raw-token-string');
    });
});
