import {assert, check} from '@augment-vir/assert';
import {
    type AnyObject,
    ensureArray,
    filterMap,
    selectFrom,
    type SelectFrom,
    wait,
} from '@augment-vir/common';
import {describe, it, type UniversalTestContext} from '@augment-vir/test';
import {type IncomingHttpHeaders} from 'node:http';
import {
    createPrismaClient,
    type PrismaAddModelData,
    prismaApi,
    PrismaDatabaseEngine,
} from 'prisma-vir';
import {type EmptyObject} from 'type-fest';
import {testPrismaSchemaFilePath} from '../file-paths.mock.js';
import {type Prisma, PrismaClient, type User} from '../generated/client.js';
import {type UserId} from '../generated/models.js';
import {AuthHeaderName} from '../headers.js';
import {generateNewJwtKeys} from '../jwt/jwt-keys.js';
import {BackendAuthClient, type BackendAuthClientConfig} from './backend-auth.client.js';

function setCookieHeaderToRegularCookieHeader(setCookies: string[] | string): string {
    /** Only keep the first "key=value", the cookie value. */
    return filterMap(
        ensureArray(setCookies),
        (cookie) => cookie.split(';')[0]?.trim(),
        check.isTruthy,
    ).join('; ');
}

const defaultMockSeedData: PrismaAddModelData<PrismaClient, Prisma.TypeMap> = {
    User: [
        {
            name: 'fake user 1',
        },
    ],
};

async function setupBackendAuthClientTest<AssumedUserParams extends AnyObject = EmptyObject>({
    testContext,
    seedDataOverride,
    authClientConfigOverrides = {},
}: {
    testContext: UniversalTestContext;
    seedDataOverride?: PrismaAddModelData<PrismaClient, Prisma.TypeMap> | undefined;
    authClientConfigOverrides?: Partial<
        BackendAuthClientConfig<SelectFrom<User, {id: true; name: true}>, UserId, AssumedUserParams>
    >;
}) {
    const {prismaClient} = await createPrismaClient(PrismaDatabaseEngine.Postgres, PrismaClient, {
        schemaPath: testPrismaSchemaFilePath,
        connection: {
            dev: {
                resetDatabase: true,
                test: testContext,
            },
        },
    });

    await prismaApi.client.addData({data: seedDataOverride || defaultMockSeedData, prismaClient});

    const mockUser =
        (await prismaClient.user.findFirst({
            select: {
                id: true,
                name: true,
            },
        })) || undefined;

    const jwtKeys = await generateNewJwtKeys();

    const backendAuthClient = new BackendAuthClient<
        SelectFrom<User, {id: true; name: true}>,
        UserId,
        AssumedUserParams,
        AuthHeaderName.CsrfToken
    >({
        getJwtKeys() {
            return jwtKeys;
        },
        async getUserFromDatabase({userId}) {
            return await prismaClient.user.findFirst({
                where: {
                    id: userId,
                },
                select: {
                    id: true,
                    name: true,
                },
            });
        },
        serviceOrigin: 'localhost',
        isDev: true,
        ...authClientConfigOverrides,
    });

    return {
        prismaClient,
        backendAuthClient,
        mockUser,
    };
}

describe(BackendAuthClient.name, () => {
    it('gets a secure user', async (testContext) => {
        const {backendAuthClient, mockUser} = await setupBackendAuthClientTest({testContext});

        assert.isDefined(mockUser, 'Failed to find mock user.');

        const cookieHeaders = await backendAuthClient.createLoginHeaders({
            isSignUpCookie: false,
            requestHeaders: {},
            userId: mockUser.id,
        });

        const requestHeaders: IncomingHttpHeaders = {
            [AuthHeaderName.CsrfToken]: cookieHeaders[AuthHeaderName.CsrfToken],
            cookie: setCookieHeaderToRegularCookieHeader(cookieHeaders['set-cookie']),
        };

        const userResult = await backendAuthClient.getSecureUser({
            requestHeaders,
        });
        assert.isDefined(userResult, 'No user result');

        assert.isEmpty(userResult.responseHeaders, 'cookie refresh headers should not be set');
        assert.deepEquals(userResult.user, mockUser);
        assert.tsType(userResult.user).equals<{
            id: UserId;
            name: string;
        }>();
    });
    it('gets an insecure user', async (testContext) => {
        const {backendAuthClient, mockUser} = await setupBackendAuthClientTest({testContext});

        assert.isDefined(mockUser, 'Failed to find mock user.');

        const cookieHeaders = await backendAuthClient.createLoginHeaders({
            isSignUpCookie: false,
            requestHeaders: {},
            userId: mockUser.id,
        });

        /** Intentionally without the CSRF token header. */
        const requestHeaders: IncomingHttpHeaders = {
            cookie: setCookieHeaderToRegularCookieHeader(cookieHeaders['set-cookie']),
        };

        const secureUserResult = await backendAuthClient.getSecureUser({
            requestHeaders,
        });
        assert.isUndefined(secureUserResult, 'Without a CSRF token, the secure user should fail.');

        // eslint-disable-next-line @typescript-eslint/no-deprecated
        const insecureUserResult = await backendAuthClient.getInsecureUser({
            requestHeaders,
        });
        assert.isDefined(insecureUserResult, 'No insecure user result.');

        assert.deepEquals(insecureUserResult.user, mockUser);
    });
    it('fails after session timeout', async (testContext) => {
        const {backendAuthClient, mockUser} = await setupBackendAuthClientTest({
            testContext,
            authClientConfigOverrides: {
                userSessionIdleTimeout: {
                    seconds: 5,
                },
            },
        });

        assert.isDefined(mockUser, 'Failed to find mock user.');

        const cookieHeaders = await backendAuthClient.createLoginHeaders({
            isSignUpCookie: false,
            requestHeaders: {},
            userId: mockUser.id,
        });

        const requestHeaders: IncomingHttpHeaders = {
            ...selectFrom(cookieHeaders, {
                [AuthHeaderName.CsrfToken]: true,
            }),
            cookie: setCookieHeaderToRegularCookieHeader(cookieHeaders['set-cookie']),
        };

        const userResult = await backendAuthClient.getSecureUser({
            requestHeaders,
        });
        assert.isDefined(userResult, 'No user result');

        assert.deepEquals(userResult.user, mockUser);
        assert.isNotEmpty(userResult.responseHeaders, 'cookie refresh headers should be set');

        await wait({seconds: 8});

        assert.isUndefined(
            await backendAuthClient.getSecureUser({
                requestHeaders,
            }),
            'User session should have timed out.',
        );
    });
});
