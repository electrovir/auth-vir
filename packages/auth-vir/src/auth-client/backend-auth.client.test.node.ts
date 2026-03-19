import {assert, assertWrap, check} from '@augment-vir/assert';
import {type AnyObject, ensureArray, filterMap, type SelectFrom, wait} from '@augment-vir/common';
import {describe, it, type UniversalTestContext} from '@augment-vir/test';
import {type IncomingHttpHeaders, type OutgoingHttpHeaders} from 'node:http';
import {
    createPrismaClient,
    type PrismaAddModelData,
    prismaApi,
    PrismaDatabaseEngine,
} from 'prisma-vir';
import {type EmptyObject} from 'type-fest';
import {AuthCookie} from '../cookie.js';
import {type CsrfHeaderNameOption, resolveCsrfHeaderName} from '../csrf-token.js';
import {testPrismaMigrationsDirPath, testPrismaSchemaFilePath} from '../file-paths.mock.js';
import {type Prisma, PrismaClient, type User} from '../generated/client.js';
import {type UserId} from '../generated/models.js';
import {generateNewJwtKeys} from '../jwt/jwt-keys.js';
import {BackendAuthClient, type BackendAuthClientConfig} from './backend-auth.client.js';

const testCsrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'test',
};
const testCsrfHeaderName = resolveCsrfHeaderName(testCsrfOption);

function setCookieHeaderToRegularCookieHeader(headers: Readonly<OutgoingHttpHeaders>): string {
    const setCookies = headers['set-cookie'] || [];

    /** Only keep the first "key=value", the cookie value. */
    return filterMap(
        ensureArray(setCookies),
        (cookie) => cookie.split(';')[0]?.trim(),
        check.isTruthy,
    ).join('; ');
}

/**
 * In production, the browser reads the CSRF cookie from `document.cookie`. In Node.js tests there
 * is no browser, so we parse it out of the Set-Cookie headers manually.
 */
function extractCsrfTokenFromSetCookies(headers: Readonly<OutgoingHttpHeaders>): string {
    const setCookies = ensureArray(headers['set-cookie'] || []);
    const csrfCookie = assertWrap.isTruthy(
        setCookies.find((cookie) => cookie.startsWith(AuthCookie.Csrf)),
        'Missing CSRF Set-Cookie.',
    );
    return assertWrap.isTruthy(csrfCookie.split(';')[0]?.split('=')[1]);
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
        migrationsDirPath: testPrismaMigrationsDirPath,
        schemaPath: testPrismaSchemaFilePath,
        connection: {
            dev: {
                resetDatabase: true,
                test: testContext,
            },
        },
    });

    await prismaApi.client.addData({
        data: seedDataOverride || defaultMockSeedData,
        prismaClient,
    });

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
        AssumedUserParams
    >({
        csrf: testCsrfOption,
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
        const {backendAuthClient, mockUser} = await setupBackendAuthClientTest({
            testContext,
        });

        assert.isDefined(mockUser, 'Failed to find mock user.');

        const cookieHeaders = await backendAuthClient.createLoginHeaders({
            isSignUpCookie: false,
            requestHeaders: {},
            userId: mockUser.id,
        });

        const requestHeaders: IncomingHttpHeaders = {
            [testCsrfHeaderName]: extractCsrfTokenFromSetCookies(cookieHeaders),
            cookie: setCookieHeaderToRegularCookieHeader(cookieHeaders),
        };

        const userResult = await backendAuthClient.getSecureUser({
            requestHeaders,
            isSignUpCookie: false,
            allowUserAuthRefresh: true,
        });
        assert.isDefined(userResult, 'No user result');

        const setCookies = ensureArray(userResult.responseHeaders['set-cookie'] || []);
        assert.isLengthExactly(setCookies, 1, 'should only have the CSRF cookie, no auth refresh');
        assert.isTrue(
            assertWrap.isDefined(setCookies[0]).startsWith(`${AuthCookie.Csrf}=`),
            'the only set-cookie should be the CSRF cookie',
        );
        assert.deepEquals(userResult.user, mockUser);
        assert.tsType(userResult.user).equals<{
            id: UserId;
            name: string;
        }>();
    });
    it('gets an insecure user', async (testContext) => {
        const {backendAuthClient, mockUser} = await setupBackendAuthClientTest({
            testContext,
        });

        assert.isDefined(mockUser, 'Failed to find mock user.');

        const cookieHeaders = await backendAuthClient.createLoginHeaders({
            isSignUpCookie: false,
            requestHeaders: {},
            userId: mockUser.id,
        });

        /** Intentionally without the CSRF token header. */
        const requestHeaders: IncomingHttpHeaders = {
            cookie: setCookieHeaderToRegularCookieHeader(cookieHeaders),
        };

        const secureUserResult = await backendAuthClient.getSecureUser({
            requestHeaders,
            isSignUpCookie: false,
            allowUserAuthRefresh: true,
        });
        assert.isUndefined(secureUserResult, 'Without a CSRF token, the secure user should fail.');

        // eslint-disable-next-line @typescript-eslint/no-deprecated
        const insecureUserResult = await backendAuthClient.getInsecureUser({
            requestHeaders,
            allowUserAuthRefresh: true,
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
                sessionRefreshStartTime: {
                    seconds: 0,
                },
                allowedClockSkew: {
                    seconds: 0,
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
            [testCsrfHeaderName]: extractCsrfTokenFromSetCookies(cookieHeaders),
            cookie: setCookieHeaderToRegularCookieHeader(cookieHeaders),
        };

        const userResult = await backendAuthClient.getSecureUser({
            requestHeaders,
            isSignUpCookie: false,
            allowUserAuthRefresh: true,
        });
        assert.isDefined(userResult, 'No user result');

        assert.deepEquals(userResult.user, mockUser);
        assert.isNotEmpty(userResult.responseHeaders, 'cookie refresh headers should be set');

        await wait({
            seconds: 8,
        });

        assert.isUndefined(
            await backendAuthClient.getSecureUser({
                requestHeaders,
                isSignUpCookie: false,
                allowUserAuthRefresh: true,
            }),
            'User session should have timed out.',
        );
    });
});
