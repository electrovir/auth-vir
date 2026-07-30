/* eslint-disable @typescript-eslint/no-deprecated */
import {check} from '@augment-vir/assert';
import {log, randomString} from '@augment-vir/common';
import {HttpMethod, HttpStatus} from '@rest-vir/api';
import {createApiImplementor, implementApi, startApiServer} from '@rest-vir/host';
import {
    AuthCookie,
    doesPasswordMatchHash,
    extractUserIdFromRequestHeaders,
    generateLogoutHeaders,
    generateNewJwtKeys,
    generateSuccessfulLoginHeaders,
    hashPassword,
    parseJwtKeys,
    resolveCsrfHeaderName,
    type CreateJwtParams,
    type CsrfHeaderNameOption,
} from 'auth-vir';
import {
    demoApi,
    demoApiStartOrigin,
    loginEndpoint,
    logoutEndpoint,
    signUpEndpoint,
    userEndpoint,
} from './demo-api.js';

const demoCsrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'demo',
};
const demoCsrfHeaderName = resolveCsrfHeaderName(demoCsrfOption);

type MockUser = {
    id: string;
    name: string;
    username: string;
    email: string;
    hashedPassword: string;
};

const mockDatabase = {
    users: [] as MockUser[],
};

const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());
const jwtParams: Readonly<Omit<CreateJwtParams, 'jwtKeys'>> = {
    audience: 'demo-context',
    jwtDuration: {
        days: 1,
    },
    issuer: 'demo-login',
};

const endpointAuthConfig = {
    /** These endpoints require an authenticated user to be making the request. */
    requiresAuth: [
        userEndpoint.path,
        logoutEndpoint.path,
    ],
    /** These endpoints require a _not_ authenticated user to be making the request. */
    requiresUnauth: [
        loginEndpoint.path,
        signUpEndpoint.path,
    ],
} as const satisfies Record<string, string[]>;

type DemoContext = {
    authenticatedUser: MockUser | undefined;
};

const {implementEndpoint} = createApiImplementor<DemoContext>()(demoApi);

const loginImplementation = implementEndpoint(loginEndpoint, {
    async [HttpMethod.Post]({context, requestData, server}) {
        log.faint('\n=== /login endpoint ===');
        log.faint('Username:', requestData.username);
        log.faint('Already authenticated:', !!context.authenticatedUser);

        if (context.authenticatedUser) {
            log.faint('LOGIN REJECTED: Already authenticated');
            return {
                [HttpStatus.BadRequest]: {},
            };
        }

        const userMatch = mockDatabase.users.find((user) => user.username === requestData.username);

        log.faint('User found in DB:', !!userMatch);
        log.faint(
            'All users in DB:',
            mockDatabase.users.map((user) => user.username),
        );

        if (!userMatch) {
            log.faint('LOGIN REJECTED: No user found with username:', requestData.username);
            return {
                [HttpStatus.Unauthorized]: {},
            };
        }

        const passwordMatches = await doesPasswordMatchHash({
            hash: userMatch.hashedPassword,
            password: requestData.password,
        });

        log.faint('Password matches:', passwordMatches);

        if (!passwordMatches) {
            log.faint('LOGIN REJECTED: Password does not match');
            return {
                [HttpStatus.Unauthorized]: {},
            };
        }

        const loginHeaders = await generateSuccessfulLoginHeaders(userMatch.id, {
            cookieDuration: {
                hours: 2,
            },
            hostOrigin: server.serviceOrigin,
            jwtParams: {
                ...jwtParams,
                jwtKeys,
            },
            isDev: true,
        });

        log.faint('Login response headers generated');

        return {
            [HttpStatus.Ok]: {
                responseData: {
                    email: userMatch.email,
                    name: userMatch.name,
                    username: userMatch.username,
                },
                headers: loginHeaders,
            },
        };
    },
});

const signUpImplementation = implementEndpoint(signUpEndpoint, {
    async [HttpMethod.Post]({context, requestData, server}) {
        log.faint('\n=== /sign-up endpoint ===');
        log.faint('Username:', requestData.username);

        if (context.authenticatedUser) {
            log.faint('SIGN-UP REJECTED: Already authenticated');
            return {
                [HttpStatus.BadRequest]: {
                    responseData: 'Already authenticated',
                },
            };
        }

        const hashedPassword = await hashPassword(requestData.password);

        if (!hashedPassword) {
            return {
                [HttpStatus.BadRequest]: {
                    responseData: 'Password too long',
                },
            };
        }

        const newUser: MockUser = {
            id: randomString(),
            email: 'fake@example.com',
            hashedPassword,
            name: 'Demo User',
            username: requestData.username,
        };

        mockDatabase.users.push(newUser);
        log.faint('New user created:', newUser.id, newUser.username);
        log.faint('Total users in DB:', mockDatabase.users.length);

        const signUpHeaders = await generateSuccessfulLoginHeaders(newUser.id, {
            cookieDuration: {
                hours: 2,
            },
            hostOrigin: server.serviceOrigin,
            jwtParams: {
                ...jwtParams,
                jwtKeys,
            },
            isDev: true,
        });

        log.faint('Sign-up response headers generated');

        return {
            [HttpStatus.Ok]: {
                responseData: {
                    email: newUser.email,
                    name: newUser.name,
                    username: newUser.username,
                },
                headers: signUpHeaders,
            },
        };
    },
});

const userImplementation = implementEndpoint(userEndpoint, {
    [HttpMethod.Get]({context}) {
        log.faint('\n=== /user endpoint ===');
        log.faint(
            'Authenticated user from context:',
            context.authenticatedUser?.username || 'none',
        );

        const userMatch = mockDatabase.users.find(
            (user) => user.username === context.authenticatedUser?.username,
        );

        log.faint('User found in DB:', !!userMatch);

        if (!context.authenticatedUser || !userMatch) {
            log.faint('/user REJECTED: No authenticated user or user not in DB');
            return {
                [HttpStatus.Unauthorized]: {},
            };
        }

        log.faint('/user SUCCESS: Returning user data for', userMatch.username);

        return {
            [HttpStatus.Ok]: {
                responseData: {
                    email: userMatch.email,
                    name: userMatch.name,
                    username: userMatch.username,
                },
            },
        };
    },
});

const logoutImplementation = implementEndpoint(logoutEndpoint, {
    [HttpMethod.Post]({server}) {
        log.faint('\n=== /logout endpoint ===');

        return {
            [HttpStatus.Ok]: {
                headers: generateLogoutHeaders({
                    hostOrigin: server.serviceOrigin,
                    isDev: true,
                }),
            },
        };
    },
});

const demoApiImplementation = implementApi<DemoContext>()(demoApi, {
    customHeaders: [
        demoCsrfHeaderName,
    ],
    clientOriginRequirement(origin) {
        return !!origin?.includes('localhost');
    },
    async createHostContext({requestHeaders, endpointDefinition}) {
        log.faint(`\n--- createHostContext for ${endpointDefinition?.path || 'unknown'} ---`);
        log.faint('Request headers:', JSON.stringify(requestHeaders, null, 2));

        if (!endpointDefinition) {
            log.faint('No endpoint definition found, returning 404');
            return {
                reject: {
                    statusCode: HttpStatus.NotFound,
                },
            };
        }

        /**
         * This is not safe because it has not been checked yet that this user id is actually in the
         * database.
         *
         * @deprecated Unsafe
         */
        const _unsafe_authenticatedUserResult = await extractUserIdFromRequestHeaders({
            headers: requestHeaders,
            jwtParams: {
                ...jwtParams,
                jwtKeys,
            },
            csrfHeaderNameOption: demoCsrfOption,
            cookieName: AuthCookie.Auth,
        });

        log.faint(
            'extractUserIdFromRequestHeaders result:',
            _unsafe_authenticatedUserResult
                ? JSON.stringify(
                      {
                          userId: _unsafe_authenticatedUserResult.userId,
                          csrfToken: _unsafe_authenticatedUserResult.csrfToken.slice(0, 20) + '...',
                      },
                      null,
                      2,
                  )
                : 'undefined (no valid auth found)',
        );

        log.faint('Cookie header present:', !!requestHeaders['cookie']);
        log.faint('CSRF header name:', demoCsrfHeaderName);
        log.faint('CSRF header present:', !!requestHeaders[demoCsrfHeaderName]);
        log.faint(
            'Users in mock database:',
            mockDatabase.users.map((user) => user.id),
        );

        const authenticatedUser = _unsafe_authenticatedUserResult
            ? mockDatabase.users.find((user) => user.id === _unsafe_authenticatedUserResult.userId)
            : undefined;

        log.faint(
            'Authenticated user found in DB:',
            authenticatedUser ? authenticatedUser.username : 'none',
        );

        if (
            authenticatedUser &&
            check.hasValue(endpointAuthConfig.requiresUnauth, endpointDefinition.path)
        ) {
            log.faint('REJECTING: User is authenticated but endpoint requires unauth');
            return {
                reject: {
                    statusCode: HttpStatus.BadRequest,
                },
            };
        } else if (
            !authenticatedUser &&
            check.hasValue(endpointAuthConfig.requiresAuth, endpointDefinition.path)
        ) {
            log.faint('REJECTING: User is NOT authenticated but endpoint requires auth');
            return {
                reject: {
                    statusCode: HttpStatus.Unauthorized,
                },
            };
        } else {
            log.faint(
                'Context created successfully, user:',
                authenticatedUser?.username || 'anonymous',
            );
            return {
                context: {
                    authenticatedUser,
                },
            };
        }
    },
    endpoints: [
        userImplementation,
        loginImplementation,
        signUpImplementation,
        logoutImplementation,
    ],
});

await startApiServer(demoApiImplementation, {
    externalOrigin: demoApiStartOrigin,
    workerCount: 1,
});
