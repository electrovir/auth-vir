import {check} from '@augment-vir/assert';
import {randomString} from '@augment-vir/common';
import {HttpStatus, implementService} from '@rest-vir/implement-service';
import {startService} from '@rest-vir/run-service';
import {
    AuthHeaderName,
    doesPasswordMatchHash,
    extractUserIdFromRequestHeaders,
    generateNewJwtKeys,
    generateSuccessfulLoginHeaders,
    hashPassword,
    parseJwtKeys,
    type CreateJwtParams,
} from 'auth-vir';
import {demoService, type DemoService} from './demo-service-definition.js';

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
    jwtDuration: {days: 1},
    issuer: 'demo-login',
};

const endpointAuthConfig = {
    /** These endpoints require an authenticated user to be making the request. */
    requiresAuth: ['/user'],
    /** These endpoints require a _not_ authenticated user to be making the request. */
    requiresUnauth: [
        '/login',
        '/sign-up',
    ],
} as const satisfies Record<string, (keyof DemoService['endpoints'])[]>;

const implementedService = implementService({
    service: demoService,
    customHeaders: [
        AuthHeaderName.CsrfToken,
    ],
    async createContext({requestHeaders, endpointDefinition}) {
        if (!endpointDefinition) {
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
        const _unsafe_authenticatedUserResult = await extractUserIdFromRequestHeaders(
            requestHeaders,
            {
                ...jwtParams,
                jwtKeys,
            },
        );

        // eslint-disable-next-line @typescript-eslint/no-deprecated
        const authenticatedUser = _unsafe_authenticatedUserResult
            ? // eslint-disable-next-line @typescript-eslint/no-deprecated
              mockDatabase.users.find((user) => user.id === _unsafe_authenticatedUserResult.userId)
            : undefined;

        if (
            authenticatedUser &&
            check.hasValue(endpointAuthConfig.requiresUnauth, endpointDefinition.path)
        ) {
            return {
                reject: {
                    statusCode: HttpStatus.BadRequest,
                },
            };
        } else if (
            !authenticatedUser &&
            check.hasValue(endpointAuthConfig.requiresAuth, endpointDefinition.path)
        ) {
            return {
                reject: {
                    statusCode: HttpStatus.Unauthorized,
                },
            };
        }

        return {
            context: {
                authenticatedUser,
            },
        };
    },
})({
    endpoints: {
        async '/login'({context, requestData, server}) {
            if (context.authenticatedUser) {
                return {
                    statusCode: HttpStatus.BadRequest,
                };
            }

            const userMatch = mockDatabase.users.find(
                (user) => user.username === requestData.username,
            );

            if (
                !userMatch ||
                !(await doesPasswordMatchHash({
                    hash: userMatch.hashedPassword,
                    password: requestData.password,
                }))
            ) {
                return {
                    statusCode: HttpStatus.Unauthorized,
                };
            }

            return {
                statusCode: HttpStatus.Ok,
                responseData: {
                    email: userMatch.email,
                    name: userMatch.name,
                    username: userMatch.username,
                },
                headers: await generateSuccessfulLoginHeaders(userMatch.id, {
                    cookieDuration: {hours: 2},
                    hostOrigin: server.serviceOrigin,
                    jwtParams: {
                        ...jwtParams,
                        jwtKeys,
                    },
                    isDev: true,
                }),
            };
        },
        async '/sign-up'({context, requestData, server}) {
            if (context.authenticatedUser) {
                return {
                    statusCode: HttpStatus.BadRequest,
                };
            }

            const hashedPassword = await hashPassword(requestData.password);

            if (!hashedPassword) {
                return {
                    statusCode: HttpStatus.BadRequest,
                    responseErrorMessage: 'Password too long',
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

            return {
                statusCode: HttpStatus.Ok,
                responseData: {
                    email: newUser.email,
                    name: newUser.name,
                    username: newUser.username,
                },
                headers: await generateSuccessfulLoginHeaders(newUser.id, {
                    cookieDuration: {hours: 2},
                    hostOrigin: server.serviceOrigin,
                    jwtParams: {
                        ...jwtParams,
                        jwtKeys,
                    },
                    isDev: true,
                }),
            };
        },
        '/user'({context}) {
            const userMatch = mockDatabase.users.find(
                (user) => user.username === context.authenticatedUser?.username,
            );

            if (!context.authenticatedUser || !userMatch) {
                return {
                    statusCode: HttpStatus.Unauthorized,
                };
            }

            return {
                statusCode: HttpStatus.Ok,
                responseData: {
                    email: userMatch.email,
                    name: userMatch.name,
                    username: userMatch.username,
                },
            };
        },
    },
});

await startService(implementedService, {
    workerCount: 1,
});
