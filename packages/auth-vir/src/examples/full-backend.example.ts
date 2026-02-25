import {type ClientRequest, type ServerResponse} from 'node:http';
import {
    doesPasswordMatchHash,
    extractUserIdFromRequestHeaders,
    generateNewJwtKeys,
    generateSuccessfulLoginHeaders,
    hashPassword,
    parseJwtKeys,
    type CookieParams,
    type CreateJwtParams,
    type CsrfHeaderNameOption,
} from '../index.js';

type MyUserId = string;

/**
 * The CSRF header prefix for this app. Either `csrfHeaderPrefix` or `csrfHeaderName` must be
 * provided to all CSRF-related functions.
 */
const csrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'my-app',
};

/**
 * Use this for a /login endpoint.
 *
 * This verifies a user's login credentials and generate the auth cookie and CSRF token.
 */
export async function handleLogin(
    userRequestData: Readonly<{username: string; password: string}>,
    response: ServerResponse,
) {
    const user = findUserInDatabaseByUsername(userRequestData.username);

    if (
        !(await doesPasswordMatchHash({
            hash: user.hashedPassword,
            password: userRequestData.password,
        }))
    ) {
        throw new Error('Credentials mismatch.');
    }

    const authHeaders = await generateSuccessfulLoginHeaders(user.id, cookieParams, csrfOption);
    response.setHeaders(new Headers(authHeaders));
}

/**
 * Use this for a /sign-up endpoint.
 *
 * This creates a new user, stores their securely hashed password in the database, and generates the
 * auth cookie and CSRF token.
 */
export async function createUser(
    userRequestData: Readonly<{username: string; password: string}>,
    response: ServerResponse,
) {
    const newUser = await createUserInDatabase(userRequestData);

    const authHeaders = await generateSuccessfulLoginHeaders(newUser.id, cookieParams, csrfOption);
    response.setHeaders(new Headers(authHeaders));
}

/**
 * Use this all endpoints that require an authenticated user.
 *
 * This loads the current user from their auth cookie and CSRF token.
 */
export async function getAuthenticatedUser(request: ClientRequest) {
    const userId = (
        await extractUserIdFromRequestHeaders<MyUserId>(request.getHeaders(), jwtParams, csrfOption)
    )?.userId;
    const user = userId ? findUserInDatabaseById(userId) : undefined;

    if (!userId || !user) {
        throw new Error('Unauthorized.');
    }

    return user;
}

/**
 * # ===========
 *
 * Helpers
 *
 * # ===========
 */

async function loadSecretJwtKeys() {
    /**
     * This should load your saved JWT keys from a non-committed config file or a secrets manager
     * (like AWS Secrets Manager).
     */
    return await generateNewJwtKeys();
}

const jwtParams: Readonly<CreateJwtParams> = {
    audience: 'server context',
    jwtDuration: {
        hours: 2,
    },
    issuer: 'server login',
    jwtKeys: await parseJwtKeys(await loadSecretJwtKeys()),
};

const cookieParams: CookieParams = {
    cookieDuration: {
        hours: 2,
    },
    hostOrigin: 'https://your-backend-origin.example.com',
    jwtParams,
};

function findUserInDatabaseByUsername(username: string) {
    /** This should connect to your database and find a user matching the given username. */

    return {
        /** This should be retrieved from your database. */
        id: 'some id',
        username,
        /** This should be retrieved from your database. */
        hashedPassword: 'hash retrieved from database',
    };
}

function findUserInDatabaseById(userId: MyUserId):
    | undefined
    | {
          id: MyUserId;
          username: string;
      } {
    /** This should connect to your database and find a user matching the given user id. */

    return {
        id: userId,
        /** This should be retrieved from your database. */
        username: 'some username',
    };
}

async function createUserInDatabase(
    userRequestData: Readonly<{username: string; password: string}>,
) {
    const hashedPassword = await hashPassword(userRequestData.password);

    if (!hashedPassword) {
        throw new Error('Password too long.');
    }

    /**
     * Store the new username and hashedPassword in your database and return the new user id.
     *
     * @example
     *
     *     // using the Prisma ORM:
     *     return (
     *         await prismaClient.user.create({
     *             data: {
     *                 username: userRequestData.username,
     *                 hashedPassword,
     *             },
     *             select: {
     *                 id: true,
     *             },
     *         })
     *     ).id;
     */

    return {
        id: 'some new id',
    };
}
