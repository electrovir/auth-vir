import {
    ensureArray,
    type AnyObject,
    type JsonCompatibleObject,
    type MaybePromise,
    type PartialWithUndefined,
} from '@augment-vir/common';
import {
    calculateRelativeDate,
    createUtcFullDate,
    getNowInUtcTimezone,
    isDateAfter,
    negateDuration,
    type AnyDuration,
} from 'date-vir';
import {type IncomingHttpHeaders, type OutgoingHttpHeaders} from 'node:http';
import {type EmptyObject, type RequireExactlyOne, type RequireOneOrNone} from 'type-fest';
import {
    extractUserIdFromRequestHeaders,
    generateLogoutHeaders,
    generateSuccessfulLoginHeaders,
    insecureExtractUserIdFromCookieAlone,
    type UserIdResult,
} from '../auth.js';
import {AuthCookieName, type CookieParams} from '../cookie.js';
import {defaultAllowedClockSkew, type CsrfHeaderNameOption} from '../csrf-token.js';
import {AuthHeaderName, mergeHeaderValues} from '../headers.js';
import {generateNewJwtKeys, parseJwtKeys, type JwtKeys, type RawJwtKeys} from '../jwt/jwt-keys.js';
import {type CreateJwtParams, type ParseJwtParams} from '../jwt/jwt.js';
import {authLog} from '../log.js';

/**
 * Output from `BackendAuthClient.getSecureUser()`.
 *
 * @category Internal
 */
export type GetUserResult<DatabaseUser extends AnyObject> = {
    /** The retrieved user. */
    user: DatabaseUser;
    /**
     * When `true`, indicates that the current `user` result is as assumed user. This can only be
     * `true` if you've configured user assuming in `BackendAuthClient`.
     */
    isAssumed: boolean;
    /**
     * This should be merged into your own response headers. It usually contains auth cookie
     * duration refresh headers.
     */
    responseHeaders: OutgoingHttpHeaders;
};

/**
 * Config for {@link BackendAuthClient}.
 *
 * @category Internal
 */
export type BackendAuthClientConfig<
    DatabaseUser extends AnyObject,
    UserId extends string | number,
    AssumedUserParams extends JsonCompatibleObject = EmptyObject,
> = Readonly<
    {
        csrf: Readonly<CsrfHeaderNameOption>;
        /** The origin of your backend that is offering auth cookies. */
        serviceOrigin: string;
        /** Finds the relevant user from your own database. */
        getUserFromDatabase: (userParams: {
            /** The user id extracted from the request cookie. */
            userId: UserId;
            /** Indicates that we're loading the user from a sign up cookie. */
            isSignUpCookie: boolean;
            /**
             * If this is set, we're attempting to load a database user for the purpose of assuming
             * their user identity. Otherwise, this is `undefined`.
             */
            assumingUser: AssumedUserParams | undefined;
        }) => MaybePromise<DatabaseUser | undefined | null>;
        /**
         * Get JWT keys produced by {@link generateNewJwtKeys}. Make sure that each time this is
         * called, the same JWT keys are returned (do not call {@link generateNewJwtKeys} each time
         * this is called). Any time the JWT keys change, all current sessions will terminate.
         */
        getJwtKeys: () => MaybePromise<Readonly<RawJwtKeys>>;
        /**
         * When `isDev` is set, cookies do not require HTTPS (so they can be used with
         * http://localhost).
         */
        isDev: boolean;
    } & PartialWithUndefined<{
        /**
         * Overwrite the header name used for tracking is an admin is assuming the identity of
         * another user.
         */
        assumedUserHeaderName: string;
        /**
         * Optionally generate a service origin from request headers. The generated origin is used
         * for set-cookie headers.
         */
        generateServiceOrigin(params: {
            requestHeaders: Readonly<IncomingHttpHeaders>;
        }): MaybePromise<undefined | string>;
        /**
         * Set this to allow specific users (determined by `canAssumeUser`) to assume the identity
         * of other users. This should only be used for admins so that they can troubleshoot user
         * issues.
         *
         * @see {@link AuthHeaderName}
         */
        assumeUser: {
            /**
             * Parse the assumed user header value.
             *
             * @see {@link AuthHeaderName}
             */
            parseAssumedUserHeaderValue: (
                /**
                 * The assumed user header value.
                 *
                 * @see {@link AuthHeaderName}
                 */
                data: string,
            ) => MaybePromise<
                | {
                      assumedUserParams: AssumedUserParams;
                      userId: UserId;
                  }
                | undefined
            >;
            /**
             * Return `true` to allow the current/original user to assume identities of other users.
             * Return `false` to block it. It is recommended to only return `true` for admin users.
             *
             * @see {@link AuthHeaderName}
             */
            canAssumeUser: (originalUser: DatabaseUser) => MaybePromise<boolean>;
        };
        /**
         * This determines how long a cookie will be valid until it needs to be refreshed.
         *
         * @default {minutes: 20}
         */
        userSessionIdleTimeout: Readonly<AnyDuration>;
        /**
         * How long into a user's session when we should start trying to refresh their session.
         *
         * @default {minutes: 2}
         */
        sessionRefreshTimeout: Readonly<AnyDuration>;
        /**
         * The maximum duration a session can last, regardless of activity. After this time, the
         * user will be logged out even if they are actively using the application.
         *
         * @default {days: 1.5}
         */
        maxSessionDuration: Readonly<AnyDuration>;
        /**
         * Allowed clock skew tolerance for JWT and CSRF token expiration checks. Accounts for
         * differences between server and client clocks.
         *
         * @default {minutes: 5}
         */
        allowedClockSkew: Readonly<AnyDuration>;
    }>
>;

const defaultSessionIdleTimeout: Readonly<AnyDuration> = {
    minutes: 20,
};

const defaultSessionRefreshTimeout: Readonly<AnyDuration> = {
    minutes: 2,
};

const defaultMaxSessionDuration: Readonly<AnyDuration> = {
    days: 1.5,
};

/**
 * An auth client for creating and validating JWTs embedded in cookies. This should only be used in
 * a backend environment as it accesses native Node packages.
 *
 * @category Auth : Host
 * @category Clients
 */
export class BackendAuthClient<
    DatabaseUser extends AnyObject,
    UserId extends string | number,
    AssumedUserParams extends AnyObject = EmptyObject,
> {
    protected cachedParsedJwtKeys: Record<string, Readonly<JwtKeys>> = {};

    constructor(
        protected readonly config: BackendAuthClientConfig<DatabaseUser, UserId, AssumedUserParams>,
    ) {}

    /** Get all the parameters used for cookie generation. */
    protected async getCookieParams({
        isSignUpCookie,
        requestHeaders,
    }: {
        /**
         * Set this to `true` when we are setting the initial cookie right after a user signs up.
         * This allows them to auto-authorize when they verify their email address.
         *
         * This should only be set to `true` when a new user is signing up.
         */
        isSignUpCookie: boolean;
        requestHeaders: Readonly<IncomingHttpHeaders> | undefined;
    }): Promise<Readonly<CookieParams>> {
        const serviceOrigin = requestHeaders
            ? await this.config.generateServiceOrigin?.({requestHeaders})
            : undefined;

        return {
            cookieDuration: this.config.userSessionIdleTimeout || defaultSessionIdleTimeout,
            hostOrigin: serviceOrigin || this.config.serviceOrigin,
            jwtParams: await this.getJwtParams(),
            isDev: this.config.isDev,
            cookieName: isSignUpCookie ? AuthCookieName.SignUp : AuthCookieName.Auth,
        };
    }

    /** Calls the provided `getUserFromDatabase` config. */
    protected async getDatabaseUser({
        isSignUpCookie,
        userId,
        assumingUser,
    }: {
        userId: UserId | undefined;
        assumingUser: AssumedUserParams | undefined;
        isSignUpCookie: boolean;
    }): Promise<undefined | DatabaseUser> {
        if (!userId) {
            return undefined;
        }

        const authenticatedUser = await this.config.getUserFromDatabase({
            assumingUser,
            userId,
            isSignUpCookie,
        });

        if (!authenticatedUser) {
            return undefined;
        }

        return authenticatedUser;
    }

    /** Creates a `'cookie-set'` header to refresh the user's session cookie. */
    protected async createCookieRefreshHeaders({
        userIdResult,
        requestHeaders,
    }: {
        userIdResult: Readonly<UserIdResult<UserId>>;
        requestHeaders: IncomingHttpHeaders;
    }): Promise<OutgoingHttpHeaders | undefined> {
        const now = getNowInUtcTimezone();

        const clockSkew = this.config.allowedClockSkew || defaultAllowedClockSkew;

        /** Double check that the JWT hasn't already expired (with clock skew tolerance). */
        const isExpiredAlready = isDateAfter({
            fullDate: now,
            relativeTo: calculateRelativeDate(userIdResult.jwtExpiration, clockSkew),
        });

        if (isExpiredAlready) {
            authLog('auth-vir: SESSION EXPIRED - JWT already expired, user will be logged out', {
                userId: userIdResult.userId,
                jwtExpiration: userIdResult.jwtExpiration,
            });
            return undefined;
        }

        /**
         * Check if the session has exceeded the max session duration. If so, don't refresh the
         * session and let it expire naturally.
         */
        const maxSessionDuration = this.config.maxSessionDuration || defaultMaxSessionDuration;
        if (userIdResult.sessionStartedAt) {
            const sessionStartDate = createUtcFullDate(userIdResult.sessionStartedAt);
            const maxSessionEndDate = calculateRelativeDate(sessionStartDate, maxSessionDuration);
            const isSessionExpired = isDateAfter({
                fullDate: now,
                relativeTo: maxSessionEndDate,
            });

            if (isSessionExpired) {
                authLog(
                    'auth-vir: SESSION EXPIRED - max session duration exceeded, user will be logged out',
                    {
                        userId: userIdResult.userId,
                        sessionStartedAt: userIdResult.sessionStartedAt,
                        maxSessionDuration,
                    },
                );
                return undefined;
            }
        }

        /**
         * This check performs the following: the current time + the refresh threshold > JWT
         * expiration.
         *
         * Visually, this check looks like this:
         *
         *      X   C=======Y=======R   Z
         *
         * - C = current time
         * - R = C + refresh threshold
         * - `=` = the time frame in which {@link isRefreshReady} = true.
         * - X = JWT expiration that has already expired (rejected by {@link isExpiredAlready}.
         * - Y = JWT expiration within the refresh threshold: {@link isRefreshReady} = true.
         * - Z = JWT expiration outside the refresh threshold: {@link isRefreshReady} = false.
         */
        const sessionRefreshTimeout =
            this.config.sessionRefreshTimeout || defaultSessionRefreshTimeout;
        const isRefreshReady = isDateAfter({
            fullDate: now,
            relativeTo: calculateRelativeDate(
                userIdResult.jwtExpiration,
                negateDuration(sessionRefreshTimeout),
            ),
        });

        if (isRefreshReady) {
            return this.createLoginHeaders({
                requestHeaders,
                userId: userIdResult.userId,
                isSignUpCookie: userIdResult.cookieName === AuthCookieName.SignUp,
            });
        } else {
            return undefined;
        }
    }

    /** Reads the user's assumed user headers and, if configured, gets the assumed user. */
    protected async getAssumedUser({
        headers,
        user,
    }: {
        user: DatabaseUser;
        headers: IncomingHttpHeaders;
    }): Promise<DatabaseUser | undefined> {
        if (!this.config.assumeUser || !(await this.config.assumeUser.canAssumeUser(user))) {
            return undefined;
        }

        const assumedUserHeader: string | undefined = ensureArray(
            headers[this.config.assumedUserHeaderName || AuthHeaderName.AssumedUser],
        )[0];

        if (!assumedUserHeader) {
            return undefined;
        }

        const parsedAssumedUserData =
            await this.config.assumeUser.parseAssumedUserHeaderValue(assumedUserHeader);

        if (!parsedAssumedUserData || !parsedAssumedUserData.userId) {
            return undefined;
        }

        const assumedUser = await this.getDatabaseUser({
            isSignUpCookie: false,
            userId: parsedAssumedUserData.userId,
            assumingUser: parsedAssumedUserData.assumedUserParams,
        });

        return assumedUser;
    }

    /** Securely extract a user from their request headers. */
    public async getSecureUser({
        requestHeaders,
        isSignUpCookie,
        allowUserAuthRefresh,
    }: {
        requestHeaders: IncomingHttpHeaders;
        isSignUpCookie: boolean;
        /**
         * If true, this method will generate headers to refresh the user's auth session. This
         * should likely only be done with a specific endpoint, like whatever endpoint you trigger
         * with the frontend auth client's `checkUser.performCheck` callback.
         */
        allowUserAuthRefresh: boolean;
    }): Promise<GetUserResult<DatabaseUser> | undefined> {
        const userIdResult = await extractUserIdFromRequestHeaders<UserId>(
            requestHeaders,
            await this.getJwtParams(),
            this.config.csrf,
            isSignUpCookie ? AuthCookieName.SignUp : AuthCookieName.Auth,
        );
        if (!userIdResult) {
            if (!isSignUpCookie) {
                authLog('auth-vir: getSecureUser failed - could not extract user from request');
            }
            return undefined;
        }

        const user = await this.getDatabaseUser({
            userId: userIdResult.userId,
            assumingUser: undefined,
            isSignUpCookie,
        });

        if (!user) {
            authLog('auth-vir: getSecureUser failed - user not found in database', {
                userId: userIdResult.userId,
            });
            return undefined;
        }

        const assumedUser = await this.getAssumedUser({
            headers: requestHeaders,
            user,
        });

        const cookieRefreshHeaders =
            (await this.createCookieRefreshHeaders({
                userIdResult,
                requestHeaders,
            })) || {};

        return {
            user: assumedUser || user,
            isAssumed: !!assumedUser,
            responseHeaders: allowUserAuthRefresh ? cookieRefreshHeaders : {},
        };
    }

    /**
     * Get all the JWT params used when creating the auth cookie, in case you need them for
     * something else too.
     */
    public async getJwtParams(): Promise<Readonly<CreateJwtParams> & ParseJwtParams> {
        const rawJwtKeys = await this.config.getJwtKeys();

        const cacheKey = JSON.stringify(rawJwtKeys);

        const cachedParsedKeys = this.cachedParsedJwtKeys[cacheKey];
        const parsedKeys = cachedParsedKeys || (await parseJwtKeys(rawJwtKeys));

        if (!cachedParsedKeys) {
            this.cachedParsedJwtKeys = {[cacheKey]: parsedKeys};
        }
        return {
            jwtKeys: parsedKeys,
            audience: 'server-context',
            issuer: 'server-auth',
            jwtDuration: this.config.userSessionIdleTimeout || defaultSessionIdleTimeout,
            allowedClockSkew: this.config.allowedClockSkew || defaultAllowedClockSkew,
        };
    }

    /** Use these headers to log out the user. */
    public async createLogoutHeaders(
        params: Readonly<
            RequireExactlyOne<{
                allCookies: true;
                isSignUpCookie: boolean;
            }> & {
                /** Overrides the client's already established `serviceOrigin`. */
                serviceOrigin?: string | undefined;
            }
        >,
    ): Promise<
        Record<string, string | string[]> & {
            'set-cookie': string[];
        }
    > {
        authLog(
            'auth-vir: LOGOUT - BackendAuthClient.createLogoutHeaders called',
            {
                allCookies: 'allCookies' in params ? params.allCookies : undefined,
                isSignUpCookie: 'isSignUpCookie' in params ? params.isSignUpCookie : undefined,
            },
            new Error().stack,
        );
        const signUpCookieHeaders =
            params.allCookies || params.isSignUpCookie
                ? generateLogoutHeaders(
                      await this.getCookieParams({
                          isSignUpCookie: true,
                          requestHeaders: undefined,
                      }),
                      this.config.csrf,
                  )
                : undefined;
        const authCookieHeaders =
            params.allCookies || !params.isSignUpCookie
                ? generateLogoutHeaders(
                      await this.getCookieParams({
                          isSignUpCookie: false,
                          requestHeaders: undefined,
                      }),
                      this.config.csrf,
                  )
                : undefined;

        const setCookieHeader: {
            'set-cookie': string[];
        } = {
            'set-cookie': mergeHeaderValues(
                signUpCookieHeaders?.['set-cookie'],
                authCookieHeaders?.['set-cookie'],
            ),
        };
        const csrfTokenHeader = {
            ...authCookieHeaders,
            ...signUpCookieHeaders,
        };

        return {
            ...csrfTokenHeader,
            ...setCookieHeader,
        };
    }

    /** Use these headers to log a user in. */
    public async createLoginHeaders({
        userId,
        requestHeaders,
        isSignUpCookie,
    }: {
        userId: UserId;
        requestHeaders: IncomingHttpHeaders;
        isSignUpCookie: boolean;
    }): Promise<OutgoingHttpHeaders> {
        const oppositeCookieName = isSignUpCookie ? AuthCookieName.Auth : AuthCookieName.SignUp;
        const hasExistingOppositeCookie = requestHeaders.cookie?.includes(`${oppositeCookieName}=`);

        const discardOppositeCookieHeaders = hasExistingOppositeCookie
            ? generateLogoutHeaders(
                  await this.getCookieParams({
                      isSignUpCookie: !isSignUpCookie,
                      requestHeaders,
                  }),
                  this.config.csrf,
              )
            : undefined;

        const existingUserIdResult = await extractUserIdFromRequestHeaders<UserId>(
            requestHeaders,
            await this.getJwtParams(),
            this.config.csrf,
            isSignUpCookie ? AuthCookieName.SignUp : AuthCookieName.Auth,
        );
        const sessionStartedAt = existingUserIdResult?.sessionStartedAt;

        const newCookieHeaders = await generateSuccessfulLoginHeaders(
            userId,
            await this.getCookieParams({
                isSignUpCookie,
                requestHeaders,
            }),
            this.config.csrf,
            sessionStartedAt,
        );

        return {
            ...newCookieHeaders,
            'set-cookie': mergeHeaderValues(
                newCookieHeaders['set-cookie'],
                discardOppositeCookieHeaders?.['set-cookie'],
            ),
            ...(isSignUpCookie
                ? {
                      [AuthHeaderName.IsSignUpAuth]: 'true',
                  }
                : {}),
        };
    }

    /** Combines `.getInsecureUser()` and `.getSecureUser()` into one method. */
    public async getInsecureOrSecureUser(params: {
        requestHeaders: IncomingHttpHeaders;
        isSignUpCookie: boolean;
        /**
         * If true, this method will generate headers to refresh the user's auth session. This
         * should likely only be done with a specific endpoint, like whatever endpoint you trigger
         * with the frontend auth client's `checkUser.performCheck` callback.
         */
        allowUserAuthRefresh: boolean;
        /** Overrides the client's already established `serviceOrigin`. */
        serviceOrigin?: string | undefined;
    }): Promise<
        RequireOneOrNone<{
            secureUser: GetUserResult<DatabaseUser>;
            /**
             * @deprecated This only half authenticates the user. It should only be used in
             *   circumstances where JavaScript cannot be used to attach the CSRF token header to
             *   the request (like when opening a PDF file). Use `.getSecureUser()` instead,
             *   whenever possible.
             */
            insecureUser: GetUserResult<DatabaseUser>;
        }>
    > {
        const secureUser = await this.getSecureUser(params);

        if (secureUser) {
            return {secureUser};
        }

        // eslint-disable-next-line @typescript-eslint/no-deprecated
        const insecureUser = await this.getInsecureUser(params);

        return insecureUser ? {insecureUser} : {};
    }

    /**
     * @deprecated This only half authenticates the user. It should only be used in circumstances
     *   where JavaScript cannot be used to attach the CSRF token header to the request (like when
     *   opening a PDF file). Use `.getSecureUser()` instead, whenever possible.
     */
    public async getInsecureUser({
        requestHeaders,
        allowUserAuthRefresh,
    }: {
        requestHeaders: IncomingHttpHeaders;
        /**
         * If true, this method will generate headers to refresh the user's auth session. This
         * should likely only be done with a specific endpoint, like whatever endpoint you trigger
         * with the frontend auth client's `checkUser.performCheck` callback.
         */
        allowUserAuthRefresh: boolean;
    }): Promise<GetUserResult<DatabaseUser> | undefined> {
        // eslint-disable-next-line @typescript-eslint/no-deprecated
        const userIdResult = await insecureExtractUserIdFromCookieAlone<UserId>(
            requestHeaders,
            await this.getJwtParams(),
            AuthCookieName.Auth,
        );

        if (!userIdResult) {
            authLog('auth-vir: getInsecureUser failed - could not extract user from request');
            return undefined;
        }

        const user = await this.getDatabaseUser({
            isSignUpCookie: false,
            userId: userIdResult.userId,
            assumingUser: undefined,
        });

        if (!user) {
            authLog('auth-vir: getInsecureUser failed - user not found in database', {
                userId: userIdResult.userId,
            });
            return undefined;
        }

        const refreshHeaders =
            allowUserAuthRefresh &&
            (await this.createCookieRefreshHeaders({
                userIdResult,
                requestHeaders,
            }));

        return {
            user,
            isAssumed: false,
            responseHeaders: refreshHeaders || {},
        };
    }
}
