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
    type AnyDuration,
} from 'date-vir';
import {type IncomingHttpHeaders, type OutgoingHttpHeaders} from 'node:http';
import {type EmptyObject, type RequireExactlyOne, type RequireOneOrNone} from 'type-fest';
import {
    extractUserIdFromRequestHeaders,
    generateLogoutHeaders,
    insecureExtractUserIdFromCookieAlone,
    type UserIdResult,
} from '../auth.js';
import {
    AuthCookie,
    clearCsrfCookie,
    generateAuthCookie,
    generateCsrfCookie,
    type CookieParams,
} from '../cookie.js';
import {generateCsrfToken, type CsrfHeaderNameOption} from '../csrf-token.js';
import {AuthHeaderName, mergeHeaderValues} from '../headers.js';
import {generateNewJwtKeys, parseJwtKeys, type JwtKeys, type RawJwtKeys} from '../jwt/jwt-keys.js';
import {defaultAllowedClockSkew, type CreateJwtParams, type ParseJwtParams} from '../jwt/jwt.js';
import {isSessionRefreshReady} from './is-session-refresh-ready.js';

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
            requestHeaders: Readonly<IncomingHttpHeaders>;
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
        /** If this returns true, logging will be enabled while handling the relevant session. */
        enableLogging(params: {
            user: DatabaseUser | undefined;
            userId: UserId | undefined;
            assumedUserParams: AssumedUserParams | undefined;
        }): boolean;
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
        /** If provided, logs will be sent to this method. */
        log?: (message: string, extraData: AnyObject) => void;
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
        sessionRefreshStartTime: Readonly<AnyDuration>;
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
        /**
         * Optional separate origin for the CSRF cookie's `Domain` attribute. When set, the
         * non-`HttpOnly` CSRF cookie will use this origin's hostname instead of `serviceOrigin`.
         *
         * This is useful when the backend and frontend live on different subdomains that don't
         * share a common parent narrower than the top-level domain. The `HttpOnly` auth cookie
         * stays scoped to `serviceOrigin` (protecting it from unrelated subdomains), while the CSRF
         * cookie uses the broader domain so frontend JavaScript can read it via `document.cookie`.
         *
         * The CSRF token alone is not a security risk — it is only meaningful when paired with the
         * JWT embedded in the `HttpOnly` auth cookie.
         */
        csrfCookieOrigin: string;
    }>
>;

const defaultSessionIdleTimeout: Readonly<AnyDuration> = {
    minutes: 20,
};

const defaultSessionRefreshStartTime: Readonly<AnyDuration> = {
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

    /**
     * Resolves the origin to use for CSRF cookie generation. Returns `csrfCookieOrigin` if
     * configured, otherwise falls back to the auth cookie origin.
     */
    protected resolveCsrfCookieOrigin(authCookieOrigin: string): string {
        return this.config.csrfCookieOrigin || authCookieOrigin;
    }

    /** Conditionally logs a message if logging is enabled for the given user context. */
    protected logForUser(
        params: {
            user: DatabaseUser | undefined;
            userId: UserId | undefined;
            assumedUserParams: AssumedUserParams | undefined;
        },
        message: string,
        extra?: Record<string, unknown>,
    ): void {
        if (this.config.enableLogging?.(params)) {
            const extraData = {
                userId: params.userId,
                ...extra,
            };

            if (this.config.log) {
                this.config.log(message, extraData);
            } else {
                console.info(`[auth-vir] ${message}`, extraData);
            }
        }
    }

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
            ? await this.config.generateServiceOrigin?.({
                  requestHeaders,
              })
            : undefined;

        return {
            cookieDuration: this.config.userSessionIdleTimeout || defaultSessionIdleTimeout,
            hostOrigin: serviceOrigin || this.config.serviceOrigin,
            jwtParams: await this.getJwtParams(),
            isDev: this.config.isDev,
            authCookie: isSignUpCookie ? AuthCookie.SignUp : AuthCookie.Auth,
        };
    }

    /** Calls the provided `getUserFromDatabase` config. */
    protected async getDatabaseUser({
        isSignUpCookie,
        userId,
        assumingUser,
        requestHeaders,
    }: {
        userId: UserId | undefined;
        assumingUser: AssumedUserParams | undefined;
        isSignUpCookie: boolean;
        requestHeaders: IncomingHttpHeaders;
    }): Promise<undefined | DatabaseUser> {
        if (!userId) {
            return undefined;
        }

        const authenticatedUser = await this.config.getUserFromDatabase({
            assumingUser,
            userId,
            isSignUpCookie,
            requestHeaders,
        });

        if (!authenticatedUser) {
            this.logForUser(
                {
                    user: undefined,
                    userId,
                    assumedUserParams: assumingUser,
                },
                'getUserFromDatabase returned no user',
                {
                    isSignUpCookie,
                },
            );
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
            this.logForUser(
                {
                    user: undefined,
                    userId: userIdResult.userId,
                    assumedUserParams: undefined,
                },
                'Session refresh denied: JWT already expired (even with clock skew tolerance)',
                {
                    jwtExpiration: userIdResult.jwtExpiration,
                    now: JSON.stringify(now),
                },
            );
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
                this.logForUser(
                    {
                        user: undefined,
                        userId: userIdResult.userId,
                        assumedUserParams: undefined,
                    },
                    'Session refresh denied: max session duration exceeded',
                    {
                        sessionStartedAt: userIdResult.sessionStartedAt,
                        maxSessionEndDate: JSON.stringify(maxSessionEndDate),
                        now: JSON.stringify(now),
                    },
                );
                return undefined;
            }
        }

        const sessionRefreshStartTime =
            this.config.sessionRefreshStartTime || defaultSessionRefreshStartTime;
        const isRefreshReady = isSessionRefreshReady({
            now,
            jwtIssuedAt: userIdResult.jwtIssuedAt,
            sessionRefreshStartTime,
        });

        if (isRefreshReady) {
            const isSignUpCookie = userIdResult.cookieName === AuthCookie.SignUp;
            const cookieParams = await this.getCookieParams({
                isSignUpCookie,
                requestHeaders,
            });

            const authCookie = await generateAuthCookie(
                {
                    csrfToken: userIdResult.csrfToken,
                    userId: userIdResult.userId,
                    sessionStartedAt: userIdResult.sessionStartedAt || Date.now(),
                },
                cookieParams,
            );
            const csrfCookie = generateCsrfCookie(userIdResult.csrfToken, {
                ...cookieParams,
                hostOrigin: this.resolveCsrfCookieOrigin(cookieParams.hostOrigin),
            });

            return {
                'set-cookie': [
                    authCookie,
                    csrfCookie,
                ],
            };
        } else {
            this.logForUser(
                {
                    user: undefined,
                    userId: userIdResult.userId,
                    assumedUserParams: undefined,
                },
                'Session refresh skipped: not yet ready for refresh',
                {
                    jwtIssuedAt: userIdResult.jwtIssuedAt,
                    sessionRefreshStartTime,
                },
            );
            return undefined;
        }
    }

    /** Reads the user's assumed user headers and, if configured, gets the assumed user. */
    protected async getAssumedUser({
        requestHeaders,
        user,
    }: {
        user: DatabaseUser;
        requestHeaders: IncomingHttpHeaders;
    }): Promise<DatabaseUser | undefined> {
        if (!this.config.assumeUser || !(await this.config.assumeUser.canAssumeUser(user))) {
            return undefined;
        }

        const assumedUserHeader: string | undefined = ensureArray(
            requestHeaders[this.config.assumedUserHeaderName || AuthHeaderName.AssumedUser],
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
            requestHeaders,
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
            isSignUpCookie ? AuthCookie.SignUp : AuthCookie.Auth,
        );
        if (!userIdResult) {
            this.logForUser(
                {
                    user: undefined,
                    userId: undefined,
                    assumedUserParams: undefined,
                },
                'getSecureUser: failed to extract user ID from request headers (invalid JWT, missing cookie, or CSRF mismatch)',
                {
                    isSignUpCookie,
                },
            );
            return undefined;
        }

        const user = await this.getDatabaseUser({
            userId: userIdResult.userId,
            assumingUser: undefined,
            isSignUpCookie,
            requestHeaders,
        });

        if (!user) {
            this.logForUser(
                {
                    user: undefined,
                    userId: userIdResult.userId,
                    assumedUserParams: undefined,
                },
                'getSecureUser: user not found in database',
                {
                    isSignUpCookie,
                },
            );
            return undefined;
        }

        const assumedUser = await this.getAssumedUser({
            requestHeaders,
            user,
        });

        const cookieRefreshHeaders = allowUserAuthRefresh
            ? await this.createCookieRefreshHeaders({
                  userIdResult,
                  requestHeaders,
              })
            : undefined;

        /**
         * Always include the CSRF cookie so it gets re-established if the browser clears it. When
         * session refresh fires, its headers already include a CSRF cookie.
         */
        const authCookieOrigin =
            (await this.config.generateServiceOrigin?.({
                requestHeaders,
            })) || this.config.serviceOrigin;

        const csrfCookie = generateCsrfCookie(userIdResult.csrfToken, {
            hostOrigin: this.resolveCsrfCookieOrigin(authCookieOrigin),
            isDev: this.config.isDev,
        });

        return {
            user: assumedUser || user,
            isAssumed: !!assumedUser,
            responseHeaders: {
                'set-cookie': mergeHeaderValues(cookieRefreshHeaders?.['set-cookie'], csrfCookie),
            },
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
            this.cachedParsedJwtKeys = {
                [cacheKey]: parsedKeys,
            };
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
        const clearingAllCookies = !!params.allCookies;

        const signUpCookieHeaders =
            params.allCookies || params.isSignUpCookie
                ? generateLogoutHeaders(
                      await this.getCookieParams({
                          isSignUpCookie: true,
                          requestHeaders: undefined,
                      }),
                      {
                          preserveCsrf: !clearingAllCookies,
                      },
                  )
                : undefined;
        const authCookieHeaders =
            params.allCookies || !params.isSignUpCookie
                ? generateLogoutHeaders(
                      await this.getCookieParams({
                          isSignUpCookie: false,
                          requestHeaders: undefined,
                      }),
                      {
                          preserveCsrf: !clearingAllCookies,
                      },
                  )
                : undefined;

        /**
         * When `csrfCookieOrigin` is configured, the CSRF cookie lives on a broader domain than the
         * auth cookie. Clear it on that broader domain too so stale tokens don't linger.
         */
        const broadCsrfClearCookie =
            clearingAllCookies && this.config.csrfCookieOrigin
                ? clearCsrfCookie({
                      hostOrigin: this.config.csrfCookieOrigin,
                      isDev: this.config.isDev,
                  })
                : undefined;

        return {
            'set-cookie': mergeHeaderValues(
                signUpCookieHeaders?.['set-cookie'],
                authCookieHeaders?.['set-cookie'],
                broadCsrfClearCookie,
            ),
        };
    }

    /**
     * Refreshes a login session by reissuing the auth cookie with the same CSRF token instead of
     * generating a new one.
     */
    protected async refreshLoginHeaders({
        userId,
        cookieParams,
        existingUserIdResult,
    }: {
        userId: UserId;
        cookieParams: Readonly<CookieParams>;
        existingUserIdResult: Readonly<UserIdResult<UserId>>;
    }): Promise<Record<string, string | string[]>> {
        const authCookie = await generateAuthCookie(
            {
                csrfToken: existingUserIdResult.csrfToken,
                userId,
                sessionStartedAt: existingUserIdResult.sessionStartedAt,
            },
            cookieParams,
        );

        const csrfCookie = generateCsrfCookie(existingUserIdResult.csrfToken, {
            ...cookieParams,
            hostOrigin: this.resolveCsrfCookieOrigin(cookieParams.hostOrigin),
        });

        return {
            'set-cookie': [
                authCookie,
                csrfCookie,
            ],
        };
    }

    /** Generates login headers for a brand-new session (no existing JWT to reuse). */
    protected async generateFreshLoginHeaders(
        userId: UserId,
        cookieParams: Readonly<CookieParams>,
    ): Promise<Record<string, string[]>> {
        const csrfToken = generateCsrfToken();

        const authCookie = await generateAuthCookie(
            {
                csrfToken,
                userId,
                sessionStartedAt: Date.now(),
            },
            cookieParams,
        );

        const csrfCookie = generateCsrfCookie(csrfToken, {
            ...cookieParams,
            hostOrigin: this.resolveCsrfCookieOrigin(cookieParams.hostOrigin),
        });

        return {
            'set-cookie': [
                authCookie,
                csrfCookie,
            ],
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
        const oppositeCookieName = isSignUpCookie ? AuthCookie.Auth : AuthCookie.SignUp;
        const hasExistingOppositeCookie = requestHeaders.cookie?.includes(`${oppositeCookieName}=`);

        const discardOppositeCookieHeaders = hasExistingOppositeCookie
            ? generateLogoutHeaders(
                  await this.getCookieParams({
                      isSignUpCookie: !isSignUpCookie,
                      requestHeaders,
                  }),
                  {
                      preserveCsrf: true,
                  },
              )
            : undefined;

        const existingUserIdResult = await extractUserIdFromRequestHeaders<UserId>(
            requestHeaders,
            await this.getJwtParams(),
            this.config.csrf,
            isSignUpCookie ? AuthCookie.SignUp : AuthCookie.Auth,
        );

        const cookieParams = await this.getCookieParams({
            isSignUpCookie,
            requestHeaders,
        });

        const newCookieHeaders = existingUserIdResult
            ? await this.refreshLoginHeaders({
                  userId,
                  cookieParams,
                  existingUserIdResult,
              })
            : await this.generateFreshLoginHeaders(userId, cookieParams);

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
            return {
                secureUser,
            };
        }

        // eslint-disable-next-line @typescript-eslint/no-deprecated
        const insecureUser = await this.getInsecureUser(params);

        return insecureUser
            ? {
                  insecureUser,
              }
            : {};
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
            AuthCookie.Auth,
        );

        if (!userIdResult) {
            this.logForUser(
                {
                    user: undefined,
                    userId: undefined,
                    assumedUserParams: undefined,
                },
                'getInsecureUser: failed to extract user ID from cookie (invalid JWT or missing cookie)',
            );
            return undefined;
        }

        const user = await this.getDatabaseUser({
            isSignUpCookie: false,
            userId: userIdResult.userId,
            assumingUser: undefined,
            requestHeaders,
        });

        if (!user) {
            this.logForUser(
                {
                    user: undefined,
                    userId: userIdResult.userId,
                    assumedUserParams: undefined,
                },
                'getInsecureUser: user not found in database',
            );
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
