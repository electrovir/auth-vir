import {
    ensureArray,
    type AnyObject,
    type JsonCompatibleObject,
    type MaybePromise,
    type PartialWithUndefined,
    type RequiredAndNotNull,
} from '@augment-vir/common';
import {calculateRelativeDate, getNowInUtcTimezone, isDateAfter, type AnyDuration} from 'date-vir';
import {type IncomingHttpHeaders, type OutgoingHttpHeaders} from 'node:http';
import {type EmptyObject, type RequireExactlyOne} from 'type-fest';
import {
    extractUserIdFromRequestHeaders,
    generateLogoutHeaders,
    generateSuccessfulLoginHeaders,
    insecureExtractUserIdFromCookieAlone,
    type UserIdResult,
} from '../auth.js';
import {AuthCookieName, type CookieParams} from '../cookie.js';
import {AuthHeaderName, mergeHeaderValues} from '../headers.js';
import {generateNewJwtKeys, parseJwtKeys, type JwtKeys, type RawJwtKeys} from '../jwt/jwt-keys.js';
import {type CreateJwtParams} from '../jwt/jwt.js';

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
    CsrfHeaderName extends string = AuthHeaderName.CsrfToken,
> = Readonly<
    {
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
        getJetKeys: () => MaybePromise<Readonly<RawJwtKeys>>;
        /**
         * When `isDev` is set, cookies do not require HTTPS (so they can be used with
         * http://localhost).
         */
        isDev: boolean;
    } & PartialWithUndefined<{
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
         * How long before a user's session times out when we should start trying to refresh their
         * session.
         *
         * @default {minutes: 5}
         */
        sessionRefreshThreshold: Readonly<AnyDuration>;
        overrides: PartialWithUndefined<{
            csrfHeaderName: CsrfHeaderName;
            assumedUserHeaderName: string;
        }>;
    }>
>;

const defaultSessionIdleTimeout: Readonly<AnyDuration> = {
    minutes: 20,
};

/**
 * An auth client for creating and validating JWTs embedded in cookies. This should only be used in
 * a backend environment as it accesses native Node packages.
 *
 * @category Auth : Host
 * @category Client
 */
export class BackendAuthClient<
    DatabaseUser extends AnyObject,
    UserId extends string | number,
    AssumedUserParams extends AnyObject = EmptyObject,
    CsrfHeaderName extends string = AuthHeaderName.CsrfToken,
> {
    protected cachedParsedJwtKeys: Record<string, Readonly<JwtKeys>> = {};

    constructor(
        protected readonly config: BackendAuthClientConfig<
            DatabaseUser,
            UserId,
            AssumedUserParams,
            CsrfHeaderName
        >,
    ) {}

    /** Get all the parameters used for cookie generation. */
    protected async getCookieParams({
        isSignUpCookie,
    }: {
        /**
         * Set this to `true` when we are setting the initial cookie right after a user signs up.
         * This allows them to auto-authorize when they verify their email address.
         *
         * This should only be set to `true` when a new user is signing up.
         */
        isSignUpCookie?: boolean | undefined;
    }): Promise<Readonly<CookieParams>> {
        return {
            cookieDuration: this.config.userSessionIdleTimeout || defaultSessionIdleTimeout,
            hostOrigin: this.config.serviceOrigin,
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
    }: {
        userIdResult: Readonly<UserIdResult<UserId>>;
    }): Promise<OutgoingHttpHeaders | undefined> {
        const now = getNowInUtcTimezone();

        /** Double check that the JWT hasn't already expired. */
        const isExpiredAlready = isDateAfter({
            fullDate: now,
            relativeTo: userIdResult.jwtExpiration,
        });

        if (isExpiredAlready) {
            return undefined;
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
        const isRefreshReady = isDateAfter({
            fullDate: calculateRelativeDate(
                now,
                this.config.sessionRefreshThreshold || {
                    minutes: 5,
                },
            ),
            relativeTo: userIdResult.jwtExpiration,
        });

        if (isRefreshReady) {
            return this.createLoginHeaders({
                requestHeaders: {},
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
            headers[this.config.overrides?.assumedUserHeaderName || AuthHeaderName.AssumedUser],
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
    }: {
        requestHeaders: IncomingHttpHeaders;
        isSignUpCookie?: boolean | undefined;
    }): Promise<GetUserResult<DatabaseUser> | undefined> {
        const userIdResult = await extractUserIdFromRequestHeaders<UserId>(
            requestHeaders,
            await this.getJwtParams(),
            isSignUpCookie ? AuthCookieName.SignUp : AuthCookieName.Auth,
            this.config.overrides,
        );
        if (!userIdResult) {
            return undefined;
        }

        const user = await this.getDatabaseUser({
            userId: userIdResult.userId,
            assumingUser: undefined,
            isSignUpCookie: !!isSignUpCookie,
        });

        if (!user) {
            return undefined;
        }

        const assumedUser = await this.getAssumedUser({
            headers: requestHeaders,
            user,
        });

        const cookieRefreshHeaders =
            (await this.createCookieRefreshHeaders({
                userIdResult,
            })) || {};

        return {
            user: assumedUser || user,
            isAssumed: !!assumedUser,
            responseHeaders: cookieRefreshHeaders,
        };
    }

    /**
     * Get all the JWT params used when creating the auth cookie, in case you need them for
     * something else too.
     */
    public async getJwtParams(): Promise<Readonly<CreateJwtParams>> {
        const rawJwtKeys = await this.config.getJetKeys();

        const cacheKey = JSON.stringify(rawJwtKeys);

        const cachedParsedKeys = this.cachedParsedJwtKeys[cacheKey];
        const parsedKeys = cachedParsedKeys ?? (await parseJwtKeys(rawJwtKeys));

        if (!cachedParsedKeys) {
            this.cachedParsedJwtKeys = {[cacheKey]: parsedKeys};
        }
        return {
            jwtKeys: parsedKeys,
            audience: 'server-context',
            issuer: 'server-auth',
            jwtDuration: this.config.userSessionIdleTimeout || defaultSessionIdleTimeout,
        };
    }

    /** Use these headers to log out the user. */
    public async createLogoutHeaders(
        params: RequireExactlyOne<{
            allCookies: true;
            isSignUpCookie: boolean;
        }>,
    ): Promise<
        Partial<Record<CsrfHeaderName, string>> & {
            'set-cookie': string[];
        }
    > {
        const signUpCookieHeaders =
            params.allCookies || params.isSignUpCookie
                ? (generateLogoutHeaders(
                      await this.getCookieParams({
                          isSignUpCookie: true,
                      }),
                      this.config.overrides,
                  ) satisfies Record<CsrfHeaderName, string>)
                : undefined;
        const authCookieHeaders =
            params.allCookies || !params.isSignUpCookie
                ? (generateLogoutHeaders(
                      await this.getCookieParams({
                          isSignUpCookie: false,
                      }),
                      this.config.overrides,
                  ) satisfies Record<CsrfHeaderName, string>)
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
        } as Record<CsrfHeaderName, string>;

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
    }): Promise<
        Pick<RequiredAndNotNull<OutgoingHttpHeaders>, 'set-cookie'> & Record<CsrfHeaderName, string>
    > {
        const oppositeCookieName = isSignUpCookie ? AuthCookieName.Auth : AuthCookieName.SignUp;
        const hasExistingOppositeCookie = requestHeaders.cookie?.includes(`${oppositeCookieName}=`);

        const discardOppositeCookieHeaders = hasExistingOppositeCookie
            ? generateLogoutHeaders(
                  await this.getCookieParams({
                      isSignUpCookie: !isSignUpCookie,
                  }),
                  this.config.overrides,
              )
            : undefined;

        const newCookieHeaders = await generateSuccessfulLoginHeaders(
            userId,
            await this.getCookieParams({
                isSignUpCookie,
            }),
            this.config.overrides,
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

    /**
     * @deprecated This only half authenticates the user. It should only be used in circumstances
     *   where JavaScript cannot be used to attach the CSRF token header to the request (like when
     *   opening a PDF file). Use `.getSecureUser()` instead, whenever possible.
     */
    public async getInsecureUser({
        headers,
    }: {
        headers: IncomingHttpHeaders;
    }): Promise<GetUserResult<DatabaseUser> | undefined> {
        // eslint-disable-next-line @typescript-eslint/no-deprecated
        const userIdResult = await insecureExtractUserIdFromCookieAlone<UserId>(
            headers,
            await this.getJwtParams(),
            AuthCookieName.Auth,
        );

        if (!userIdResult) {
            return undefined;
        }

        const user = await this.getDatabaseUser({
            isSignUpCookie: false,
            userId: userIdResult.userId,
            assumingUser: undefined,
        });

        if (!user) {
            return undefined;
        }

        return {
            user,
            isAssumed: false,
            responseHeaders:
                (await this.createCookieRefreshHeaders({
                    userIdResult,
                })) || {},
        };
    }
}
