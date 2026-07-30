import {
    type createBlockingInterval,
    type EmptyObject,
    HttpStatus,
    type JsonCompatibleObject,
    type MaybePromise,
    type PartialWithUndefined,
    type SelectFrom,
} from '@augment-vir/common';
import {type AnyDuration} from 'date-vir';
import {listenToActivity} from 'detect-activity';
import {
    type CsrfHeaderNameOption,
    getCurrentCsrfToken,
    resolveCsrfHeaderName,
} from '../csrf-token.js';
import {AuthHeaderName} from '../headers.js';

/**
 * Config for {@link FrontendAuthClient}.
 *
 * @category Internal
 */
export type FrontendAuthClientConfig = Readonly<{
    csrf: Readonly<CsrfHeaderNameOption>;
}> &
    PartialWithUndefined<{
        /**
         * Optional suffix appended to cookie names (e.g., `'staging'` produces
         * `auth-vir-csrf-staging`). When `undefined`, cookie names are unchanged.
         */
        cookieNameSuffix: string;
        /**
         * Determine if the current user can assume the identity of another user. If this is not
         * defined, all users will be blocked from assuming other user identities.
         */
        canAssumeUser: () => MaybePromise<boolean>;
        /** Called whenever the current user becomes unauthorized and their CSRF token is wiped. */
        authClearedCallback: () => MaybePromise<void>;

        /**
         * Performs automatic checks on an interval to see if the user is still authenticated. Omit
         * this to turn off automatic checks.
         */
        checkUser: {
            /**
             * Get a response from the backend to see if the user is still authenticated. If the
             * response returns a non-authorized status, the user is wiped. Any other status is
             * ignored.
             *
             * If the user is not currently authorized, this should return `undefined` to prevent
             * unnecessary network traffic.
             *
             * This will be called any time the user interacts with the page, debounced by the
             * adjacent `debounce` property.
             */
            performCheck: () => MaybePromise<
                | SelectFrom<
                      Response,
                      {
                          status: true;
                      }
                  >
                | undefined
            >;
            /**
             * Debounce for firing `performCheck`.
             *
             * @default {minutes: 1}
             */
            debounce?: AnyDuration | undefined;
        };
        /**
         * Overwrite the header name used for tracking is an admin is assuming the identity of
         * another user.
         */
        assumedUserHeaderName: string;

        overrides: PartialWithUndefined<{
            localStorage: SelectFrom<Storage, {setItem: true; removeItem: true; getItem: true}>;
        }>;
    }>;

/**
 * An auth client for sending and validating client requests to a backend. This should only be used
 * in a frontend environment as it accesses native browser APIs.
 *
 * @category Auth : Client
 * @category Clients
 */
export class FrontendAuthClient<AssumedUserParams extends JsonCompatibleObject = EmptyObject> {
    protected userCheckInterval: undefined | ReturnType<typeof createBlockingInterval>;
    /** Used to clean up the activity listener on `.destroy()`. */
    protected removeActivityListener: VoidFunction | undefined;

    constructor(protected readonly config: FrontendAuthClientConfig) {
        if (config.checkUser) {
            this.removeActivityListener = listenToActivity({
                listener: async () => {
                    const response = await config.checkUser?.performCheck();

                    if (response) {
                        await this.verifyResponseAuth({
                            status: response.status,
                        });
                    }
                },
                debounce: config.checkUser.debounce || {
                    minutes: 1,
                },
                fireImmediately: false,
            });
        }
    }

    /**
     * Destroys the client and performs all necessary cleanup (like clearing the user check
     * interval).
     */
    public destroy() {
        this.userCheckInterval?.clearInterval();
        this.removeActivityListener?.();
    }

    /**
     * Assume the given user. Pass `undefined` to wipe the currently assumed user.
     *
     * @returns Whether the assumed user setting or clearing succeeded or not.
     */
    public async assumeUser(
        assumedUserParams: Readonly<AssumedUserParams> | undefined,
    ): Promise<boolean> {
        const localStorage = this.config.overrides?.localStorage || globalThis.localStorage;
        const storageKey = this.config.assumedUserHeaderName || AuthHeaderName.AssumedUser;

        if (!assumedUserParams) {
            localStorage.removeItem(storageKey);
            return true;
        } else if (await this.config.canAssumeUser?.()) {
            localStorage.setItem(storageKey, JSON.stringify(assumedUserParams));

            return true;
        } else {
            return false;
        }
    }

    /** Gets the assumed user params stored in local storage, if any. */
    public getAssumedUser(): AssumedUserParams | undefined {
        const rawValue = (this.config.overrides?.localStorage || globalThis.localStorage).getItem(
            this.config.assumedUserHeaderName || AuthHeaderName.AssumedUser,
        );

        if (!rawValue) {
            return undefined;
        }
        try {
            return JSON.parse(rawValue);
        } catch {
            return undefined;
        }
    }

    /**
     * Creates a `RequestInit` object for the `fetch` API. If you have other request init options,
     * use [`mergeDeep` from
     * `@augment-vir/common`](https://electrovir.github.io/augment-vir/functions/mergeDeep.html) to
     * combine them with these.
     */
    public createAuthenticatedRequestInit(): RequestInit {
        const csrfToken = getCurrentCsrfToken(this.config.cookieNameSuffix);

        const assumedUser = this.getAssumedUser();
        const headers: HeadersInit = {
            ...(csrfToken
                ? {
                      [resolveCsrfHeaderName(this.config.csrf)]: csrfToken,
                  }
                : {}),
            ...(assumedUser
                ? {
                      [this.config.assumedUserHeaderName || AuthHeaderName.AssumedUser]:
                          JSON.stringify(assumedUser),
                  }
                : {}),
        };

        return {
            headers,
            credentials: 'include',
        };
    }

    /** Wipes the current user auth. */
    public async logout() {
        await this.config.authClearedCallback?.();
    }

    /**
     * Use to handle a login response. The CSRF token cookie is automatically stored by the browser
     * from the `Set-Cookie` response header.
     *
     * @throws Error if the login response failed.
     */
    public async handleLoginResponse(
        response: Readonly<SelectFrom<Response, {ok: true}>>,
    ): Promise<void> {
        if (!response.ok) {
            await this.logout();
            throw new Error('Login response failed.');
        }
    }

    /**
     * Use to verify _all_ responses received from the backend. Immediately logs the user out once
     * an unauthorized response is detected.
     *
     * @returns `true` if the auth is okay, `false` otherwise.
     */
    public async verifyResponseAuth(
        response: Readonly<
            PartialWithUndefined<
                SelectFrom<
                    Response,
                    {
                        status: true;
                        headers: true;
                    }
                >
            >
        >,
    ): Promise<boolean> {
        if (
            response.status === HttpStatus.Unauthorized &&
            !response.headers?.get(AuthHeaderName.IsSignUpAuth)
        ) {
            await this.logout();
            return false;
        }

        return true;
    }
}
