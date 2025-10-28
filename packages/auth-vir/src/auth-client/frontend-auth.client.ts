import {
    createBlockingInterval,
    HttpStatus,
    type JsonCompatibleObject,
    type MaybePromise,
    type PartialWithUndefined,
    type SelectFrom,
} from '@augment-vir/common';
import {type AnyDuration} from 'date-vir';
import {isPageActive} from 'page-active';
import {type EmptyObject} from 'type-fest';
import {
    CsrfTokenFailureReason,
    extractCsrfTokenHeader,
    getCurrentCsrfToken,
    storeCsrfToken,
    wipeCurrentCsrfToken,
} from '../csrf-token.js';
import {AuthHeaderName} from '../headers.js';

/**
 * Config for {@link FrontendAuthClient}.
 *
 * @category Internal
 */
export type FrontendAuthClientConfig = PartialWithUndefined<{
    /**
     * Determine if the current user can assume the identity of another user. If this is not
     * defined, all users will be blocked from assuming other user identities.
     */
    canAssumeUser: () => MaybePromise<boolean>;
    /** Called whenever the current user becomes unauthorized and their CSRF token is wiped. */
    authClearedCallback: () => MaybePromise<void>;

    /**
     * Performs automatic checks on an interval to see if the user is still authenticated. Omit this
     * to turn off automatic checks.
     */
    checkUser: {
        /**
         * Get a response from the backend to see if the user is still authenticated. If the
         * response returns a non-authorized status, the user is wiped. Any other status is
         * ignored.
         *
         * If the user is not currently authorized, this should return `undefined` to prevent
         * unnecessary network traffic.
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
        /** @default {minutes: 1} */
        interval?: AnyDuration | undefined;
    };

    overrides: PartialWithUndefined<{
        localStorage: Pick<Storage, 'setItem' | 'removeItem' | 'getItem'>;
        csrfHeaderName: string;
        assumedUserHeaderName: string;
    }>;
}>;

/**
 * An auth client for sending and validating client requests to a backend. This should only be used
 * in a frontend environment as it accesses native browser APIs.
 *
 * @category Auth : Client
 * @category Client
 */
export class FrontendAuthClient<AssumedUserParams extends JsonCompatibleObject = EmptyObject> {
    protected userCheckInterval: undefined | ReturnType<typeof createBlockingInterval>;

    constructor(protected readonly config: FrontendAuthClientConfig = {}) {
        if (config.checkUser) {
            this.userCheckInterval = createBlockingInterval(
                async () => {
                    if (!isPageActive()) {
                        /** Do not refresh the user when the page is inactive. */
                        return;
                    }
                    const response = await config.checkUser?.performCheck();

                    if (response) {
                        await this.verifyResponseAuth({
                            status: response.status,
                        });
                    }
                },
                config.checkUser.interval || {minutes: 1},
            );
        }
    }

    /**
     * Destroys the client and performs all necessary cleanup (like clearing the user check
     * interval).
     */
    public destroy() {
        this.userCheckInterval?.clearInterval();
    }

    /** Wraps {@link getCurrentCsrfToken} to automatically handle wiping an invalid CSRF token. */
    public async getCurrentCsrfToken(): Promise<string | undefined> {
        const csrfTokenResult = getCurrentCsrfToken(this.config.overrides);

        if (
            csrfTokenResult.failure &&
            csrfTokenResult.failure !== CsrfTokenFailureReason.DoesNotExist
        ) {
            await this.logout();
            return undefined;
        } else {
            return csrfTokenResult.csrfToken?.token;
        }
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
        const storageKey =
            this.config.overrides?.assumedUserHeaderName || AuthHeaderName.AssumedUser;

        if (!assumedUserParams) {
            localStorage.removeItem(storageKey);
            return true;
        }

        if (!(await this.config.canAssumeUser?.())) {
            return false;
        }

        localStorage.setItem(storageKey, JSON.stringify(assumedUserParams));

        return true;
    }

    /** Gets the assumed user params stored in local storage, if any. */
    public getAssumedUser(): AssumedUserParams | undefined {
        const rawValue = (this.config.overrides?.localStorage || globalThis.localStorage).getItem(
            this.config.overrides?.assumedUserHeaderName || AuthHeaderName.AssumedUser,
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
    public async createAuthenticatedRequestInit(): Promise<RequestInit> {
        const csrfToken = await this.getCurrentCsrfToken();

        const assumedUser = this.getAssumedUser();
        const headers: HeadersInit = {
            ...(csrfToken
                ? {
                      [AuthHeaderName.CsrfToken]: csrfToken,
                  }
                : {}),
            ...(assumedUser
                ? {
                      [this.config.overrides?.assumedUserHeaderName || AuthHeaderName.AssumedUser]:
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
        wipeCurrentCsrfToken(this.config.overrides);
    }

    /**
     * Use to handle a login response. Automatically stores the CSRF token.
     *
     * @throws Error if the login response failed.
     * @throws Error if the login response has an invalid CSRF token.
     */
    public async handleLoginResponse(
        response: Readonly<
            SelectFrom<
                Response,
                {
                    headers: true;
                    ok: true;
                }
            >
        >,
    ): Promise<void> {
        if (!response.ok) {
            await this.logout();
            throw new Error('Login response failed.');
        }

        const {csrfToken} = extractCsrfTokenHeader(response, this.config.overrides);

        if (!csrfToken) {
            await this.logout();
            throw new Error('Did not receive any CSRF token.');
        }

        storeCsrfToken(csrfToken, this.config.overrides);
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

        /** If the response has a new CSRF token, store it. */
        const {csrfToken} = extractCsrfTokenHeader(response, this.config.overrides);
        if (csrfToken) {
            storeCsrfToken(csrfToken, this.config.overrides);
        }

        return true;
    }
}
