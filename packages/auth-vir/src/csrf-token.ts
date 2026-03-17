import {randomString, type PartialWithUndefined, type SelectFrom} from '@augment-vir/common';
import {type AnyDuration} from 'date-vir';
import {type RequireExactlyOne} from 'type-fest';
import {getDefaultCsrfTokenStore, type CsrfTokenStore} from './csrf-token-store.js';

/**
 * Default allowed clock skew for JWT expiration checks. Accounts for differences between server and
 * client clocks.
 *
 * @category Internal
 * @default {minutes: 5}
 */
export const defaultAllowedClockSkew: Readonly<AnyDuration> = {
    minutes: 5,
};

/**
 * Generates a random, cryptographically secure CSRF token string.
 *
 * @category Internal
 */
export function generateCsrfToken(): string {
    return randomString(256);
}

/**
 * Options for specifying the CSRF token header name.
 *
 * @category Auth : Client
 * @category Auth : Host
 */
export type CsrfHeaderNameOption = RequireExactlyOne<{
    /** Prefix used to generate the header name: `${prefix}-auth-vir-csrf-token`. */
    csrfHeaderPrefix: string;
    /** Overrides the entire CSRF header name. */
    csrfHeaderName: string;
}>;

/**
 * Resolves a {@link CsrfHeaderNameOption} to the actual header name string.
 *
 * @category Auth : Client
 * @category Auth : Host
 */
export function resolveCsrfHeaderName(option: Readonly<CsrfHeaderNameOption>): string {
    if ('csrfHeaderName' in option && option.csrfHeaderName) {
        return option.csrfHeaderName;
    } else {
        return [
            option.csrfHeaderPrefix,
            'auth-vir',
            'csrf-token',
        ].join('-');
    }
}

/**
 * Extract the CSRF token header from a response.
 *
 * @category Auth : Client
 */
export function extractCsrfTokenHeader(
    response: Readonly<PartialWithUndefined<SelectFrom<Response, {headers: true}>>>,
    csrfHeaderNameOption: Readonly<CsrfHeaderNameOption>,
): string | undefined {
    const csrfTokenHeaderName = resolveCsrfHeaderName(csrfHeaderNameOption);

    return response.headers?.get(csrfTokenHeaderName) || undefined;
}

/**
 * Stores the given CSRF token into IndexedDB.
 *
 * @category Auth : Client
 */
export async function storeCsrfToken(
    csrfToken: string,
    options: Readonly<CsrfHeaderNameOption> &
        PartialWithUndefined<{
            /**
             * Allows mocking or overriding the default CSRF token store.
             *
             * @default getDefaultCsrfTokenStore()
             */
            csrfTokenStore: CsrfTokenStore;
        }>,
): Promise<void> {
    await (options.csrfTokenStore || (await getDefaultCsrfTokenStore())).setCsrfToken(csrfToken);
}

/**
 * Used in client (frontend) code to retrieve the current CSRF token in order to send it with
 * requests to the host (backend).
 *
 * @category Auth : Client
 */
export async function getCurrentCsrfToken(
    options: Readonly<CsrfHeaderNameOption> &
        PartialWithUndefined<{
            /**
             * Allows mocking or overriding the default CSRF token store.
             *
             * @default getDefaultCsrfTokenStore()
             */
            csrfTokenStore: CsrfTokenStore;
        }>,
): Promise<string | undefined> {
    return (
        (await (options.csrfTokenStore || (await getDefaultCsrfTokenStore())).getCsrfToken()) ||
        undefined
    );
}

/**
 * Wipes the current stored CSRF token. This should be used by client (frontend) code to react to a
 * session timeout.
 *
 * @category Auth : Client
 */
export async function wipeCurrentCsrfToken(
    options: Readonly<CsrfHeaderNameOption> &
        PartialWithUndefined<{
            /**
             * Allows mocking or overriding the default CSRF token store.
             *
             * @default getDefaultCsrfTokenStore()
             */
            csrfTokenStore: CsrfTokenStore;
        }>,
): Promise<void> {
    await (options.csrfTokenStore || (await getDefaultCsrfTokenStore())).deleteCsrfToken();
}
