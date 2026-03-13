import {
    randomString,
    wrapInTry,
    type PartialWithUndefined,
    type SelectFrom,
} from '@augment-vir/common';
import {
    calculateRelativeDate,
    fullDateShape,
    getNowInUtcTimezone,
    isDateAfter,
    type AnyDuration,
} from 'date-vir';
import {defineShape, parseJsonWithShape} from 'object-shape-tester';
import {type RequireExactlyOne} from 'type-fest';
import {getDefaultCsrfTokenStore, type CsrfTokenStore} from './csrf-token-store.js';

/**
 * Shape definition for {@link CsrfToken}.
 *
 * @category Internal
 */
export const csrfTokenShape = defineShape({
    token: '',
    expiration: fullDateShape,
});

/**
 * A cryptographically CSRF token with expiration date.
 *
 * @category Internal
 */
export type CsrfToken = typeof csrfTokenShape.runtimeType;

/**
 * Default allowed clock skew for CSRF token expiration checks. Accounts for differences between
 * server and client clocks when checking token expiration.
 *
 * @category Internal
 * @default {minutes: 5}
 */
export const defaultAllowedClockSkew: Readonly<AnyDuration> = {
    minutes: 5,
};

/**
 * Generates a random, cryptographically secure CSRF token.
 *
 * @category Internal
 */
export function generateCsrfToken(
    /** How long the CSRF token is valid for. */
    duration: Readonly<AnyDuration>,
): CsrfToken {
    return {
        token: randomString(256),
        expiration: calculateRelativeDate(getNowInUtcTimezone(), duration),
    };
}

/**
 * CSRF token failure reasons for {@link GetCsrfTokenResult}.
 *
 * @category Internal
 */
export enum CsrfTokenFailureReason {
    /** No CSRF token was found. */
    DoesNotExist = 'does-not-exist',
    /** A CSRF token was found but parsing it failed. */
    ParseFailed = 'parse-failed',
    /** A CSRF token was found and parsed but is expired. */
    Expired = 'expired',
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
 * Output from {@link getCurrentCsrfToken}.
 *
 * @category Internal
 */
export type GetCsrfTokenResult = RequireExactlyOne<{
    csrfToken: Readonly<CsrfToken>;
    failure: CsrfTokenFailureReason;
}>;

/**
 * Extract the CSRF token header from a response.
 *
 * @category Auth : Client
 */
export function extractCsrfTokenHeader(
    response: Readonly<PartialWithUndefined<SelectFrom<Response, {headers: true}>>>,
    csrfHeaderNameOption: Readonly<CsrfHeaderNameOption>,
    options?: PartialWithUndefined<{
        /**
         * Allowed clock skew tolerance for CSRF token expiration checks.
         *
         * @default {minutes: 5}
         */
        allowedClockSkew: Readonly<AnyDuration>;
    }>,
): Readonly<GetCsrfTokenResult> {
    const csrfTokenHeaderName = resolveCsrfHeaderName(csrfHeaderNameOption);

    const rawCsrfToken = response.headers?.get(csrfTokenHeaderName);

    return parseCsrfToken(rawCsrfToken, options);
}

/**
 * Stores the given CSRF token into IndexedDB.
 *
 * @category Auth : Client
 */
export async function storeCsrfToken(
    csrfToken: Readonly<CsrfToken>,
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
    await (options.csrfTokenStore || (await getDefaultCsrfTokenStore())).setCsrfToken(
        JSON.stringify(csrfToken),
    );
}

/**
 * Parse a raw CSRF token JSON string.
 *
 * @category Internal
 */
export function parseCsrfToken(
    value: string | undefined | null,
    options?: PartialWithUndefined<{
        /**
         * Allowed clock skew tolerance for CSRF token expiration checks. Accounts for differences
         * between server and client clocks.
         *
         * @default {minutes: 5}
         */
        allowedClockSkew: Readonly<AnyDuration>;
    }>,
): Readonly<GetCsrfTokenResult> {
    if (!value) {
        return {
            failure: CsrfTokenFailureReason.DoesNotExist,
        };
    }

    const csrfToken: CsrfToken | undefined = wrapInTry(
        () =>
            parseJsonWithShape(value, csrfTokenShape, {
                /** For forwards / backwards compatibility. */
                allowExtraKeys: true,
            }),
        {
            fallbackValue: undefined,
        },
    );

    if (!csrfToken) {
        return {
            failure: CsrfTokenFailureReason.ParseFailed,
        };
    }

    const effectiveExpiration = calculateRelativeDate(
        csrfToken.expiration,
        options?.allowedClockSkew || defaultAllowedClockSkew,
    );

    if (
        isDateAfter({
            fullDate: getNowInUtcTimezone(),
            relativeTo: effectiveExpiration,
        })
    ) {
        return {
            failure: CsrfTokenFailureReason.Expired,
        };
    }

    return {
        csrfToken,
    };
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
            /**
             * Allowed clock skew tolerance for CSRF token expiration checks.
             *
             * @default {minutes: 5}
             */
            allowedClockSkew: Readonly<AnyDuration>;
        }>,
): Promise<Readonly<GetCsrfTokenResult>> {
    const rawCsrfToken: string | undefined =
        (await (options.csrfTokenStore || (await getDefaultCsrfTokenStore())).getCsrfToken()) ||
        undefined;

    return parseCsrfToken(rawCsrfToken, options);
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
