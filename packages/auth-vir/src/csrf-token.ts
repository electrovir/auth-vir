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
import {AuthHeaderName} from './headers.js';
import {authLog} from './log.js';

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
    overrides: PartialWithUndefined<{
        csrfHeaderName: string;
    }> = {},
): Readonly<GetCsrfTokenResult> {
    const csrfTokenHeaderName = overrides.csrfHeaderName || AuthHeaderName.CsrfToken;

    const rawCsrfToken = response.headers?.get(csrfTokenHeaderName);

    return parseCsrfToken(rawCsrfToken);
}

/**
 * Stores the given CSRF token into local storage.
 *
 * @category Auth : Client
 */
export function storeCsrfToken(
    csrfToken: Readonly<CsrfToken>,
    overrides: PartialWithUndefined<{
        /**
         * Allows mocking or overriding the global `localStorage`.
         *
         * @default globalThis.localStorage
         */
        localStorage: Pick<Storage, 'setItem' | 'removeItem'>;
        /** Override the default CSRF token header name. */
        csrfHeaderName: string;
    }> = {},
) {
    (overrides.localStorage || globalThis.localStorage).setItem(
        overrides.csrfHeaderName || AuthHeaderName.CsrfToken,
        JSON.stringify(csrfToken),
    );
}

/**
 * Parse a raw CSRF token JSON string.
 *
 * @category Internal
 */
export function parseCsrfToken(value: string | undefined | null): Readonly<GetCsrfTokenResult> {
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

    if (
        isDateAfter({
            fullDate: getNowInUtcTimezone(),
            relativeTo: csrfToken.expiration,
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
export function getCurrentCsrfToken(
    overrides: PartialWithUndefined<{
        /**
         * Allows mocking or overriding the global `localStorage`.
         *
         * @default globalThis.localStorage
         */
        localStorage: Pick<Storage, 'getItem'>;
        /** Override the default CSRF token header name. */
        csrfHeaderName: string;
    }> = {},
): Readonly<GetCsrfTokenResult> {
    const rawCsrfToken: string | undefined =
        (overrides.localStorage || globalThis.localStorage).getItem(
            overrides.csrfHeaderName || AuthHeaderName.CsrfToken,
        ) || undefined;

    return parseCsrfToken(rawCsrfToken);
}

/**
 * Wipes the current stored CSRF token. This should be used by client (frontend) code to logout a
 * user or react to a session timeout.
 *
 * @category Auth : Client
 */
export function wipeCurrentCsrfToken(
    overrides: PartialWithUndefined<{
        /**
         * Allows mocking or overriding the global `localStorage`.
         *
         * @default globalThis.localStorage
         */
        localStorage: Pick<Storage, 'removeItem'>;
        /** Override the default CSRF token header name. */
        csrfHeaderName: string;
    }> = {},
) {
    authLog('auth-vir: wipeCurrentCsrfToken called', new Error().stack);
    return (overrides.localStorage || globalThis.localStorage).removeItem(
        overrides.csrfHeaderName || AuthHeaderName.CsrfToken,
    );
}
