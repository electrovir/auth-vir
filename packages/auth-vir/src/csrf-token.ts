import {randomString} from '@augment-vir/common';

/**
 * Name of the header attached to responses that stores the CSRF token value.
 *
 * @category Internal
 */
export const csrfTokenHeaderName = 'csrf-token';

/**
 * Generates a random, cryptographically secure CSRF token.
 *
 * @category Internal
 */
export function generateCsrfToken(): string {
    return randomString(128);
}
