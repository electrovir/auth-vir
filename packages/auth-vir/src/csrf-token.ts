import {randomString} from '@augment-vir/common';

/**
 * Generates a random, cryptographically secure CSRF token.
 *
 * @category Internal
 */
export function generateCsrfToken(): string {
    return randomString(256);
}
