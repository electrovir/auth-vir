import {check} from '@augment-vir/assert';

/**
 * All custom headers used by auth-vir.
 *
 * @category Internal
 */
export enum AuthHeaderName {
    AssumedUser = 'assumed-user',
    /**
     * Used to track if the current user is signed in only with a sign-up cookie, which prevents us
     * from prematurely wiping their CSRF token.
     */
    IsSignUpAuth = 'is-sign-up-auth',
}

/**
 * Merges multiple header values into a single array of header values.
 *
 * @category Internal
 */
export function mergeHeaderValues(...values: (string | string[] | undefined)[]): string[] {
    const finalHeaderValues: string[] = [];

    values.forEach((value) => {
        if (check.isArray(value)) {
            finalHeaderValues.push(...value);
        } else if (check.isString(value)) {
            finalHeaderValues.push(value);
        }
    });

    return finalHeaderValues;
}
