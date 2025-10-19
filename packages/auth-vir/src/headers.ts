import {check} from '@augment-vir/assert';

/**
 * All custom headers used by auth-vir.
 *
 * @category Internal
 */
export enum AuthHeaderName {
    CsrfToken = 'csrf-token',
    AssumedUser = 'assumed-user',
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
