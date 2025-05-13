import {
    type AnyObject,
    mergeDefinedProperties,
    type PartialWithUndefined,
} from '@augment-vir/common';
import {argon2id, argon2Verify, type IArgon2Options} from 'hash-wasm';

/**
 * Default value for {@link HashPasswordOptions}.
 *
 * @category Internal
 */
export const defaultHashOptions: HashPasswordOptions = {
    hashLength: 32,
    iterations: 256,
    memorySize: 512,
    parallelism: 1,
};

/**
 * Options for {@link hashPassword}.
 *
 * @category Internal
 */
export type HashPasswordOptions = PartialWithUndefined<
    Omit<IArgon2Options, 'outputType' | 'salt' | 'password' | 'secret'>
>;

/**
 * Hashes a password using the Argon2id algorithm so passwords don't need to be stored in plain
 * text. The output of this function is safe to store in a database for future credential
 * comparisons.
 *
 * @category Auth : Host
 * @returns The hashed password.
 * @see https://en.wikipedia.org/wiki/Argon2
 */
export async function hashPassword(
    password: string,
    options: HashPasswordOptions = {},
): Promise<string> {
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));

    return await argon2id(
        mergeDefinedProperties<AnyObject>(defaultHashOptions, options, {
            outputType: 'encoded',
            password: password.normalize(),
            salt,
        }) as IArgon2Options,
    );
}

/**
 * A utility that provides more accurate string byte size than doing `string.length`.
 *
 * @category Internal
 */
export function getByteLength(input: string): number {
    return new Blob([input]).size;
}

/**
 * Checks if the given password is a match by comparing it to the previously computed and stored
 * hash.
 *
 * @category Auth : Host
 */
export async function doesPasswordMatchHash({
    password,
    hash,
}: {
    /** The password entered by the user in their login attempt. */
    password: string;
    /** The stored password hash for that user. */
    hash: string;
}): Promise<boolean> {
    return await argon2Verify({
        hash,
        password,
    });
}
