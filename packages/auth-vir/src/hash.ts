import {bcrypt, bcryptVerify} from 'hash-wasm';

/**
 * Hashes a password using the bcrypt algorithm so passwords don't need to be stored in plain text.
 * The output of this function is safe to store in a database for future credential comparisons.
 *
 * @category Auth : Host
 * @returns `undefined` if the password is too long. Otherwise, the hashed output.
 * @see https://wikipedia.org/wiki/Bcrypt
 */
export async function hashPassword(password: string): Promise<undefined | string> {
    if (willHashTruncate(password)) {
        return undefined;
    }

    const salt = new Uint8Array(16);
    globalThis.crypto.getRandomValues(salt);

    return await bcrypt({
        costFactor: 10,
        password: password.normalize(),
        salt,
    });
}

/**
 * Checks if the given string will be truncated when passed through {@link hashPassword}. Passwords
 * longer than this should not be accepted.
 *
 * @category Internal
 */
export function willHashTruncate(input: string): boolean {
    return getByteLength(input) > 72;
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
 * Checks if the given password is a match by comparing it to its previously computed and stored
 * hash.
 *
 * @category Auth : Host
 */
export async function compareHash({
    password,
    hash,
}: {
    /** The password entered by the user in their login attempt. */
    password: string;
    /** The stored password hash for that user. */
    hash: string;
}): Promise<boolean> {
    return await bcryptVerify({
        hash,
        password,
    });
}
