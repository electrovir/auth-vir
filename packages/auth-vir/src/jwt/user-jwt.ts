import {checkValidShape, defineShape} from 'object-shape-tester';
import {type generateCsrfToken} from '../csrf-token.js';
import {createJwt, type CreateJwtParams, parseJwt, type ParseJwtParams} from './jwt.js';

/**
 * Shape definition and source of truth for {@link UserJwtData}.
 *
 * @category Internal
 */
export const userJwtDataShape = defineShape({
    /** The id from your database of the user you're authenticating. */
    userId: '',
    /**
     * CSRF token. This can be any cryptographically secure randomized string.
     *
     * Consider using {@link generateCsrfToken} to generate this.
     */
    csrfToken: '',
});

/**
 * Data required for user JWTs.
 *
 * @category Internal
 */
export type UserJwtData = typeof userJwtDataShape.runtimeType;

/**
 * Creates a new signed and encrypted {@link UserJwtData} when a client (frontend) successfully
 * authenticates with the host (backend). This is used by host (backend) code to establish a new
 * user session. The output of this function should be sent to the client (frontend) for storage.
 *
 * @category Internal
 */
export async function createUserJwt(
    data: Readonly<UserJwtData>,
    params: Readonly<CreateJwtParams>,
): Promise<string> {
    return await createJwt(data, params);
}

/**
 * Parses a {@link UserJwtData} generated from {@link createUserJwt}. This should be used on the host
 * (backend) to a client (frontend) request. Do not use this function in client (frontend) code: it
 * requires JWT signing keys which should not be shared with any client (frontend).
 *
 * @category Internal
 */
export async function parseUserJwt(
    encryptedJwt: string,
    params: Readonly<ParseJwtParams>,
): Promise<UserJwtData | undefined> {
    const parsed = await parseJwt(encryptedJwt, params);

    if (!checkValidShape(parsed, userJwtDataShape)) {
        throw new TypeError('Verified jwt has wrong data.');
    }

    return parsed;
}
