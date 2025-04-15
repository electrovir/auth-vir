import {defineShape, isValidShape} from 'object-shape-tester';
import {createJwt, CreateJwtParams, parseJwt, ParseJwtParams} from './jwt.js';

/**
 * Shape definition and source of truth for {@link UserJwtData}.
 *
 * @category Internal
 */
export const userJwtDataShape = defineShape({
    userId: '',
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
 * @category Auth : Host
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
 * @category Auth : Host
 */
export async function parseUserJwt(
    encryptedJwt: string,
    params: Readonly<ParseJwtParams>,
): Promise<UserJwtData | undefined> {
    const parsed = await parseJwt(encryptedJwt, params);

    if (!isValidShape(parsed, userJwtDataShape)) {
        throw new TypeError('Verified jwt has wrong data.');
    }

    return parsed;
}
