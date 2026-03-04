import {checkValidShape, defineShape, optionalShape, unionShape} from 'object-shape-tester';
import {type generateCsrfToken} from '../csrf-token.js';
import {
    createJwt,
    type CreateJwtParams,
    type ParsedJwt,
    parseJwt,
    type ParseJwtParams,
} from './jwt.js';

/**
 * Shape definition and source of truth for {@link JwtUserData}.
 *
 * @category Internal
 */
export const userJwtDataShape = defineShape({
    /** The id from your database of the user you're authenticating. */
    userId: unionShape('', -1),
    /**
     * CSRF token. This can be any cryptographically secure randomized string.
     *
     * Consider using {@link generateCsrfToken} to generate this.
     */
    csrfToken: '',
    /**
     * Unix timestamp (in milliseconds) when the session was originally started. This is used to
     * enforce the max session duration. If not present, the session is considered to have started
     * when the JWT was issued.
     */
    sessionStartedAt: optionalShape(0, {
        alsoUndefined: true,
    }),
});

/**
 * Data required for user JWTs.
 *
 * @category Internal
 */
export type JwtUserData = typeof userJwtDataShape.runtimeType;

/**
 * Creates a new signed and encrypted {@link JwtUserData} when a client (frontend) successfully
 * authenticates with the host (backend). This is used by host (backend) code to establish a new
 * user session. The output of this function should be sent to the client (frontend) for storage.
 *
 * @category Internal
 */
export async function createUserJwt(
    data: Readonly<JwtUserData>,
    params: Readonly<CreateJwtParams>,
): Promise<string> {
    return await createJwt(data, params);
}

/**
 * Parses a {@link JwtUserData} generated from {@link createUserJwt}. This should be used on the host
 * (backend) to a client (frontend) request. Do not use this function in client (frontend) code: it
 * requires JWT signing keys which should not be shared with any client (frontend).
 *
 * @category Internal
 */
export async function parseUserJwt(
    encryptedJwt: string,
    params: Readonly<ParseJwtParams>,
): Promise<ParsedJwt<JwtUserData> | undefined> {
    const {data, jwtExpiration, jwtIssuedAt} = await parseJwt(encryptedJwt, params);

    if (!checkValidShape(data, userJwtDataShape)) {
        throw new TypeError('Verified jwt has wrong data.');
    }

    return {
        data,
        jwtExpiration,
        jwtIssuedAt,
    };
}
