import {check} from '@augment-vir/assert';
import type {AnyObject, PartialWithUndefined} from '@augment-vir/common';
import {
    calculateRelativeDate,
    createFullDateInUserTimezone,
    getNowInUtcTimezone,
    toTimestamp,
    type AnyDuration,
    type DateLike,
} from 'date-vir';
import {EncryptJWT, jwtDecrypt, jwtVerify, SignJWT} from 'jose';
import {JwtKeys} from './jwt-keys.js';

const encryptionProtectedHeader = {alg: 'dir', enc: 'A256GCM'};
const signingProtectedHeader = {alg: 'HS512'};

/**
 * Params for {@link createJwt}.
 *
 * @category Internal
 */
export type CreateJwtParams = Readonly<{
    /**
     * The keys required to sign and encrypt the JWT.
     *
     * These keys should be kept secret and never shared with any frontend, client, etc.
     */
    jwtKeys: Readonly<JwtKeys>;
    /**
     * The name of the company, the name of the service, or the URL to the service that originally
     * issued the JWT. The same value must be used when creating and parsing a JWT or the parse will
     * fail.
     *
     * This name can be anything you want.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
     */
    issuer: string;
    /**
     * The arbitrary name or URL of the client intended to consume the JWT. The host and client must
     * both know this name in order for the token to be signed and read correctly.
     *
     * This name can be anything you want.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
     */
    audience: string;
    /**
     * The duration until the JWT expires.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
     */
    jwtDuration: Readonly<AnyDuration>;
}> &
    Readonly<
        PartialWithUndefined<{
            /**
             * Set a custom issued at date.
             *
             * This should usually not be overridden.
             *
             * @default Date.now()
             * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
             */
            issuedAt: DateLike;
            /**
             * Set a custom date for when the JWT will become valid. The JWT will be considered
             * invalid and not be processed until this date.
             *
             * This should usually not be overridden.
             *
             * @default
             * none, the JWT will be immediately valid
             * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
             */
            notValidUntil: DateLike;
        }>
    >;

/**
 * Creates a signed and encrypted JWT that contains the given data.
 *
 * @category Internal
 */
export async function createJwt<JwtData extends AnyObject = AnyObject>(
    /** The data to be included in the JWT. */
    data: JwtData,
    params: Readonly<CreateJwtParams>,
): Promise<string> {
    const rawJwt = new SignJWT({data: data})
        .setProtectedHeader(signingProtectedHeader)
        .setIssuedAt(
            params.issuedAt
                ? toTimestamp(createFullDateInUserTimezone(params.issuedAt))
                : undefined,
        )
        .setIssuer(params.issuer)
        .setAudience(params.audience)
        .setExpirationTime(
            toTimestamp(calculateRelativeDate(getNowInUtcTimezone(), params.jwtDuration)),
        );

    if (params.notValidUntil) {
        rawJwt.setNotBefore(toTimestamp(createFullDateInUserTimezone(params.notValidUntil)));
    }

    const signedJwt = await rawJwt.sign(params.jwtKeys.signingKey);

    return await new EncryptJWT({jwt: signedJwt})
        .setProtectedHeader(encryptionProtectedHeader)
        .encrypt(params.jwtKeys.encryptionKey);
}

/**
 * Params for {@link parseJwt}.
 *
 * @category Internal
 */
export type ParseJwtParams = Readonly<Pick<CreateJwtParams, 'issuer' | 'audience' | 'jwtKeys'>>;

/**
 * Parse and extract all data from an encrypted and signed JWT.
 *
 * @category Internal
 * @throws Errors if the decryption, signature verification, or other JWT requirements fail
 */
export async function parseJwt<JwtData extends AnyObject = AnyObject>(
    encryptedJwt: string,
    params: Readonly<ParseJwtParams>,
): Promise<JwtData> {
    const decryptedJwt = await jwtDecrypt(encryptedJwt, params.jwtKeys.encryptionKey);

    if (!check.deepEquals(decryptedJwt.protectedHeader, encryptionProtectedHeader)) {
        throw new Error('Invalid encryption protected header.');
    } else if (!check.isString(decryptedJwt.payload.jwt)) {
        throw new TypeError('Decrypted jwt is not a string.');
    }

    const verifiedJwt = await jwtVerify(decryptedJwt.payload.jwt, params.jwtKeys.signingKey, {
        issuer: params.issuer,
        audience: params.audience,
        requiredClaims: [
            'iat',
            'aud',
            'iss',
        ],
    });

    if (!verifiedJwt.payload.iat || verifiedJwt.payload.iat * 1000 > Date.now()) {
        throw new Error('"iat" claim timestamp check failed');
    }

    const data = verifiedJwt.payload.data;

    if (!check.deepEquals(verifiedJwt.protectedHeader, signingProtectedHeader)) {
        throw new Error('Invalid signing protected header.');
    }

    return data as JwtData;
}
