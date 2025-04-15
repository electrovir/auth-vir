import {assertWrap} from '@augment-vir/assert';
import {base64url} from 'jose';

/**
 * The keys required to sign and encrypt the JWT in their raw form for storage in a secure secrets
 * database (such as AWS Secrets Manager) for later parsing by {@link parseJwtKeys}.
 *
 * These keys should be kept secret and never shared with any frontend, client, etc.
 *
 * @category Internal
 */
export type RawJwtKeys = Readonly<{
    encryptionKey: string;
    signingKey: string;
}>;

/**
 * The keys required to sign and encrypt the JWT.
 *
 * These keys should be kept secret and never shared with any frontend, client, etc.
 *
 * @category Internal
 */
export type JwtKeys = Readonly<{
    /**
     * Encryption key for JWTs. This is a Uint8Array because `EncryptJWT.encrypt` does not support
     * `CryptoKey` for our chosen encryption algorithm.
     */
    encryptionKey: Readonly<Uint8Array>;
    /** Signing key for JWTs. */
    signingKey: Readonly<CryptoKey>;
}>;

const signingKeyOptions: [HmacKeyGenParams, boolean, ReadonlyArray<KeyUsage>] = [
    {
        name: 'HMAC',
        hash: 'SHA-512',
    },
    true,
    [
        'sign',
        'verify',
    ],
];

/**
 * Generate fresh and serialized JWT signing and encryption keys. These should be stored in a secure
 * secrets database (such as AWS Secrets Manager) for later parsing by {@link parseJwtKeys}.
 *
 * These keys should be kept secret and never shared with any frontend, client, etc.
 *
 * @category Keys
 */
export async function generateNewJwtKeys(): Promise<RawJwtKeys> {
    return {
        encryptionKey: assertWrap.isDefined(
            (
                await globalThis.crypto.subtle.exportKey(
                    'jwk',
                    await globalThis.crypto.subtle.generateKey(
                        {
                            name: 'AES-GCM',
                            length: 256,
                        },
                        true,
                        [
                            'encrypt',
                            'decrypt',
                        ],
                    ),
                )
            ).k,
        ),
        signingKey: assertWrap.isDefined(
            (
                await globalThis.crypto.subtle.exportKey(
                    'jwk',
                    await globalThis.crypto.subtle.generateKey(...signingKeyOptions),
                )
            ).k,
        ),
    };
}

/**
 * Parses an instance of {@link RawJwtKeys} and produces the final {@link JwtKeys} object required by
 * all authentication functionality.
 *
 * @category Keys
 */
export async function parseJwtKeys(rawKeys: Readonly<RawJwtKeys>): Promise<Readonly<JwtKeys>> {
    if (!rawKeys.encryptionKey) {
        throw new Error('JWT encryption key is empty');
    } else if (!rawKeys.signingKey) {
        throw new Error('JWT signing key is empty');
    }
    return {
        encryptionKey: base64url.decode(rawKeys.encryptionKey),
        signingKey: await crypto.subtle.importKey(
            'jwk',
            {
                k: rawKeys.signingKey,
                alg: 'HS512',
                ext: signingKeyOptions[1],
                key_ops: [...signingKeyOptions[2]],
                kty: 'oct',
            },
            ...signingKeyOptions,
        ),
    };
}
