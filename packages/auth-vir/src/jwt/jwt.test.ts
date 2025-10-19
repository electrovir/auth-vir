import {assert, assertWrap} from '@augment-vir/assert';
import {wait} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {calculateRelativeDate, getNowInUtcTimezone, toTimestamp} from 'date-vir';
import {EncryptJWT, SignJWT} from 'jose';
import {generateNewJwtKeys, parseJwtKeys} from './jwt-keys.js';
import {createJwt, parseJwt} from './jwt.js';
import {mockJwtParams} from './jwt.mock.js';

describe(parseJwt.name, () => {
    it('fails if the signing protected header does not match', async () => {
        try {
            const overriddenSigningKey = await crypto.subtle.importKey(
                'jwk',
                {
                    k: assertWrap.isDefined(
                        (
                            await globalThis.crypto.subtle.exportKey(
                                'jwk',
                                await globalThis.crypto.subtle.generateKey(
                                    {
                                        name: 'HMAC',
                                        hash: 'SHA-384',
                                    },
                                    true,
                                    [
                                        'sign',
                                        'verify',
                                    ],
                                ),
                            )
                        ).k,
                    ),
                    alg: 'HS384',
                    ext: true,
                    key_ops: [
                        'sign',
                        'verify',
                    ],
                    kty: 'oct',
                },
                {
                    name: 'HMAC',
                    hash: 'SHA-384',
                },
                true,
                [
                    'sign',
                    'verify',
                ],
            );

            const jwtKeys = {
                ...(await parseJwtKeys(await generateNewJwtKeys())),
                signingKey: overriddenSigningKey,
            };

            const mockData = {some: 'data'};

            const jwt = await new EncryptJWT({
                jwt: await new SignJWT({data: mockData})
                    .setProtectedHeader({alg: 'HS384'})
                    .setIssuedAt()
                    .setIssuer(mockJwtParams.issuer)
                    .setAudience(mockJwtParams.audience)
                    .setExpirationTime(
                        toTimestamp(
                            calculateRelativeDate(getNowInUtcTimezone(), mockJwtParams.jwtDuration),
                        ),
                    )
                    .sign(jwtKeys.signingKey),
            })
                .setProtectedHeader({alg: 'dir', enc: 'A256GCM'})
                .encrypt(jwtKeys.encryptionKey);

            await assert.throws(
                () =>
                    parseJwt(jwt, {
                        ...mockJwtParams,
                        jwtKeys,
                    }),
                {
                    matchMessage: 'Invalid signing protected header',
                },
            );
        } catch (error) {
            console.error(error);
            throw error;
        }
    });
    it('fails if the encryption protected header does not match', async () => {
        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());
        const mockData = {some: 'data'};

        const jwt = await new EncryptJWT({
            jwt: await new SignJWT({data: mockData})
                .setProtectedHeader({alg: 'HS512'})
                .setIssuedAt()
                .setIssuer(mockJwtParams.issuer)
                .setAudience(mockJwtParams.audience)
                .setExpirationTime(
                    toTimestamp(
                        calculateRelativeDate(getNowInUtcTimezone(), mockJwtParams.jwtDuration),
                    ),
                )
                .sign(jwtKeys.signingKey),
        })
            .setProtectedHeader({alg: 'dir', enc: 'A128CBC-HS256'})
            .encrypt(jwtKeys.encryptionKey);

        await assert.throws(
            () =>
                parseJwt(jwt, {
                    ...mockJwtParams,
                    jwtKeys,
                }),
            {
                matchMessage: 'Invalid encryption protected header',
            },
        );
    });
    it('fails if the encrypted JWT is not a string', async () => {
        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        const jwt = await new EncryptJWT({
            jwt: 42,
        })
            .setProtectedHeader({alg: 'dir', enc: 'A256GCM'})
            .encrypt(jwtKeys.encryptionKey);

        await assert.throws(
            () =>
                parseJwt(jwt, {
                    ...mockJwtParams,
                    jwtKeys,
                }),
            {
                matchMessage: 'Decrypted jwt is not a string',
            },
        );
    });
    it('successfully parses a JWT', async () => {
        const mockData = {
            mock: 'data',
        };

        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        assert.deepEquals(
            (
                await parseJwt(
                    await createJwt(mockData, {
                        ...mockJwtParams,
                        jwtKeys,
                    }),
                    {
                        ...mockJwtParams,
                        jwtKeys,
                    },
                )
            ).data,
            mockData,
        );
    });
    it('fails to parse a JWT with issued at in the future', async () => {
        const mockData = {
            mock: 'data',
        };

        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        await assert.throws(
            async () =>
                await parseJwt(
                    await createJwt(mockData, {
                        ...mockJwtParams,
                        jwtKeys,
                        issuedAt: calculateRelativeDate(getNowInUtcTimezone(), {days: 10}),
                    }),
                    {
                        ...mockJwtParams,
                        jwtKeys,
                    },
                ),
            {
                matchMessage: '"iat" claim timestamp check failed',
            },
        );
    });
    it('fails to parse an expired JWT', async () => {
        const mockData = {
            mock: 'data',
        };

        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        const jwt = await createJwt(mockData, {
            ...mockJwtParams,
            jwtKeys,
            jwtDuration: {
                seconds: 1,
            },
        });

        await wait({seconds: 2});

        await assert.throws(
            async () =>
                await parseJwt(jwt, {
                    ...mockJwtParams,
                    jwtKeys,
                }),
            {
                matchMessage: 'JWT expired',
            },
        );
    });
    it('fails to parse a JWT with not valid until in the future', async () => {
        const mockData = {
            mock: 'data',
        };

        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        await assert.throws(
            async () =>
                await parseJwt(
                    await createJwt(mockData, {
                        ...mockJwtParams,
                        jwtKeys,
                        notValidUntil: calculateRelativeDate(getNowInUtcTimezone(), {days: 10}),
                    }),
                    {
                        ...mockJwtParams,
                        jwtKeys,
                    },
                ),
            {
                matchMessage: '"nbf" claim timestamp check failed',
            },
        );
    });
});
