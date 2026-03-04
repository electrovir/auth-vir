import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {generateNewJwtKeys, parseJwtKeys} from './jwt-keys.js';
import {createJwt} from './jwt.js';
import {mockJwtParams} from './jwt.mock.js';
import {createUserJwt, parseUserJwt, type JwtUserData} from './user-jwt.js';

describe('user JWT', () => {
    it('creates and parses a user JWT', async () => {
        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        const mockJwt: JwtUserData = {
            csrfToken: 'hi',
            userId: 'something',
        };

        assert.deepEquals(
            (
                await parseUserJwt(
                    await createUserJwt(mockJwt, {
                        ...mockJwtParams,
                        jwtKeys,
                    }),
                    {
                        ...mockJwtParams,
                        jwtKeys,
                    },
                )
            )?.data,
            mockJwt,
        );
    });
    it('encrypts the user JWT', async () => {
        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        const mockJwt: JwtUserData = {
            csrfToken: 'hi',
            userId: 'something',
        };

        const jwt = await createUserJwt(mockJwt, {
            ...mockJwtParams,
            jwtKeys,
        });

        assert.isString(jwt);
        assert.lacksValue(jwt, 'something');
    });
    it('rejects invalid JWT data', async () => {
        const jwtKeys = await parseJwtKeys(await generateNewJwtKeys());

        const jwt = await createJwt(
            {
                not: 'user data',
            },
            {
                ...mockJwtParams,
                jwtKeys,
            },
        );

        await assert.throws(
            () =>
                parseUserJwt(jwt, {
                    ...mockJwtParams,
                    jwtKeys,
                }),
            {
                matchMessage: 'wrong data',
            },
        );
    });
});
