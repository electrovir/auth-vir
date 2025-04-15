import {assert} from '@augment-vir/assert';
import {randomString} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {compareHash, hashPassword} from './hash.js';

describe(hashPassword.name, () => {
    it('hashes the password', async () => {
        const originalPassword = randomString();
        assert.notStrictEquals(originalPassword, await hashPassword(originalPassword));
    });
    it('fails if the password is too long', async () => {
        const originalPassword = '💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩';
        assert.strictEquals(new Blob([originalPassword]).size, 76);
        assert.isUndefined(await hashPassword(originalPassword));
    });
    it('works on the longest passwords possible', async () => {
        const originalPassword = '💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩';
        assert.strictEquals(new Blob([originalPassword]).size, 72);
        assert.isString(await hashPassword(originalPassword));
    });
});

describe(compareHash.name, () => {
    it('successfully compares a password', async () => {
        const originalPassword = randomString();
        const hash = await hashPassword(originalPassword);

        assert.isDefined(hash);

        assert.isTrue(
            await compareHash({
                password: originalPassword,
                hash,
            }),
        );
    });
});
