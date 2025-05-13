import {assert} from '@augment-vir/assert';
import {randomString} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {doesPasswordMatchHash, getByteLength, hashPassword} from './hash.js';

describe(hashPassword.name, () => {
    it('hashes the password', async () => {
        const originalPassword = randomString();
        assert.notStrictEquals(originalPassword, await hashPassword(originalPassword));
    });
    it('does not truncate a long password', async () => {
        const originalPassword = '💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩💩'.repeat(100);
        assert.strictEquals(getByteLength(originalPassword), 7600);
        assert.isString(await hashPassword(originalPassword));
    });
});

describe(doesPasswordMatchHash.name, () => {
    it('successfully compares a password', async () => {
        const originalPassword = randomString();
        const hash = await hashPassword(originalPassword);

        assert.isDefined(hash);

        assert.isTrue(
            await doesPasswordMatchHash({
                password: originalPassword,
                hash,
            }),
        );
        assert.isFalse(
            await doesPasswordMatchHash({
                password: originalPassword + 'a',
                hash,
            }),
        );
    });
});
