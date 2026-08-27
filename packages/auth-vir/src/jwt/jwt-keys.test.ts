import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {parseJwtKeys} from './jwt-keys.js';

describe(parseJwtKeys.name, () => {
    it('errors on empty raw keys', async () => {
        await assert.throws(() => {
            return parseJwtKeys({
                encryptionKey: '',
                signingKey: 'abc',
            });
        });
        await assert.throws(() => {
            return parseJwtKeys({
                encryptionKey: 'abc',
                signingKey: '',
            });
        });
    });
});
