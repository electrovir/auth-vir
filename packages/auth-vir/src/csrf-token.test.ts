import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {generateCsrfToken, getCurrentCsrfToken, wipeCurrentCsrfToken} from './csrf-token.js';
import {createMockCsrfTokenStore} from './mock-csrf-token-store.js';

const testCsrfOption = {
    csrfHeaderPrefix: 'test',
};

describe(getCurrentCsrfToken.name, () => {
    it('can store and retrieve a CSRF token', async () => {
        const mockCsrfToken = generateCsrfToken({
            days: 2,
        });

        const {csrfTokenStore} = createMockCsrfTokenStore();
        await csrfTokenStore.setCsrfToken(JSON.stringify(mockCsrfToken));

        assert.strictEquals(
            (
                await getCurrentCsrfToken({
                    csrfTokenStore,
                    ...testCsrfOption,
                })
            ).csrfToken?.token,
            mockCsrfToken.token,
        );
        await wipeCurrentCsrfToken({
            csrfTokenStore,
            ...testCsrfOption,
        });
        assert.isUndefined(
            (
                await getCurrentCsrfToken({
                    csrfTokenStore,
                    ...testCsrfOption,
                })
            ).csrfToken,
        );
    });
    it('uses prefix to generate header name', async () => {
        const mockCsrfToken = generateCsrfToken({
            days: 2,
        });

        const {csrfTokenStore} = createMockCsrfTokenStore();
        await csrfTokenStore.setCsrfToken(JSON.stringify(mockCsrfToken));

        assert.strictEquals(
            (
                await getCurrentCsrfToken({
                    csrfTokenStore,
                    ...testCsrfOption,
                })
            ).csrfToken?.token,
            mockCsrfToken.token,
        );
        await wipeCurrentCsrfToken({
            csrfTokenStore,
            ...testCsrfOption,
        });
        assert.isUndefined(
            (
                await getCurrentCsrfToken({
                    csrfTokenStore,
                    ...testCsrfOption,
                })
            ).csrfToken,
        );
    });
});
