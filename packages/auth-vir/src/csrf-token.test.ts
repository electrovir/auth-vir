import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {
    generateCsrfToken,
    getCurrentCsrfToken,
    storeCsrfToken,
    wipeCurrentCsrfToken,
} from './csrf-token.js';
import {createMockCsrfTokenStore} from './mock-csrf-token-store.js';

const testCsrfOption = {
    csrfHeaderPrefix: 'test',
};

describe(getCurrentCsrfToken.name, () => {
    it('can store and retrieve a CSRF token', async () => {
        const mockCsrfToken = generateCsrfToken();

        const {csrfTokenStore} = createMockCsrfTokenStore();
        await storeCsrfToken(mockCsrfToken, {
            csrfTokenStore,
            ...testCsrfOption,
        });

        assert.strictEquals(
            await getCurrentCsrfToken({
                csrfTokenStore,
                ...testCsrfOption,
            }),
            mockCsrfToken,
        );
        await wipeCurrentCsrfToken({
            csrfTokenStore,
            ...testCsrfOption,
        });
        assert.isUndefined(
            await getCurrentCsrfToken({
                csrfTokenStore,
                ...testCsrfOption,
            }),
        );
    });
    it('uses prefix to generate header name', async () => {
        const mockCsrfToken = generateCsrfToken();

        const {csrfTokenStore} = createMockCsrfTokenStore();
        await storeCsrfToken(mockCsrfToken, {
            csrfTokenStore,
            ...testCsrfOption,
        });

        assert.strictEquals(
            await getCurrentCsrfToken({
                csrfTokenStore,
                ...testCsrfOption,
            }),
            mockCsrfToken,
        );
        await wipeCurrentCsrfToken({
            csrfTokenStore,
            ...testCsrfOption,
        });
        assert.isUndefined(
            await getCurrentCsrfToken({
                csrfTokenStore,
                ...testCsrfOption,
            }),
        );
    });
});
