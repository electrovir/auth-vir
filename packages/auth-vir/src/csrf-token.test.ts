import {assert} from '@augment-vir/assert';
import {randomString} from '@augment-vir/common';
import {describe, it} from '@augment-vir/test';
import {
    generateCsrfToken,
    getCurrentCsrfToken,
    resolveCsrfHeaderName,
    wipeCurrentCsrfToken,
} from './csrf-token.js';
import {createMockLocalStorage} from './mock-local-storage.js';

const testCsrfOption = {
    csrfHeaderPrefix: 'test',
};

describe(getCurrentCsrfToken.name, () => {
    it('can override the localstorage key', () => {
        const mockKey = `mock-key-${randomString()}`;
        const mockCsrfToken = generateCsrfToken({
            days: 2,
        });

        const {localStorage} = createMockLocalStorage();
        localStorage.setItem(mockKey, JSON.stringify(mockCsrfToken));

        assert.strictEquals(
            getCurrentCsrfToken({
                localStorage,
                csrfHeaderName: mockKey,
            }).csrfToken?.token,
            mockCsrfToken.token,
        );
        wipeCurrentCsrfToken({
            localStorage,
            csrfHeaderName: mockKey,
        });
        assert.isUndefined(
            getCurrentCsrfToken({
                localStorage,
                csrfHeaderName: mockKey,
            }).csrfToken,
        );
    });
    it('uses prefix to generate header name', () => {
        const mockCsrfToken = generateCsrfToken({
            days: 2,
        });

        const {localStorage} = createMockLocalStorage();
        const resolvedName = resolveCsrfHeaderName(testCsrfOption);
        localStorage.setItem(resolvedName, JSON.stringify(mockCsrfToken));

        assert.strictEquals(
            getCurrentCsrfToken({
                localStorage,
                ...testCsrfOption,
            }).csrfToken?.token,
            mockCsrfToken.token,
        );
        wipeCurrentCsrfToken({
            localStorage,
            ...testCsrfOption,
        });
        assert.isUndefined(
            getCurrentCsrfToken({
                localStorage,
                ...testCsrfOption,
            }).csrfToken,
        );
    });
});
