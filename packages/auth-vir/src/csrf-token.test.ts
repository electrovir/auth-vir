import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {generateCsrfToken, getCurrentCsrfToken} from './csrf-token.js';
import {clearCsrfCookieInBrowser, simulateCsrfCookie} from './csrf-token.mock.js';

describe(getCurrentCsrfToken.name, () => {
    it('can store and retrieve a CSRF token', () => {
        clearCsrfCookieInBrowser();
        const mockCsrfToken = generateCsrfToken();

        simulateCsrfCookie(mockCsrfToken);

        assert.strictEquals(getCurrentCsrfToken(), mockCsrfToken);

        clearCsrfCookieInBrowser();

        assert.isUndefined(getCurrentCsrfToken());
    });
    it('uses prefix to generate header name', () => {
        clearCsrfCookieInBrowser();
        const mockCsrfToken = generateCsrfToken();

        simulateCsrfCookie(mockCsrfToken);

        assert.strictEquals(getCurrentCsrfToken(), mockCsrfToken);

        clearCsrfCookieInBrowser();

        assert.isUndefined(getCurrentCsrfToken());
    });
});
