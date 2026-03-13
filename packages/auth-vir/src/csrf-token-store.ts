import {LocalDbClient} from 'local-db-client';
import {defineShape} from 'object-shape-tester';

const csrfTokenDbShapes = {
    csrfToken: defineShape(''),
} as const;

/**
 * The interface used for overriding the default CSRF token store in storage functions.
 *
 * @category Internal
 */
export type CsrfTokenStore = {
    /** Retrieves the stored CSRF token, if any. */
    getCsrfToken(): Promise<string | undefined>;
    /** Stores a CSRF token. */
    setCsrfToken(value: string): Promise<void>;
    /** Deletes the stored CSRF token. */
    deleteCsrfToken(): Promise<void>;
};

async function createDefaultCsrfTokenStore(): Promise<CsrfTokenStore> {
    const client = await LocalDbClient.createClient(csrfTokenDbShapes, {
        storeName: 'auth-vir-csrf',
    });

    return {
        async getCsrfToken() {
            return (await client.load.csrfToken()) || undefined;
        },
        async setCsrfToken(value) {
            await client.set.csrfToken(value);
        },
        async deleteCsrfToken() {
            await client.delete.csrfToken();
        },
    };
}

/**
 * The default {@link LocalDbClient} instance used for storing CSRF tokens. This uses a dedicated
 * store name to avoid collisions with other storage. Lazily initialized to avoid crashes in Node.js
 * environments where IndexedDB is not available.
 *
 * @category Internal
 */
export async function getDefaultCsrfTokenStore(): Promise<CsrfTokenStore> {
    if (!cachedStorePromise) {
        cachedStorePromise = createDefaultCsrfTokenStore();
    }
    return cachedStorePromise;
}

let cachedStorePromise: Promise<CsrfTokenStore> | undefined;
