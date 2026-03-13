import {type CsrfTokenStore} from './csrf-token-store.js';

/**
 * `accessRecord` type for {@link createMockLocalStorage}'s output.
 *
 * @category Internal
 */
export type MockLocalStorageAccessRecord = {
    getItem: string[];
    removeItem: string[];
    setItem: {key: string; value: string}[];
    key: number[];
};

/**
 * Create an empty `accessRecord` object, this is to be used in conjunction with
 * {@link createMockLocalStorage}.
 *
 * @category Mock
 */
export function createEmptyMockLocalStorageAccessRecord(): MockLocalStorageAccessRecord {
    return {
        getItem: [],
        removeItem: [],
        setItem: [],
        key: [],
    };
}

/**
 * Create a LocalStorage mock.
 *
 * @category Mock
 */
export function createMockLocalStorage(
    /** Set values in here to initialize the mocked localStorage data store contents. */
    init: Record<string, string> = {},
) {
    const store: Record<string, string> = init;
    const accessRecord = createEmptyMockLocalStorageAccessRecord();

    const mockLocalStorage: Storage = {
        clear() {
            Object.keys(store).forEach((key) => {
                delete store[key];
            });
        },
        getItem(key) {
            accessRecord.getItem.push(key);
            return store[key] ?? null;
        },
        get length() {
            return Object.keys(store).length;
        },
        key(index) {
            accessRecord.key.push(index);
            return Object.keys(store)[index] ?? null;
        },
        removeItem(key) {
            accessRecord.removeItem.push(key);
            delete store[key];
        },
        setItem(key, value) {
            accessRecord.setItem.push({
                key,
                value,
            });
            store[key] = value;
        },
    };

    return {
        localStorage: mockLocalStorage,
        store,
        accessRecord,
    };
}

/**
 * `accessRecord` type for {@link createMockCsrfTokenStore}'s output.
 *
 * @category Internal
 */
export type MockCsrfTokenStoreAccessRecord = {
    getCsrfToken: number;
    setCsrfToken: string[];
    deleteCsrfToken: number;
};

/**
 * Create an empty `accessRecord` object, this is to be used in conjunction with
 * {@link createMockCsrfTokenStore}.
 *
 * @category Mock
 */
export function createEmptyMockCsrfTokenStoreAccessRecord(): MockCsrfTokenStoreAccessRecord {
    return {
        getCsrfToken: 0,
        setCsrfToken: [],
        deleteCsrfToken: 0,
    };
}

/**
 * Create a mock {@link CsrfTokenStore} backed by a simple in-memory object, for use in tests.
 *
 * @category Mock
 */
export function createMockCsrfTokenStore(
    /** Set an initial value to initialize the mocked store contents. */
    init?: string | undefined,
) {
    let storedValue: string | undefined = init;
    const accessRecord = createEmptyMockCsrfTokenStoreAccessRecord();

    const csrfTokenStore: CsrfTokenStore = {
        getCsrfToken() {
            accessRecord.getCsrfToken++;
            return Promise.resolve(storedValue);
        },
        setCsrfToken(value: string) {
            accessRecord.setCsrfToken.push(value);
            storedValue = value;
            return Promise.resolve();
        },
        deleteCsrfToken() {
            accessRecord.deleteCsrfToken++;
            storedValue = undefined;
            return Promise.resolve();
        },
    };

    return {
        csrfTokenStore,
        /** The current value held in the mock store. */
        get storedValue() {
            return storedValue;
        },
        accessRecord,
    };
}
