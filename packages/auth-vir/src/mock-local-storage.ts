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
