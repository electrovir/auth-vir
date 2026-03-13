import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {
    createEmptyMockLocalStorageAccessRecord,
    createMockLocalStorage,
} from './mock-csrf-token-store.js';

describe(createMockLocalStorage.name, () => {
    it('removes an item', () => {
        const {accessRecord, localStorage, store} = createMockLocalStorage({
            key: 'value',
        });

        assert.deepEquals(accessRecord, createEmptyMockLocalStorageAccessRecord());
        assert.hasKey(store, 'key');
        assert.strictEquals(store.key, 'value');
        assert.strictEquals(localStorage.getItem('key'), 'value');
        assert.strictEquals(localStorage.key(0), 'key');
        assert.strictEquals(localStorage.length, 1);

        localStorage.removeItem('key');

        assert.deepEquals(accessRecord, {
            ...createEmptyMockLocalStorageAccessRecord(),
            removeItem: ['key'],
            getItem: ['key'],
            key: [0],
        });
        assert.lacksKey(store, 'key');
        assert.isUndefined(store['key']);
        assert.isNull(localStorage.getItem('key'));
        assert.isNull(localStorage.key(0));
        assert.strictEquals<number, number>(localStorage.length, 0);
    });
    it('clears the store', () => {
        const {accessRecord, localStorage, store} = createMockLocalStorage({
            key: 'value',
        });

        assert.deepEquals(accessRecord, createEmptyMockLocalStorageAccessRecord());
        assert.hasKey(store, 'key');
        assert.strictEquals(store.key, 'value');
        assert.strictEquals(localStorage.getItem('key'), 'value');
        assert.strictEquals(localStorage.key(0), 'key');
        assert.strictEquals(localStorage.length, 1);

        localStorage.clear();

        assert.deepEquals(accessRecord, {
            ...createEmptyMockLocalStorageAccessRecord(),
            getItem: ['key'],
            key: [0],
        });
        assert.lacksKey(store, 'key');
        assert.isUndefined(store['key']);
        assert.isNull(localStorage.getItem('key'));
        assert.isNull(localStorage.key(0));
        assert.strictEquals<number, number>(localStorage.length, 0);
    });
    it('sets an item', () => {
        const {accessRecord, localStorage, store} = createMockLocalStorage();

        assert.deepEquals(accessRecord, createEmptyMockLocalStorageAccessRecord());
        assert.lacksKey(store, 'key');
        assert.isUndefined(store['key']);
        assert.isNull(localStorage.getItem('key'));
        assert.isNull(localStorage.key(0));
        assert.strictEquals<number, number>(localStorage.length, 0);

        localStorage.setItem('key', 'value');

        assert.deepEquals(accessRecord, {
            ...createEmptyMockLocalStorageAccessRecord(),
            setItem: [
                {
                    key: 'key',
                    value: 'value',
                },
            ],
            getItem: ['key'],
            key: [0],
        });
        assert.hasKey(store, 'key');
        assert.strictEquals<string, string>(store['key'], 'value');
        assert.strictEquals(localStorage.getItem('key'), 'value');
        assert.strictEquals(localStorage.key(0), 'key');
        assert.strictEquals(localStorage.length, 1);
    });
});
