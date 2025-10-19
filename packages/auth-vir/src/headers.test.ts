import {describe, itCases} from '@augment-vir/test';
import {mergeHeaderValues} from './headers.js';

describe(mergeHeaderValues.name, () => {
    itCases(mergeHeaderValues, [
        {
            it: 'ignores undefined',
            inputs: [
                'value',
                undefined,
            ],
            expect: ['value'],
        },
        {
            it: 'merges two strings',
            inputs: [
                'value',
                'value1',
            ],
            expect: [
                'value',
                'value1',
            ],
        },
        {
            it: 'merges an array',
            inputs: [
                'value',
                [
                    'value1',
                    'value2',
                    'value3',
                ],
            ],
            expect: [
                'value',
                'value1',
                'value2',
                'value3',
            ],
        },
    ]);
});
