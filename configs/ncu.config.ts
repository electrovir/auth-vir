import {baseNcuConfig} from '@virmator/deps/configs/ncu.config.base';
import {RunOptions} from 'npm-check-updates';

export const ncuConfig: RunOptions = {
    ...baseNcuConfig,
    // exclude these
    reject: [
        ...baseNcuConfig.reject,

        /** Stay on v6 for now. */
        'prisma',
        '@prisma/client',
    ],
    // include only these
    filter: [],
};
