import {defineEslintConfig} from '@virmator/lint/configs/eslint.config.base.mjs';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default [
    ...defineEslintConfig(__dirname),
    {
        ignores: [
            /** Add file globs that should be ignored. */
            'packages/auth-vir/src/generated/',
        ],
    },
    {
        rules: {
            /**
             * Turn off or on specific rules. See {@link defineEslintConfig} for which plugins are
             * already enabled.
             */
            /**
             * This is turned of so we don't need a comment for it in the README example source
             * code. This repo has no actual passwords.
             */
            'sonarjs/no-hardcoded-passwords': 'off',
        },
    },
];
