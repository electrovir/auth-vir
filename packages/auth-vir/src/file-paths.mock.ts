import {join, resolve} from 'node:path';

export const monoRepoDirPath = resolve(import.meta.dirname, '..', '..', '..');
const authVirPackageDirPath = join(monoRepoDirPath, 'packages', 'auth-vir');
export const testPrismaConfigFilePath = join(
    authVirPackageDirPath,
    'test-files',
    'prisma.config.ts',
);
