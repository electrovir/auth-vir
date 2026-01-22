import {join, resolve} from 'node:path';

export const monoRepoDirPath = resolve(import.meta.dirname, '..', '..', '..');
const authVirPackageDirPath = join(monoRepoDirPath, 'packages', 'auth-vir');
export const testPrismaSchemaFilePath = join(authVirPackageDirPath, 'test-files', 'schema.prisma');
export const testPrismaMigrationsDirPath = join(authVirPackageDirPath, 'test-files', 'migrations');
