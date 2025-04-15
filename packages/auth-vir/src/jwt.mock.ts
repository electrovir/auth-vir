import type {CreateJwtParams} from './jwt.js';

export const mockJwtParams: Omit<CreateJwtParams, 'jwtKeys'> = {
    audience: 'mock audience',
    expirationDuration: {days: 20},
    issuer: 'mock issuer',
};
