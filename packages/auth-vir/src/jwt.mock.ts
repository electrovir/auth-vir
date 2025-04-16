import type {CreateJwtParams} from './jwt.js';

export const mockJwtParams: Omit<CreateJwtParams, 'jwtKeys'> = {
    audience: 'mock audience',
    jwtDuration: {days: 20},
    issuer: 'mock issuer',
};
