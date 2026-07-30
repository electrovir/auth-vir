import {defineApi, defineEndpoint, HttpMethod, HttpStatus} from '@rest-vir/api';
import {defineShape} from 'object-shape-tester';

/** The origin that the demo server starts on and that the frontend starts scanning from. */
export const demoApiStartOrigin = 'http://localhost:3586';

export const userResponseShape = defineShape({
    name: '',
    username: '',
    email: '',
});

export type DemoUser = typeof userResponseShape.runtimeType;

const credentialsShape = defineShape({
    username: '',
    password: '',
});

/** Retrieve current authenticated user data. */
export const userEndpoint = defineEndpoint({
    path: '/user',
    requests: {
        [HttpMethod.Get]: {
            responses: {
                [HttpStatus.Ok]: {
                    responseData: userResponseShape,
                },
                [HttpStatus.Unauthorized]: {
                    responseData: undefined,
                },
            },
        },
    },
});

/** Login and store credentials. */
export const loginEndpoint = defineEndpoint({
    path: '/login',
    requests: {
        [HttpMethod.Post]: {
            requestData: credentialsShape,
            responses: {
                [HttpStatus.Ok]: {
                    responseData: userResponseShape,
                },
                [HttpStatus.BadRequest]: {
                    responseData: undefined,
                },
                [HttpStatus.Unauthorized]: {
                    responseData: undefined,
                },
            },
        },
    },
});

export const signUpEndpoint = defineEndpoint({
    path: '/sign-up',
    requests: {
        [HttpMethod.Post]: {
            requestData: credentialsShape,
            responses: {
                [HttpStatus.Ok]: {
                    responseData: userResponseShape,
                },
                [HttpStatus.BadRequest]: {
                    responseData: defineShape(''),
                },
            },
        },
    },
});

/** Log out and clear auth cookies. */
export const logoutEndpoint = defineEndpoint({
    path: '/logout',
    requests: {
        [HttpMethod.Post]: {
            responses: {
                [HttpStatus.Ok]: {
                    responseData: undefined,
                },
            },
        },
    },
});

export const demoApi = defineApi({
    apiName: 'demo',
    endpoints: [
        userEndpoint,
        loginEndpoint,
        signUpEndpoint,
        logoutEndpoint,
    ],
});
