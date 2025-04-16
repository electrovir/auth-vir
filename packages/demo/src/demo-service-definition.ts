import {defineService, HttpMethod} from '@rest-vir/define-service';

export type DemoService = typeof demoService;

const userResponseShape = {
    name: '',
    username: '',
    email: '',
};

export const demoService = defineService({
    requiredClientOrigin(origin) {
        return !!origin?.includes('localhost');
    },
    serviceName: 'demo',
    serviceOrigin: 'http://localhost:3586',
    endpoints: {
        /** Retrieve current authenticated user data. */
        '/user': {
            methods: {
                [HttpMethod.Get]: true,
            },
            requestDataShape: undefined,
            responseDataShape: userResponseShape,
        },
        /** Login and store credentials. */
        '/login': {
            methods: {
                [HttpMethod.Post]: true,
            },
            requestDataShape: {
                username: '',
                password: '',
            },
            responseDataShape: userResponseShape,
        },
        '/sign-up': {
            methods: {
                [HttpMethod.Post]: true,
            },
            requestDataShape: {
                username: '',
                password: '',
            },
            responseDataShape: userResponseShape,
        },
    },
});
