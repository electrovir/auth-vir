import {check} from '@augment-vir/assert';
import {
    DeferredPromise,
    ensureError,
    extractErrorMessage,
    HttpStatus,
    mergeDeep,
} from '@augment-vir/common';
import {generateApi, mapServiceDevPort} from '@rest-vir/define-service';
import {
    AuthHeaderName,
    getCurrentCsrfToken,
    handleAuthResponse,
    wipeCurrentCsrfToken,
} from 'auth-vir';
import {asyncProp, css, defineElement, html, listen, nothing, type AsyncProp} from 'element-vir';
import {
    LoaderAnimated24Icon,
    ViraButton,
    ViraButtonStyle,
    ViraIcon,
    ViraInput,
    ViraInputType,
} from 'vira';
import {demoService, type DemoService} from '../../demo-service-definition.js';

function setupAuthState() {
    const deferredDemoApi = new DeferredPromise<DemoApi>();

    const asyncUser = asyncProp({
        defaultValue: loadUser(deferredDemoApi.promise),
    });

    connectToDemoApi(asyncUser)
        .then((result) => deferredDemoApi.resolve(result))
        .catch((error: unknown) => deferredDemoApi.reject(error));

    return {
        asyncUser,
        apiPromise: deferredDemoApi.promise,
    };
}

async function loadUser(
    apiPromise: Promise<DemoApi>,
): Promise<DemoService['endpoints']['/user']['ResponseType'] | undefined> {
    const {csrfToken} = getCurrentCsrfToken();

    if (csrfToken) {
        const api = await apiPromise;
        const output = await api.endpoints['/user'].fetch({
            options: {
                headers: {
                    [AuthHeaderName.CsrfToken]: csrfToken.token,
                },
            },
        });

        if (output.ok) {
            return output.data;
        }
    }

    return undefined;
}

type DemoApi = Awaited<ReturnType<typeof connectToDemoApi>>;

export async function connectToDemoApi(
    asyncUser: AsyncProp<DemoService['endpoints']['/user']['ResponseType'] | undefined, any>,
) {
    return generateApi(await mapServiceDevPort(demoService), {
        endpointFetch: {
            async fetch(url, init) {
                const {csrfToken} = getCurrentCsrfToken();
                const extraHeaders = csrfToken
                    ? {
                          [AuthHeaderName.CsrfToken]: csrfToken.token,
                      }
                    : {};

                const combinedInit = mergeDeep(init, {
                    headers: extraHeaders,
                    credentials: 'include',
                });

                const response = await globalThis.fetch(url, combinedInit);

                /**
                 * If any request comes back as unauthorized then we need to immediately log out the
                 * current user.
                 */
                if (response.status === HttpStatus.Unauthorized) {
                    asyncUser.setValue(undefined);
                    wipeCurrentCsrfToken();
                }

                return response;
            },
        },
    });
}

enum LoginStatus {
    SigningUp = 'signing-up',
    LoggingIn = 'logging-in',
}

export const DemoApp = defineElement()({
    tagName: 'demo-app',
    styles: css`
        :host {
            display: inline-flex;
            flex-direction: column;
            gap: 16px;
            font-family: sans-serif;
            padding: 16px;
        }

        .buttons {
            display: flex;
            justify-content: center;
            gap: 8px;
        }

        .error {
            color: red;
            font-weight: bold;
        }

        th {
            text-align: right;
        }
    `,
    state() {
        const {apiPromise, asyncUser} = setupAuthState();

        return {
            authenticatedUser: asyncUser,
            api: asyncProp({defaultValue: apiPromise}),
            passwordInput: '',
            usernameInput: '',
            status: undefined as undefined | LoginStatus | Error,
        };
    },
    render({state, updateState}) {
        if (state.api.isError()) {
            return html`
                <p class="error">
                    Failed to connect to demo API:
                    ${extractErrorMessage(state.api.value) || 'unknown error.'}
                </p>
            `;
        }

        const buttonsEnabled =
            (state.passwordInput && state.usernameInput && state.status == undefined) ||
            check.isError(state.status);

        async function login(status: LoginStatus) {
            const api: DemoApi | undefined = state.api.isNotError()
                ? await state.api.value
                : undefined;

            if (!api) {
                return;
            }

            updateState({
                status,
            });

            const endpoint =
                status === LoginStatus.LoggingIn
                    ? api.endpoints['/login']
                    : api.endpoints['/sign-up'];

            try {
                const response = await endpoint.fetch({
                    requestData: {
                        password: state.passwordInput,
                        username: state.usernameInput,
                    },
                });

                handleAuthResponse(response.response);

                if (response.ok) {
                    state.authenticatedUser.setValue(response.data);

                    updateState({
                        status: undefined,
                    });
                } else {
                    const errorMessage = [
                        status === LoginStatus.LoggingIn ? 'Login failed' : 'Sign up failed',
                        response.data,
                    ]
                        .filter(check.isTruthy)
                        .join(': ');
                    throw new Error(errorMessage);
                }
            } catch (error) {
                updateState({
                    status: ensureError(error),
                });
            }
        }

        const loginTemplate = html`
            <table>
                <tbody>
                    <tr>
                        <th>Username:</th>
                        <td>
                            <${ViraInput.assign({
                                value: state.usernameInput,
                            })}
                                ${listen(ViraInput.events.valueChange, (event) => {
                                    updateState({usernameInput: event.detail});
                                })}
                            ></${ViraInput}>
                        </td>
                    </tr>
                    <tr>
                        <th>Password:</th>
                        <td>
                            <${ViraInput.assign({
                                value: state.passwordInput,
                                type: ViraInputType.Password,
                            })}
                                ${listen(ViraInput.events.valueChange, (event) => {
                                    updateState({passwordInput: event.detail});
                                })}
                            ></${ViraInput}>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div class="buttons">
                <${ViraButton.assign({
                    text: 'Sign up',
                    buttonStyle: ViraButtonStyle.Outline,
                    disabled: !buttonsEnabled,
                    icon: state.status === LoginStatus.SigningUp ? LoaderAnimated24Icon : undefined,
                })}
                    ${listen('click', async () => {
                        await login(LoginStatus.SigningUp);
                    })}
                ></${ViraButton}>
                <${ViraButton.assign({
                    text: 'Login',
                    disabled: !buttonsEnabled,
                    icon: state.status === LoginStatus.LoggingIn ? LoaderAnimated24Icon : undefined,
                })}
                    ${listen('click', async () => {
                        await login(LoginStatus.LoggingIn);
                    })}
                ></${ViraButton}>
            </div>
            ${state.status instanceof Error
                ? html`
                      <p class="error">${extractErrorMessage(state.status)}</p>
                  `
                : nothing}
        `;

        if (state.authenticatedUser.isError()) {
            return html`
                <p class="error">${extractErrorMessage(state.authenticatedUser.value)}</p>
            `;
        } else if (state.authenticatedUser.isResolved()) {
            if (state.authenticatedUser.value) {
                return html`
                    Successfully authenticated.
                    <table>
                        <tbody>
                            <tr>
                                <th>Username:</th>
                                <td>${state.authenticatedUser.value.username}</td>
                            </tr>
                            <tr>
                                <th>Email:</th>
                                <td>${state.authenticatedUser.value.email}</td>
                            </tr>
                            <tr>
                                <th>Name:</th>
                                <td>${state.authenticatedUser.value.name}</td>
                            </tr>
                        </tbody>
                    </table>
                    <${ViraButton.assign({text: 'Logout'})}
                        ${listen('click', () => {
                            state.authenticatedUser.setValue(undefined);
                            wipeCurrentCsrfToken();
                        })}
                    ></${ViraButton}>
                `;
            } else {
                return loginTemplate;
            }
        } else {
            return html`
                <${ViraIcon.assign({
                    icon: LoaderAnimated24Icon,
                })}></${ViraIcon}>
            `;
        }
    },
});
