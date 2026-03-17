import {check} from '@augment-vir/assert';
import {
    DeferredPromise,
    ensureError,
    extractErrorMessage,
    HttpStatus,
    mergeDeep,
    stringify,
} from '@augment-vir/common';
import {generateApi, mapServiceDevPort} from '@rest-vir/define-service';
import {
    getCurrentCsrfToken,
    handleAuthResponse,
    resolveCsrfHeaderName,
    wipeCurrentCsrfToken,
    type CsrfHeaderNameOption,
} from 'auth-vir';
import {asyncProp, css, defineElement, html, listen, nothing, type AsyncProp} from 'element-vir';
import {LoaderAnimated24Icon, ViraButton, ViraIcon, ViraInput, ViraInputType} from 'vira';
import {demoService, type DemoService} from '../../demo-service-definition.js';

const demoCsrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'demo',
};
const demoCsrfHeaderName = resolveCsrfHeaderName(demoCsrfOption);

function setupAuthState() {
    console.info('[auth-setup] Setting up auth state...');
    const deferredDemoApi = new DeferredPromise<DemoApi>();

    const asyncUser = asyncProp({
        defaultValue: loadUser(deferredDemoApi.promise),
    });

    connectToDemoApi(asyncUser)
        .then((result) => {
            console.info('[auth-setup] Demo API connected successfully');
            deferredDemoApi.resolve(result);
        })
        .catch((error: unknown) => {
            console.error('[auth-setup] Failed to connect to demo API:', error);
            deferredDemoApi.reject(error);
        });

    return {
        asyncUser,
        apiPromise: deferredDemoApi.promise,
    };
}

async function loadUser(
    apiPromise: Promise<DemoApi>,
): Promise<DemoService['endpoints']['/user']['ResponseType'] | undefined> {
    console.info('[loadUser] Checking for existing CSRF token...');
    const csrfToken = await getCurrentCsrfToken(demoCsrfOption);

    console.info(
        '[loadUser] CSRF token result:',
        csrfToken ? `token exists (${csrfToken.slice(0, 20)}...)` : 'no token found',
    );

    if (csrfToken) {
        console.info('[loadUser] Have CSRF token, fetching /user...');
        const api = await apiPromise;
        const output = await api.endpoints['/user'].fetch({
            options: {
                headers: {
                    [demoCsrfHeaderName]: csrfToken,
                },
            },
        });

        console.info('[loadUser] /user response ok:', output.ok);
        console.info('[loadUser] /user response data:', output.data);

        if (output.ok) {
            return output.data;
        }
    }

    console.info('[loadUser] No valid user session found');
    return undefined;
}

type DemoApi = Awaited<ReturnType<typeof connectToDemoApi>>;

export async function connectToDemoApi(
    asyncUser: AsyncProp<DemoService['endpoints']['/user']['ResponseType'] | undefined, any>,
) {
    console.info('[connectToDemoApi] Creating API connection...');
    return generateApi(await mapServiceDevPort(demoService), {
        endpointFetch: {
            async fetch(url, init) {
                console.info('[fetch-wrapper] Fetching:', url);
                console.info('[fetch-wrapper] Init method:', init.method);

                const csrfToken = await getCurrentCsrfToken(demoCsrfOption);
                console.info(
                    '[fetch-wrapper] CSRF token for request:',
                    csrfToken ? `present (${csrfToken.slice(0, 20)}...)` : 'MISSING',
                );

                const extraHeaders = csrfToken
                    ? {
                          [demoCsrfHeaderName]: csrfToken,
                      }
                    : {};

                const combinedInit = mergeDeep(init, {
                    headers: extraHeaders,
                    credentials: 'include',
                });

                console.info(
                    '[fetch-wrapper] Request headers:',
                    JSON.stringify(combinedInit.headers),
                );
                console.info('[fetch-wrapper] Request credentials:', combinedInit.credentials);

                const response = await globalThis.fetch(url, combinedInit);

                console.info('[fetch-wrapper] Response status:', response.status);
                console.info('[fetch-wrapper] Response headers:');
                response.headers.forEach((value, key) => {
                    console.info(
                        `  ${key}: ${key === 'set-cookie' ? value.slice(0, 80) + '...' : value}`,
                    );
                });

                /**
                 * If any request comes back as unauthorized then we need to immediately log out the
                 * current user.
                 */
                if (response.status === HttpStatus.Unauthorized) {
                    console.info('[fetch-wrapper] Got 401 Unauthorized, clearing user state');
                    asyncUser.setValue(undefined);
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
            api: asyncProp({
                defaultValue: apiPromise,
            }),
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
            console.info(`\n=== LOGIN ATTEMPT (${status}) ===`);
            console.info('[login] Username:', state.usernameInput);
            console.info('[login] Password length:', state.passwordInput.length);

            const api: DemoApi | undefined = state.api.isNotError()
                ? await state.api.value
                : undefined;

            if (!api) {
                console.error('[login] API not available, aborting');
                return;
            }

            updateState({
                status,
            });

            const endpoint =
                status === LoginStatus.LoggingIn
                    ? api.endpoints['/login']
                    : api.endpoints['/sign-up'];

            console.info(
                '[login] Using endpoint:',
                status === LoginStatus.LoggingIn ? '/login' : '/sign-up',
            );

            try {
                const response = await endpoint.fetch({
                    requestData: {
                        password: state.passwordInput,
                        username: state.usernameInput,
                    },
                });

                console.info('[login] Response ok:', response.ok);
                console.info('[login] Response status:', response.response.status);
                console.info('[login] Response data:', JSON.stringify(response.data));
                console.info('[login] Response headers:');
                response.response.headers.forEach((value, key) => {
                    console.info(
                        `  ${key}:`,
                        value.length > 100 ? value.slice(0, 100) + '...' : value,
                    );
                });

                console.info('[login] Calling handleAuthResponse...');
                await handleAuthResponse(response.response, demoCsrfOption);
                console.info('[login] handleAuthResponse completed');

                /** Verify CSRF was stored by reading it back. */
                const storedCsrf = await getCurrentCsrfToken(demoCsrfOption);
                console.info(
                    '[login] CSRF token stored after handleAuthResponse:',
                    storedCsrf ? `yes (${storedCsrf.slice(0, 20)}...)` : 'NO - MISSING',
                );

                if (response.ok) {
                    console.info('[login] Login successful, setting user data');
                    state.authenticatedUser.setValue(response.data);

                    updateState({
                        status: undefined,
                    });
                } else {
                    const errorMessage = [
                        status === LoginStatus.LoggingIn ? 'Login failed' : 'Sign up failed',
                        stringify(response.data),
                    ]
                        .filter(check.isTruthy)
                        .join(': ');
                    console.error('[login] Login not ok:', errorMessage);
                    throw new Error(errorMessage);
                }
            } catch (error) {
                console.error('[login] Login error:', error);
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
                                    updateState({
                                        usernameInput: event.detail,
                                    });
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
                                    updateState({
                                        passwordInput: event.detail,
                                    });
                                })}
                            ></${ViraInput}>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div class="buttons">
                <${ViraButton.assign({
                    text: 'Sign up',
                    isDisabled: !buttonsEnabled,
                    icon: state.status === LoginStatus.SigningUp ? LoaderAnimated24Icon : undefined,
                })}
                    ${listen('click', async () => {
                        await login(LoginStatus.SigningUp);
                    })}
                ></${ViraButton}>
                <${ViraButton.assign({
                    text: 'Login',
                    isDisabled: !buttonsEnabled,
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
                    <${ViraButton.assign({
                        text: 'Logout',
                    })}
                        ${listen('click', async () => {
                            console.info('[logout] Wiping CSRF token...');
                            await wipeCurrentCsrfToken(demoCsrfOption);
                            console.info('[logout] CSRF token wiped, clearing user state');
                            state.authenticatedUser.setValue(undefined);
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
