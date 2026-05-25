import {HttpStatus} from '@augment-vir/common';
import {type CsrfHeaderNameOption, getCurrentCsrfToken, resolveCsrfHeaderName} from '../index.js';

/**
 * The CSRF header prefix for this app. Either `csrfHeaderPrefix` or `csrfHeaderName` must be
 * provided to all CSRF-related functions.
 */
const csrfOption: CsrfHeaderNameOption = {
    csrfHeaderPrefix: 'my-app',
};

/** Call this when the user logs in for the first time this session. */
export async function sendLoginRequest(
    userLoginData: {username: string; password: string},
    loginUrl: string,
) {
    if (getCurrentCsrfToken()) {
        throw new Error('Already logged in.');
    }

    const response = await fetch(loginUrl, {
        method: 'post',
        body: JSON.stringify(userLoginData),
        credentials: 'include',
    });

    /** The CSRF token cookie is automatically stored by the browser from the Set-Cookie header. */

    return response;
}

/** Call this when the user needs to send any authenticated request after already having logged in. */
export async function sendAuthenticatedRequest(
    requestUrl: string,
    requestInit: Omit<RequestInit, 'headers'> = {},
    headers: Record<string, string> = {},
) {
    const csrfToken = getCurrentCsrfToken();

    if (!csrfToken) {
        throw new Error('Not authenticated.');
    }

    const response = await fetch(requestUrl, {
        ...requestInit,
        credentials: 'include',
        headers: {
            ...headers,
            [resolveCsrfHeaderName(csrfOption)]: csrfToken,
        },
    });

    if (response.status === HttpStatus.Unauthorized) {
        throw new Error('User no longer logged in.');
    } else {
        return response;
    }
}

/**
 * Call this when the user explicitly clicks a "log out" button. The backend clears the auth and
 * CSRF cookies via Set-Cookie headers.
 */
export async function logout(logoutUrl: string) {
    await sendAuthenticatedRequest(logoutUrl, {
        method: 'post',
    });
}
