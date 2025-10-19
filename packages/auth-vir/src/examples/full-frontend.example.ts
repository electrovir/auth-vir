import {HttpStatus} from '@augment-vir/common';
import {AuthHeaderName} from '../headers.js';
import {getCurrentCsrfToken, handleAuthResponse, wipeCurrentCsrfToken} from '../index.js';

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

    handleAuthResponse(response);

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
            [AuthHeaderName.CsrfToken]: csrfToken,
        },
    });

    /**
     * This indicates the user is no longer authorized and thus needs to login again. (This likely
     * means that their session timed out or they clicked a "log out" button onr your website in
     * another tab.)
     */
    if (response.status === HttpStatus.Unauthorized) {
        wipeCurrentCsrfToken();
        throw new Error(`User no longer logged in.`);
    } else {
        return response;
    }
}

/** Call this when the user explicitly clicks a "log out" button. */
export function logout() {
    wipeCurrentCsrfToken();
}
