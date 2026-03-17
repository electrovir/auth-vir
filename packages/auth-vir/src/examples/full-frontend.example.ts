import {HttpStatus} from '@augment-vir/common';
import {
    type CsrfHeaderNameOption,
    getCurrentCsrfToken,
    handleAuthResponse,
    resolveCsrfHeaderName,
    wipeCurrentCsrfToken,
} from '../index.js';

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
    if (await getCurrentCsrfToken(csrfOption)) {
        throw new Error('Already logged in.');
    }

    const response = await fetch(loginUrl, {
        method: 'post',
        body: JSON.stringify(userLoginData),
        credentials: 'include',
    });

    await handleAuthResponse(response, csrfOption);

    return response;
}

/** Call this when the user needs to send any authenticated request after already having logged in. */
export async function sendAuthenticatedRequest(
    requestUrl: string,
    requestInit: Omit<RequestInit, 'headers'> = {},
    headers: Record<string, string> = {},
) {
    const csrfToken = await getCurrentCsrfToken(csrfOption);

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

    /**
     * This indicates the user is no longer authorized and thus needs to login again. (This likely
     * means that their session timed out or they clicked a "log out" button onr your website in
     * another tab.)
     */
    if (response.status === HttpStatus.Unauthorized) {
        await wipeCurrentCsrfToken(csrfOption);
        throw new Error(`User no longer logged in.`);
    } else {
        return response;
    }
}

/** Call this when the user explicitly clicks a "log out" button. */
export async function logout() {
    await wipeCurrentCsrfToken(csrfOption);
}
