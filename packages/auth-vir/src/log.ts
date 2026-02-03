/**
 * Send logs to the console for debugging.
 *
 * @category Internal
 */
export function authLog(...params: any[]) {
    if (!shouldLogAuth) {
        return;
    }
    console.info(...params);
}

let shouldLogAuth = true;

/**
 * Set to `false` to disable logging.
 *
 * @category Internal
 */
export function setShouldLogAuth(value: boolean) {
    shouldLogAuth = value;
}
