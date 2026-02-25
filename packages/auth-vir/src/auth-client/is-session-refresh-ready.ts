import {
    type AnyDuration,
    calculateRelativeDate,
    type FullDate,
    getNowInUtcTimezone,
    isDateAfter,
    type UtcTimezone,
} from 'date-vir';

/**
 * Determines if enough time has passed since the JWT was issued to start refreshing the session.
 *
 * Visually, this check looks like this:
 *
 *      I====R===========E
 *
 * - I = JWT issued time (from the JWT's `iat` claim)
 * - R = session refreshing is available now (I + sessionRefreshStartTime)
 * - E = JWT expiration
 * - `=` between R and E = the time frame in which the return value is `true`.
 *
 * @category Auth : Host
 */
export function isSessionRefreshReady({
    now = getNowInUtcTimezone(),
    jwtIssuedAt,
    sessionRefreshStartTime,
}: {
    /** The current time. */
    now?: Readonly<FullDate<UtcTimezone>> | undefined;
    /** When the JWT was issued (`iat` claim). */
    jwtIssuedAt: Readonly<FullDate<UtcTimezone>>;
    /** How long after JWT issuance before refreshing is available. */
    sessionRefreshStartTime: Readonly<AnyDuration>;
}): boolean {
    return isDateAfter({
        fullDate: now,
        relativeTo: calculateRelativeDate(jwtIssuedAt, sessionRefreshStartTime),
    });
}
