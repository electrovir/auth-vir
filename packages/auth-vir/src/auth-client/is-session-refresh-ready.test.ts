import {assert} from '@augment-vir/assert';
import {describe, it} from '@augment-vir/test';
import {calculateRelativeDate, getNowInUtcTimezone} from 'date-vir';
import {isSessionRefreshReady} from './is-session-refresh-ready.js';

describe(isSessionRefreshReady.name, () => {
    it('returns false when the timeout has not elapsed', () => {
        const now = getNowInUtcTimezone();
        const jwtIssuedAt = now;

        assert.isFalse(
            isSessionRefreshReady({
                now,
                jwtIssuedAt,
                sessionRefreshStartTime: {minutes: 2},
            }),
        );
    });

    it('returns true when the timeout has fully elapsed', () => {
        const now = getNowInUtcTimezone();
        /** Issued 5 minutes ago. */
        const jwtIssuedAt = calculateRelativeDate(now, {minutes: -5});

        assert.isTrue(
            isSessionRefreshReady({
                now,
                jwtIssuedAt,
                sessionRefreshStartTime: {minutes: 2},
            }),
        );
    });

    it('returns false when exactly at the timeout boundary', () => {
        const now = getNowInUtcTimezone();
        /** Issued exactly 2 minutes ago, with a 2-minute timeout. */
        const jwtIssuedAt = calculateRelativeDate(now, {minutes: -2});

        /**
         * `isDateAfter` returns false when the dates are equal (it checks strictly after, not "at
         * or after").
         */
        assert.isFalse(
            isSessionRefreshReady({
                now,
                jwtIssuedAt,
                sessionRefreshStartTime: {minutes: 2},
            }),
        );
    });

    it('returns true just past the timeout boundary', () => {
        const now = getNowInUtcTimezone();
        /** Issued 2 minutes and 1 second ago. */
        const jwtIssuedAt = calculateRelativeDate(now, {minutes: -2, seconds: -1});

        assert.isTrue(
            isSessionRefreshReady({
                now,
                jwtIssuedAt,
                sessionRefreshStartTime: {minutes: 2},
            }),
        );
    });

    it('returns false just before the timeout boundary', () => {
        const now = getNowInUtcTimezone();
        /** Issued 1 minute and 59 seconds ago. */
        const jwtIssuedAt = calculateRelativeDate(now, {minutes: -1, seconds: -59});

        assert.isFalse(
            isSessionRefreshReady({
                now,
                jwtIssuedAt,
                sessionRefreshStartTime: {minutes: 2},
            }),
        );
    });

    it('works with a zero-second timeout', () => {
        const now = getNowInUtcTimezone();
        /** Issued 1 second ago with zero timeout → immediately ready. */
        const jwtIssuedAt = calculateRelativeDate(now, {seconds: -1});

        assert.isTrue(
            isSessionRefreshReady({
                now,
                jwtIssuedAt,
                sessionRefreshStartTime: {seconds: 0},
            }),
        );
    });

    it('works with a large timeout', () => {
        const now = getNowInUtcTimezone();
        /** Issued 23 hours ago with a 1-day timeout. */
        const jwtIssuedAt = calculateRelativeDate(now, {hours: -23});

        assert.isFalse(
            isSessionRefreshReady({
                now,
                jwtIssuedAt,
                sessionRefreshStartTime: {days: 1},
            }),
        );
    });

    it('returns true with a large timeout once elapsed', () => {
        const now = getNowInUtcTimezone();
        /** Issued 25 hours ago with a 1-day timeout. */
        const jwtIssuedAt = calculateRelativeDate(now, {hours: -25});

        assert.isTrue(
            isSessionRefreshReady({
                now,
                jwtIssuedAt,
                sessionRefreshStartTime: {days: 1},
            }),
        );
    });

    it('defaults now to the current time', () => {
        /** Issued 5 minutes ago, so with a 2-minute timeout it should be ready. */
        const jwtIssuedAt = calculateRelativeDate(getNowInUtcTimezone(), {minutes: -5});

        assert.isTrue(
            isSessionRefreshReady({
                jwtIssuedAt,
                sessionRefreshStartTime: {minutes: 2},
            }),
        );
    });
});
