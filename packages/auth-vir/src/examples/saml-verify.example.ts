import {type FullDate, type UtcTimezone} from 'date-vir';
import {verifySamlResponse} from '../saml/index.js';

/** Stand-in for a database table with a unique assertion ID column. */
const usedAssertions: Record<string, FullDate<UtcTimezone>> = {};

function insertAssertionIdIfNew({
    assertionId,
    expiresAt,
}: Readonly<{assertionId: string; expiresAt: FullDate<UtcTimezone>}>): boolean {
    /** Rows can be deleted once `expiresAt` has passed. */
    if (assertionId in usedAssertions) {
        return false;
    } else {
        usedAssertions[assertionId] = expiresAt;
        return true;
    }
}

/** This should be the body of the form POST your IdP sends to your ACS URL. */
const requestBody = {
    SAMLResponse: 'base64 encoded SAMLResponse',
};

const result = await verifySamlResponse({
    /** Usually the output of `parseIdpMetadata`, stored per organization. */
    idp: {
        entityId: 'http://adfs.example.com/adfs/services/trust',
        signingCertificates: ['-----BEGIN CERTIFICATE-----...'],
    },
    spEntityId: 'https://app.example.com/sso/saml/metadata',
    acsUrl: 'https://app.example.com/sso/saml/acs/example-org',
    samlResponse: requestBody.SAMLResponse,
    replayStore: {
        markAssertionUsed: insertAssertionIdIfNew,
    },
});

if (!result.success) {
    /** Log `result.reason` and `result.detail`, but do not show them to the user. */
    throw new Error('SAML sign-in failed.');
}

/** `result.profile.nameId` and `result.profile.attributes` are now safe to trust. */
