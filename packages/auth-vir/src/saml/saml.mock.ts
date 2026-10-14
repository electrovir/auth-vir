// cspell:words adfs nameid samlp
import {getObjectTypedEntries} from '@augment-vir/common';
import {
    type AnyDuration,
    calculateRelativeDate,
    type FullDate,
    getNowInUtcTimezone,
    toUtcIsoString,
    type UtcTimezone,
} from 'date-vir';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {SignedXml} from 'xml-crypto';
import {samlTestFilesDirPath} from '../file-paths.mock.js';

export type MockIdpKeyPair = Readonly<{
    privateKey: string;
    certificate: string;
}>;

function readMockKeyPair(name: string) {
    return {
        privateKey: readFileSync(join(samlTestFilesDirPath, `${name}.key.pem`), 'utf8'),
        certificate: readFileSync(join(samlTestFilesDirPath, `${name}.cert.pem`), 'utf8'),
    };
}

/** Throwaway key pairs generated only for these tests. Never trust them anywhere else. */
export const mockIdpKeys = {
    current: readMockKeyPair('idp-current'),
    rolledOver: readMockKeyPair('idp-rolled-over'),
    unknown: readMockKeyPair('idp-unknown'),
} satisfies Record<string, MockIdpKeyPair>;

export const mockSaml = {
    idpEntityId: 'http://adfs.example.com/adfs/services/trust',
    spEntityId: 'https://app.example.com/sso/saml/metadata',
    acsUrl: 'https://app.example.com/sso/saml/acs/example-org',
    nameId: 'user@example.com',
};

export type MockSamlResponseParams = Partial<{
    assertionId: string;
    issuer: string;
    audiences: ReadonlyArray<string>;
    recipient: string;
    nameId: string;
    /** Defaults to one minute ago. */
    notBefore: FullDate<UtcTimezone>;
    /** Defaults to five minutes from now. */
    notOnOrAfter: FullDate<UtcTimezone>;
    /** The bearer SubjectConfirmationData's NotOnOrAfter. Defaults to `notOnOrAfter`. */
    subjectNotOnOrAfter: FullDate<UtcTimezone>;
    /**
     * Written verbatim as the Conditions NotOnOrAfter, to test time strings `FullDate` can't
     * produce.
     */
    conditionsNotOnOrAfterText: string;
    attributes: Readonly<Record<string, ReadonlyArray<string>>>;
    signedElements: MockSignedElements;
    signingKey: MockIdpKeyPair;
    /** Defaults to `MockHashAlgorithm.Sha256`, which is what ADFS uses. */
    hashAlgorithm: MockHashAlgorithm;
}>;

export enum MockSignedElements {
    Assertion = 'assertion',
    Response = 'response',
    Both = 'both',
    None = 'none',
}

export enum MockHashAlgorithm {
    Sha256 = 'sha256',
    Sha1 = 'sha1',
}

enum SignableElement {
    Assertion = 'Assertion',
    Response = 'Response',
}

/** Signing order matters: the Response signature must cover the already signed Assertion. */
const elementsToSign: Record<MockSignedElements, ReadonlyArray<SignableElement>> = {
    [MockSignedElements.Assertion]: [
        SignableElement.Assertion,
    ],
    [MockSignedElements.Response]: [
        SignableElement.Response,
    ],
    [MockSignedElements.Both]: [
        SignableElement.Assertion,
        SignableElement.Response,
    ],
    [MockSignedElements.None]: [],
};

const mockHashAlgorithms: Record<MockHashAlgorithm, {signature: string; digest: string}> = {
    [MockHashAlgorithm.Sha256]: {
        signature: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        digest: 'http://www.w3.org/2001/04/xmlenc#sha256',
    },
    [MockHashAlgorithm.Sha1]: {
        signature: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        digest: 'http://www.w3.org/2000/09/xmldsig#sha1',
    },
};

export function fromNow(duration: Readonly<AnyDuration>) {
    return calculateRelativeDate(getNowInUtcTimezone(), duration);
}

function escapeXml(value: string) {
    return value
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;');
}

const exclusiveC14n = 'http://www.w3.org/2001/10/xml-exc-c14n#';

function signElement({
    xml,
    localName,
    signingKey,
    hashAlgorithm,
}: Readonly<{
    xml: string;
    localName: SignableElement;
    signingKey: MockIdpKeyPair;
    hashAlgorithm: MockHashAlgorithm;
}>) {
    const elementXpath = `//*[local-name(.)='${localName}']`;
    const signedXml = new SignedXml({
        privateKey: signingKey.privateKey,
        /** Embeds the signer's certificate in KeyInfo, like ADFS does. It must never be trusted. */
        publicCert: signingKey.certificate,
        signatureAlgorithm: mockHashAlgorithms[hashAlgorithm].signature,
        canonicalizationAlgorithm: exclusiveC14n,
    });
    signedXml.addReference({
        xpath: elementXpath,
        transforms: [
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            exclusiveC14n,
        ],
        digestAlgorithm: mockHashAlgorithms[hashAlgorithm].digest,
    });
    signedXml.computeSignature(xml, {
        prefix: 'ds',
        location: {
            /** The schema requires the Signature right after the element's Issuer. */
            reference: `${elementXpath}/*[local-name(.)='Issuer']`,
            action: 'after',
        },
    });

    return signedXml.getSignedXml();
}

/** Builds the XML of an ADFS-style SAML response, before base64 encoding. */
export function createMockSamlResponseXml({
    assertionId = `_${crypto.randomUUID()}`,
    issuer = mockSaml.idpEntityId,
    audiences = [
        mockSaml.spEntityId,
    ],
    recipient = mockSaml.acsUrl,
    nameId = mockSaml.nameId,
    notBefore = fromNow({
        minutes: -1,
    }),
    notOnOrAfter = fromNow({
        minutes: 5,
    }),
    subjectNotOnOrAfter = notOnOrAfter,
    conditionsNotOnOrAfterText = toUtcIsoString(notOnOrAfter),
    attributes = {
        role: [
            'admin',
        ],
    },
    signedElements = MockSignedElements.Assertion,
    signingKey = mockIdpKeys.current,
    hashAlgorithm = MockHashAlgorithm.Sha256,
}: MockSamlResponseParams = {}) {
    const escapedIssuer = escapeXml(issuer);
    const issueInstant = toUtcIsoString(getNowInUtcTimezone());
    const escapedRecipient = escapeXml(recipient);
    const audiencesXml = audiences
        .map((audience) => `<saml:Audience>${escapeXml(audience)}</saml:Audience>`)
        .join('');
    const attributesXml = getObjectTypedEntries(attributes)
        .map(
            ([
                name,
                values,
            ]) => {
                return `<saml:Attribute Name="${escapeXml(name)}">${values
                    .map(
                        (value) => `<saml:AttributeValue>${escapeXml(value)}</saml:AttributeValue>`,
                    )
                    .join('')}</saml:Attribute>`;
            },
        )
        .join('');

    const xml = [
        `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_${crypto.randomUUID()}" Version="2.0" IssueInstant="${issueInstant}" Destination="${escapedRecipient}">`,
        `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${escapedIssuer}</saml:Issuer>`,
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>',
        `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${escapeXml(assertionId)}" IssueInstant="${issueInstant}" Version="2.0">`,
        `<saml:Issuer>${escapedIssuer}</saml:Issuer>`,
        '<saml:Subject>',
        `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${escapeXml(nameId)}</saml:NameID>`,
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">',
        `<saml:SubjectConfirmationData NotOnOrAfter="${toUtcIsoString(subjectNotOnOrAfter)}" Recipient="${escapedRecipient}"/>`,
        '</saml:SubjectConfirmation>',
        '</saml:Subject>',
        `<saml:Conditions NotBefore="${toUtcIsoString(notBefore)}" NotOnOrAfter="${conditionsNotOnOrAfterText}">`,
        `<saml:AudienceRestriction>${audiencesXml}</saml:AudienceRestriction>`,
        '</saml:Conditions>',
        `<saml:AttributeStatement>${attributesXml}</saml:AttributeStatement>`,
        `<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${escapeXml(assertionId)}">`,
        '<saml:AuthnContext><saml:AuthnContextClassRef>urn:federation:authentication:windows</saml:AuthnContextClassRef></saml:AuthnContext>',
        '</saml:AuthnStatement>',
        '</saml:Assertion>',
        '</samlp:Response>',
    ].join('');

    return elementsToSign[signedElements].reduce((currentXml, localName) => {
        return signElement({
            xml: currentXml,
            localName,
            signingKey,
            hashAlgorithm,
        });
    }, xml);
}

export function encodeSamlResponse(xml: string) {
    return Buffer.from(xml, 'utf8').toString('base64');
}

export function createMockSamlResponse(params: MockSamlResponseParams = {}) {
    return encodeSamlResponse(createMockSamlResponseXml(params));
}

export function createMockReplayStore() {
    const usedAssertionIds = new Set<string>();

    return {
        usedAssertionIds,
        markAssertionUsed({assertionId}: Readonly<{assertionId: string}>) {
            if (usedAssertionIds.has(assertionId)) {
                return false;
            }
            usedAssertionIds.add(assertionId);
            return true;
        },
    };
}
