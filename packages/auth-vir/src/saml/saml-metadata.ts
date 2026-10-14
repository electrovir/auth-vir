// cspell:words dsig idpsso nameid
import {removeDuplicates, type PartialWithUndefined} from '@augment-vir/common';
import {generateServiceProviderMetadata} from '@node-saml/node-saml';
import {type Element} from '@xmldom/xmldom';
import {X509Certificate} from 'node:crypto';
import {
    getAttribute,
    getChildElements,
    getElementText,
    getOnlyChildElement,
    isXmlElement,
    parseStrictXml,
    SamlNamespace,
} from './saml-xml.js';

/**
 * The parts of an IdP's SAML metadata needed to accept sign-ins from it. Output of
 * {@link parseIdpMetadata}.
 *
 * @category Internal
 */
export type ParsedIdpMetadata = {
    entityId: string;
    /**
     * The IdP's `SingleSignOnService` location. The HTTP-Redirect binding is preferred, then
     * HTTP-POST.
     */
    ssoUrl: string;
    /** Every signing certificate listed in the metadata, PEM encoded. */
    signingCertificates: string[];
};

/**
 * NameID formats defined in SAML core 8.3.
 *
 * @category Internal
 */
export enum SamlNameIdFormat {
    Unspecified = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    EmailAddress = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    X509SubjectName = 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
    WindowsDomainQualifiedName = 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
    Kerberos = 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
    Entity = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
    Persistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    Transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
}

enum SamlBinding {
    HttpRedirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    HttpPost = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
}

/**
 * The SAML bindings `ssoUrl` can come from, most preferred first. HTTP-Redirect is a plain link the
 * app can send users to for SP-initiated sign-in; HTTP-POST needs an auto-submitting form instead.
 */
const ssoBindingPreference = [
    SamlBinding.HttpRedirect,
    SamlBinding.HttpPost,
];

/**
 * Parse an IdP's SAML metadata XML (the metadata XML the IdP publishes). Throws an `Error` with a
 * human-readable message if the metadata is invalid.
 *
 * The metadata's own signature is not checked: the admin who pastes it in is trusted to have
 * obtained it from the right place.
 *
 * @category SAML
 */
export function parseIdpMetadata(metadataXml: string): ParsedIdpMetadata {
    /** `trimStart` also removes a UTF-8 BOM, which Node keeps when reading a file as utf8. */
    const entityDescriptor = parseStrictXml(metadataXml.trimStart());

    if (!isXmlElement(entityDescriptor, SamlNamespace.Metadata, 'EntityDescriptor')) {
        throw new Error('Metadata root element must be a SAML 2.0 EntityDescriptor.');
    }

    const entityId = getAttribute(entityDescriptor, 'entityID');
    if (!entityId) {
        throw new Error('Metadata EntityDescriptor has no entityID.');
    }

    const idpDescriptor = getOnlyChildElement(
        entityDescriptor,
        SamlNamespace.Metadata,
        'IDPSSODescriptor',
    );
    if (!idpDescriptor) {
        throw new Error('Metadata has no IDPSSODescriptor.');
    }

    const signingCertificates = readSigningCertificates(idpDescriptor);
    if (!signingCertificates.length) {
        throw new Error('Metadata has no signing certificates.');
    }

    return {
        entityId,
        ssoUrl: readSsoUrl(idpDescriptor),
        signingCertificates,
    };
}

function readSsoUrl(idpDescriptor: Readonly<Element>) {
    const services = getChildElements(idpDescriptor, SamlNamespace.Metadata, 'SingleSignOnService');

    for (const binding of ssoBindingPreference) {
        const service = services.find((candidate) => {
            return (
                getAttribute(candidate, 'Binding') === binding &&
                getAttribute(candidate, 'Location')
            );
        });
        const location = service && getAttribute(service, 'Location');

        if (location) {
            return location;
        }
    }

    throw new Error('Metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService.');
}

function readSigningCertificates(idpDescriptor: Readonly<Element>) {
    const certificates = getChildElements(idpDescriptor, SamlNamespace.Metadata, 'KeyDescriptor')
        /** A KeyDescriptor without a `use` is usable for both signing and encryption. */
        .filter((keyDescriptor) => (getAttribute(keyDescriptor, 'use') ?? 'signing') === 'signing')
        .flatMap((keyDescriptor) => {
            return Array.from(
                keyDescriptor.getElementsByTagNameNS(SamlNamespace.XmlDsig, 'X509Certificate'),
            );
        })
        .map((certificate) => toPemCertificate(getElementText(certificate)));

    return removeDuplicates(certificates);
}

function toPemCertificate(base64Certificate: string) {
    const base64 = base64Certificate.replaceAll(/\s/g, '');

    if (!base64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
        throw new Error('Metadata contains an X509Certificate that is not valid base64.');
    }

    const pem = [
        '-----BEGIN CERTIFICATE-----',
        ...(base64.match(/.{1,64}/g) || []),
        '-----END CERTIFICATE-----',
    ].join('\n');

    try {
        return new X509Certificate(pem).toString().trimEnd();
    } catch (error) {
        throw new Error(
            'Metadata contains an X509Certificate that is not a valid X.509 certificate.',
            {
                cause: error,
            },
        );
    }
}

/**
 * Params for {@link generateSpMetadata}.
 *
 * @category Internal
 */
export type GenerateSpMetadataParams = Readonly<{
    /** Our SP entity ID. Must match `spEntityId` given to `verifySamlResponse`. */
    entityId: string;
    /** Our Assertion Consumer Service URL. Must match `acsUrl` given to `verifySamlResponse`. */
    acsUrl: string;
}> &
    Readonly<
        PartialWithUndefined<{
            /**
             * The NameID format to request from the IdP.
             *
             * @default SamlNameIdFormat.EmailAddress
             */
            nameIdFormat: SamlNameIdFormat;
        }>
    >;

/**
 * Generate our SP metadata XML, for an IdP admin to import. It declares that assertions must be
 * signed and that our requests are not signed.
 *
 * @category SAML
 */
export function generateSpMetadata({entityId, acsUrl, nameIdFormat}: GenerateSpMetadataParams) {
    return generateServiceProviderMetadata({
        issuer: entityId,
        callbackUrl: acsUrl,
        wantAssertionsSigned: true,
        identifierFormat: nameIdFormat || SamlNameIdFormat.EmailAddress,
    });
}
