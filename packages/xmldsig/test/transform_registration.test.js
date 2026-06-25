"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const vitest_1 = require("vitest");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
require("./config.js");
const CUSTOM_TRANSFORM_NAMESPACE = 'urn:custom:transform';
class CustomTransformation extends xmldsig.Transform {
    constructor() {
        super(...arguments);
        this.Algorithm = CUSTOM_TRANSFORM_NAMESPACE;
    }
    GetOutput() {
        if (!this.innerXml) {
            throw new Error('innerXml is required');
        }
        const result = xmldsig.Stringify(this.innerXml);
        return result;
    }
}
(0, vitest_1.describe)('Transform Registration', () => {
    (0, vitest_1.beforeAll)(() => {
        xmldsig.CryptoConfig.RegisterTransform(CUSTOM_TRANSFORM_NAMESPACE, CustomTransformation);
    });
    (0, vitest_1.it)('should register and use custom transform', () => {
        const transform = xmldsig.CryptoConfig.CreateFromName(CUSTOM_TRANSFORM_NAMESPACE);
        vitest_1.assert.ok(transform instanceof CustomTransformation);
        vitest_1.assert.equal(transform.Algorithm, CUSTOM_TRANSFORM_NAMESPACE);
    });
    (0, vitest_1.it)('should use custom transform with XML', () => {
        const transform = xmldsig.CryptoConfig.CreateFromName(CUSTOM_TRANSFORM_NAMESPACE);
        const doc = xmldsig.Parse('<root><child>test</child></root>');
        transform.LoadInnerXml(doc.documentElement);
        const output = transform.GetOutput();
        vitest_1.assert.ok(output.includes('<root'));
        vitest_1.assert.ok(output.includes('test'));
    });
    (0, vitest_1.it)('should preserve backward compatibility with built-in transforms', () => {
        const c14nTransform = xmldsig.CryptoConfig.CreateFromName('http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        vitest_1.assert.ok(c14nTransform instanceof xmldsig.XmlDsigC14NTransform);
    });
    (0, vitest_1.it)('should allow overriding built-in transforms', () => {
        const customNamespace = 'http://www.w3.org/2000/09/xmldsig#base64';
        class CustomBase64Transform extends xmldsig.Transform {
            constructor() {
                super(...arguments);
                this.Algorithm = customNamespace;
            }
            GetOutput() {
                return 'custom-base64-output';
            }
        }
        xmldsig.CryptoConfig.RegisterTransform(customNamespace, CustomBase64Transform);
        const transform = xmldsig.CryptoConfig.CreateFromName(customNamespace);
        vitest_1.assert.ok(transform instanceof CustomBase64Transform);
        xmldsig.CryptoConfig.RegisterTransform(customNamespace, xmldsig.XmlDsigBase64Transform);
    });
    (0, vitest_1.it)('should use custom transform in SignedXml', async () => {
        const { crypto } = xmldsig.Application;
        const keys = (await crypto.subtle.generateKey({
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
        }, false, ['sign', 'verify']));
        const xmlDocument = xmldsig.Parse('<root><data>test data</data></root>');
        const signedXml = new xmldsig.SignedXml();
        const signature = await signedXml.Sign({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, keys.privateKey, xmlDocument, {
            keyValue: keys.publicKey,
            references: [
                {
                    hash: 'SHA-256',
                    transforms: [CUSTOM_TRANSFORM_NAMESPACE, 'c14n'],
                    uri: '',
                },
            ],
        });
        const signatureXml = signature.GetXml();
        vitest_1.assert.ok(signatureXml);
        const transformElements = signatureXml.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Transform');
        let foundCustomTransform = false;
        for (let i = 0; i < transformElements.length; i++) {
            const algorithm = transformElements[i].getAttribute('Algorithm');
            if (algorithm === CUSTOM_TRANSFORM_NAMESPACE) {
                foundCustomTransform = true;
            }
        }
        vitest_1.assert.ok(foundCustomTransform, 'Custom transform should be present in signature');
    });
    (0, vitest_1.it)('should verify signature with custom transform', async () => {
        const { crypto } = xmldsig.Application;
        const keys = (await crypto.subtle.generateKey({
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
        }, false, ['sign', 'verify']));
        const xmlDocument = xmldsig.Parse('<root><data>test data</data></root>');
        const signedXml = new xmldsig.SignedXml();
        signedXml.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm = CUSTOM_TRANSFORM_NAMESPACE;
        const signature = await signedXml.Sign({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, keys.privateKey, xmlDocument, {
            keyValue: keys.publicKey,
            references: [
                {
                    hash: 'SHA-256',
                    transforms: [CUSTOM_TRANSFORM_NAMESPACE, 'enveloped', 'c14n'],
                    uri: '',
                },
            ],
        });
        const signatureXml = signature.GetXml();
        vitest_1.assert.ok(signatureXml);
        xmlDocument.documentElement.appendChild(signatureXml);
        const signatureString = signature.toString();
        vitest_1.assert.ok(signatureString.includes('CanonicalizationMethod Algorithm="urn:custom:transform"'));
        vitest_1.assert.ok(signatureString.includes('Transform Algorithm="urn:custom:transform"'));
        const signedXmlVerify = new xmldsig.SignedXml(xmlDocument);
        signedXmlVerify.LoadXml(signatureXml);
        const isValid = await signedXmlVerify.Verify(keys.publicKey);
        vitest_1.assert.ok(isValid, 'Signature with custom transform should be valid');
    });
});
