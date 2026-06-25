"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const vitest_1 = require("vitest");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
require("./config.js");
(0, vitest_1.describe)('Signing options', () => {
    const xmlDocument = xmldsig.Parse(`<root><child id="child"/></root>`);
    const algorithm = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
    };
    let keys;
    (0, vitest_1.beforeAll)(async () => {
        keys = await xmldsig.Application.crypto.subtle.generateKey(algorithm, false, [
            'sign',
            'verify',
        ]);
    });
    async function Sign(options) {
        const signedXml = new xmldsig.SignedXml();
        await signedXml.Sign(algorithm, keys.privateKey, xmlDocument, options);
        return signedXml;
    }
    function Parse(xml) {
        const vXml = xmldsig.Parse(xml);
        const vSignature = vXml.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
        const signedXml = new xmldsig.SignedXml(vXml);
        signedXml.LoadXml(vSignature);
        return signedXml;
    }
    async function SignParse(options) {
        const xml = await Sign(options);
        return Parse(xml.toString());
    }
    (0, vitest_1.describe)('Signature', () => {
        (0, vitest_1.describe)('Id', () => {
            async function Check(value, expectedValue) {
                const signature = await SignParse({
                    id: value,
                    keyValue: keys.publicKey,
                    references: [
                        {
                            hash: 'SHA-256',
                            transforms: ['enveloped'],
                        },
                    ],
                });
                vitest_1.assert.equal(expectedValue, signature.XmlSignature.Id);
            }
            (0, vitest_1.it)('Empty', async () => {
                await Check(undefined, '');
            });
            (0, vitest_1.it)('Not empty', async () => {
                await Check('id-12345', 'id-12345');
            });
        });
    });
    (0, vitest_1.describe)('References', () => {
        (0, vitest_1.describe)('Uri', () => {
            async function Check(value, expectedValue) {
                const signature = await SignParse({
                    keyValue: keys.publicKey,
                    references: [
                        {
                            uri: value,
                            hash: 'SHA-256',
                            transforms: ['enveloped'],
                        },
                    ],
                });
                vitest_1.assert.equal(expectedValue, signature.XmlSignature.SignedInfo.References.Item(0)?.Uri);
            }
            (0, vitest_1.it)('Not present', async () => {
                await Check(undefined, undefined);
            });
            (0, vitest_1.it)('Empty string', async () => {
                await Check('', '');
            });
            (0, vitest_1.it)('Value', async () => {
                await Check('/', '/');
            });
        });
        (0, vitest_1.it)('Count', async () => {
            const signature = await SignParse({
                keyValue: keys.publicKey,
                references: [
                    {
                        hash: 'SHA-256',
                        transforms: ['enveloped'],
                    },
                    {
                        hash: 'SHA-1',
                        transforms: ['enveloped'],
                    },
                ],
            });
            vitest_1.assert.equal(2, signature.XmlSignature.SignedInfo.References.Count);
        });
    });
});
