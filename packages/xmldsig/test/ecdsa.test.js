"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const vitest_1 = require("vitest");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
require("./config.js");
(0, vitest_1.describe)('ECDSA', () => {
    ['P-256', 'P-384', 'P-521'].forEach((namedCurve) => {
        (0, vitest_1.describe)(namedCurve, () => {
            ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].forEach((hash) => {
                (0, vitest_1.it)(hash, async () => {
                    const signature = new xmldsig.SignedXml();
                    const keys = (await xmldsig.Application.crypto.subtle.generateKey({
                        name: 'ECDSA',
                        namedCurve,
                    }, true, ['sign', 'verify']));
                    await signature.Sign({ name: 'ECDSA', hash }, keys.privateKey, xmldsig.Parse(`<root><first id="id1"><foo>hello</foo></first></root>`), {
                        keyValue: keys.publicKey,
                        references: [{ hash, transforms: ['c14n'] }],
                    });
                    const signature2 = new xmldsig.SignedXml(xmldsig.Parse(`<root><first id="id1"><foo>hello</foo></first></root>`));
                    const xmlSignature = signature.XmlSignature.GetXml();
                    vitest_1.assert.ok(xmlSignature);
                    signature2.LoadXml(xmlSignature);
                    const si = signature2.XmlSignature.SignedInfo;
                    vitest_1.assert.equal(si.CanonicalizationMethod.Algorithm, 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
                    let signatureMethod;
                    switch (hash) {
                        case 'SHA-1':
                            signatureMethod = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1';
                            break;
                        case 'SHA-224':
                            signatureMethod = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224';
                            break;
                        case 'SHA-256':
                            signatureMethod = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
                            break;
                        case 'SHA-384':
                            signatureMethod = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
                            break;
                        case 'SHA-512':
                            signatureMethod = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';
                            break;
                    }
                    vitest_1.assert.equal(si.SignatureMethod.Algorithm, signatureMethod);
                    let digestMethod;
                    switch (hash) {
                        case 'SHA-1':
                            digestMethod = 'http://www.w3.org/2000/09/xmldsig#sha1';
                            break;
                        case 'SHA-224':
                            digestMethod = 'http://www.w3.org/2001/04/xmlenc#sha224';
                            break;
                        case 'SHA-256':
                            digestMethod = 'http://www.w3.org/2001/04/xmlenc#sha256';
                            break;
                        case 'SHA-384':
                            digestMethod = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
                            break;
                        case 'SHA-512':
                            digestMethod = 'http://www.w3.org/2001/04/xmlenc#sha512';
                            break;
                    }
                    vitest_1.assert.equal(si.References.Item(0)?.DigestMethod.Algorithm, digestMethod);
                    const ok = await signature2.Verify();
                    vitest_1.assert.equal(ok, true);
                });
            });
        });
    });
});
