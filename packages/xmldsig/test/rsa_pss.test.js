"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const vitest_1 = require("vitest");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
require("./config.js");
(0, vitest_1.describe)('RSA-PSS', () => {
    [1024, 2048].forEach((modulusLength) => {
        [new Uint8Array([1, 0, 1])].forEach((publicExponent) => {
            (0, vitest_1.describe)(`n:${modulusLength} e:${publicExponent[0] === 1 ? 65537 : 3}`, () => {
                ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].forEach((hash) => {
                    [32, 64].forEach((saltLength) => {
                        if (hash === 'SHA-512' && saltLength === 64) {
                            return;
                        }
                        (0, vitest_1.it)(`hash:${hash} salt:${saltLength}`, async () => {
                            const signature = new xmldsig.SignedXml();
                            const keys = (await xmldsig.Application.crypto.subtle.generateKey({
                                name: 'RSA-PSS',
                                hash,
                                modulusLength,
                                publicExponent,
                            }, true, ['sign', 'verify']));
                            const alg = { name: 'RSA-PSS' };
                            if (saltLength) {
                                alg['saltLength'] = saltLength;
                            }
                            await signature.Sign(alg, keys.privateKey, xmldsig.Parse(`<root><first id="id1"><foo>hello</foo></first></root>`), {
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
                                case 'SHA-224':
                                case 'SHA-256':
                                case 'SHA-384':
                                case 'SHA-512':
                                    signatureMethod = 'http://www.w3.org/2007/05/xmldsig-more#rsa-pss';
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
                            vitest_1.assert.equal(si.SignatureMethod.Any.Count, 1);
                            const pss = si.SignatureMethod.Any.Item(0);
                            vitest_1.assert.equal(pss.DigestMethod.Algorithm, digestMethod);
                            vitest_1.assert.equal(pss.SaltLength, saltLength);
                            const ok = await signature2.Verify();
                            vitest_1.assert.equal(ok, true);
                        });
                    });
                });
            });
        });
    });
    (0, vitest_1.describe)('No params URI', () => {
        const vectors = [
            {
                hash: 'SHA-1',
                saltLength: 20,
                namespace: xmldsig.RSA_PSS_SHA1_NAMESPACE,
                algorithm: xmldsig.RsaPssWithoutParamsSha1,
            },
            {
                hash: 'SHA-256',
                saltLength: 32,
                namespace: xmldsig.RSA_PSS_SHA256_NAMESPACE,
                algorithm: xmldsig.RsaPssWithoutParamsSha256,
            },
            {
                hash: 'SHA-384',
                saltLength: 48,
                namespace: xmldsig.RSA_PSS_SHA384_NAMESPACE,
                algorithm: xmldsig.RsaPssWithoutParamsSha384,
            },
            {
                hash: 'SHA-512',
                saltLength: 64,
                namespace: xmldsig.RSA_PSS_SHA512_NAMESPACE,
                algorithm: xmldsig.RsaPssWithoutParamsSha512,
            },
        ];
        vectors.forEach((vector) => {
            (0, vitest_1.it)(`resolves ${vector.hash} namespace and signs/verifies`, async () => {
                const method = xmldsig.CryptoConfig.CreateSignatureMethod(new vector.algorithm());
                vitest_1.assert.equal(method.Algorithm, vector.namespace);
                vitest_1.assert.equal(method.Any.Count, 0);
                const resolved = xmldsig.CryptoConfig.CreateSignatureAlgorithm(method);
                vitest_1.assert.equal(resolved.algorithm.name, 'RSA-PSS');
                vitest_1.assert.equal(resolved.algorithm.hash.name, vector.hash);
                vitest_1.assert.equal(resolved.algorithm.saltLength, vector.saltLength);
                const algorithm = new vector.algorithm();
                const data = '<SignedInfo />';
                const keys = (await xmldsig.Application.crypto.subtle.generateKey({
                    name: 'RSA-PSS',
                    hash: vector.hash,
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                }, true, ['sign', 'verify']));
                const signature = await algorithm.Sign(data, keys.privateKey, algorithm.algorithm);
                const ok = await algorithm.Verify(data, keys.publicKey, new Uint8Array(signature));
                vitest_1.assert.equal(ok, true);
            });
        });
    });
});
