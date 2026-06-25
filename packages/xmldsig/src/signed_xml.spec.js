"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const vitest_1 = require("vitest");
require("../test/config.js");
const xmldsig = tslib_1.__importStar(require("./index.js"));
class TestSignedXml extends xmldsig.SignedXml {
    getPublicKeys() {
        return this.GetPublicKeys();
    }
}
function createSignedXmlWithMethod(method) {
    const doc = xmldsig.Parse('<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" />');
    const signedXml = new TestSignedXml(doc);
    signedXml.XmlSignature.SignedInfo.SignatureMethod = method;
    return signedXml;
}
async function createRsaPssPublicKey() {
    const keyPair = (await xmldsig.Application.crypto.subtle.generateKey({
        name: 'RSA-PSS',
        hash: 'SHA-256',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
    }, true, ['sign', 'verify']));
    return keyPair.publicKey;
}
function addX509ExportStub(signedXml, publicKey) {
    let seenAlgorithm;
    const cert = {
        exportKey: async (alg) => {
            seenAlgorithm = alg;
            return publicKey;
        },
    };
    const x509Data = new xmldsig.KeyInfoX509Data();
    x509Data.AddCertificate(cert);
    signedXml.XmlSignature.KeyInfo.Add(x509Data);
    return () => seenAlgorithm;
}
(0, vitest_1.describe)('SignedXml', () => {
    (0, vitest_1.describe)('GetPublicKeys', () => {
        (0, vitest_1.it)('passes the resolved signature algorithm to X509 certificate export', async () => {
            const algorithm = { name: 'RSA-PSS', hash: { name: 'SHA-256' }, saltLength: 32 };
            const signatureAlgorithm = xmldsig.CryptoConfig.GetSignatureAlgorithm(algorithm);
            const method = xmldsig.CryptoConfig.CreateSignatureMethod(signatureAlgorithm);
            const signedXml = createSignedXmlWithMethod(method);
            const publicKey = await createRsaPssPublicKey();
            const getSeenAlgorithm = addX509ExportStub(signedXml, publicKey);
            const keys = await signedXml.getPublicKeys();
            const seenAlgorithm = getSeenAlgorithm();
            vitest_1.assert.equal(keys.length, 1);
            vitest_1.assert.equal(seenAlgorithm?.name, 'RSA-PSS');
            vitest_1.assert.equal(seenAlgorithm.hash.name, 'SHA-256');
            vitest_1.assert.equal(seenAlgorithm.saltLength, 32);
        });
        (0, vitest_1.it)('supports RSA-PSS no-params URI (sha256-rsa-MGF1) for X509 certificate export', async () => {
            const method = xmldsig.CryptoConfig.CreateSignatureMethod(new xmldsig.RsaPssWithoutParamsSha256());
            const signedXml = createSignedXmlWithMethod(method);
            const publicKey = await createRsaPssPublicKey();
            const getSeenAlgorithm = addX509ExportStub(signedXml, publicKey);
            const keys = await signedXml.getPublicKeys();
            const seenAlgorithm = getSeenAlgorithm();
            vitest_1.assert.equal(keys.length, 1);
            vitest_1.assert.equal(signedXml.XmlSignature.SignedInfo.SignatureMethod.Algorithm, xmldsig.RSA_PSS_SHA256_NAMESPACE);
            vitest_1.assert.equal(signedXml.XmlSignature.SignedInfo.SignatureMethod.Any.Count, 0);
            vitest_1.assert.equal(seenAlgorithm?.name, 'RSA-PSS');
            vitest_1.assert.equal(seenAlgorithm.hash.name, 'SHA-256');
            vitest_1.assert.equal(seenAlgorithm.saltLength, 32);
        });
    });
});
