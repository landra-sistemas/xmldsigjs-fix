"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const vitest_1 = require("vitest");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
require("./config.js");
const ED25519_NAMESPACE = 'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519';
const SHAKE256_NAMESPACE = 'http://www.w3.org/2021/04/xmldsig-more#shake256';
const crypto = xmldsig.Application.crypto;
class Shake256 extends xmldsig.HashAlgorithm {
    constructor() {
        super(...arguments);
        this.algorithm = { name: 'SHAKE256' };
        this.namespaceURI = SHAKE256_NAMESPACE;
    }
    async Digest(xml) {
        let buf;
        if (typeof xml === 'string') {
            buf = new TextEncoder().encode(xml);
        }
        else if (ArrayBuffer.isView(xml)) {
            buf = new Uint8Array(xml.buffer);
        }
        else if (xml instanceof ArrayBuffer) {
            buf = new Uint8Array(xml);
        }
        else {
            const txt = xmldsig.Stringify(xml);
            buf = new TextEncoder().encode(txt);
        }
        const hashAlgorithm = { name: 'SHAKE256', length: 32 };
        const hash = await crypto.subtle.digest(hashAlgorithm, buf);
        return new Uint8Array(hash);
    }
}
class Ed25519Signature extends xmldsig.SignatureAlgorithm {
    constructor() {
        super(...arguments);
        this.algorithm = { name: 'Ed25519' };
        this.namespaceURI = ED25519_NAMESPACE;
    }
    static fromAlgorithm(alg) {
        if (alg.name.toUpperCase() === 'ED25519') {
            return new Ed25519Signature();
        }
        return null;
    }
    async Sign(signedInfo, signingKey, _algorithm) {
        const info = new TextEncoder().encode(signedInfo);
        return crypto.subtle.sign('Ed25519', signingKey, info);
    }
    async Verify(signedInfo, key, signatureValue, _algorithm) {
        const info = new TextEncoder().encode(signedInfo);
        return crypto.subtle.verify('Ed25519', key, signatureValue, info);
    }
}
let Ed25519KeyValue = class Ed25519KeyValue extends xmldsig.KeyInfoClause {
    static canImportCryptoKey(key) {
        return key.algorithm.name === 'Ed25519';
    }
    async importKey(key) {
        if (key.algorithm.name !== 'Ed25519') {
            throw new Error('Key algorithm must be Ed25519');
        }
        const keyData = await crypto.subtle.exportKey('raw', key);
        this.PublicKey = new Uint8Array(keyData);
        this.Key = key;
        return this;
    }
    async exportKey(alg) {
        if (!this.PublicKey) {
            throw new Error('PublicKey is not set');
        }
        const algorithm = alg || { name: 'Ed25519' };
        return crypto.subtle.importKey('raw', this.PublicKey, algorithm, true, ['verify']);
    }
};
tslib_1.__decorate([
    xmldsig.XmlChildElement({
        localName: 'PublicKey',
        namespaceURI: 'http://www.w3.org/2021/04/xmldsig-more#',
        prefix: 'dsig11',
    }),
    tslib_1.__metadata("design:type", Uint8Array)
], Ed25519KeyValue.prototype, "PublicKey", void 0);
Ed25519KeyValue = tslib_1.__decorate([
    xmldsig.XmlElement({
        localName: 'Ed25519KeyValue',
        namespaceURI: 'http://www.w3.org/2021/04/xmldsig-more#',
        prefix: 'dsig11',
    })
], Ed25519KeyValue);
(0, vitest_1.describe)('Dynamic Algorithm Registration', () => {
    (0, vitest_1.beforeAll)(() => {
        xmldsig.CryptoConfig.RegisterHashAlgorithm(SHAKE256_NAMESPACE, Shake256);
        xmldsig.CryptoConfig.RegisterSignatureAlgorithm(ED25519_NAMESPACE, Ed25519Signature);
        xmldsig.CryptoConfig.RegisterKeyInfoClause('Ed25519', Ed25519KeyValue);
    });
    (0, vitest_1.it)('should register and use SHAKE256 hash algorithm', async () => {
        const shake256 = xmldsig.CryptoConfig.CreateHashAlgorithm(SHAKE256_NAMESPACE);
        vitest_1.assert.ok(shake256 instanceof Shake256);
        const testData = 'Hello, SHAKE256!';
        const hash = await shake256.Digest(testData);
        vitest_1.assert.ok(hash instanceof Uint8Array);
        vitest_1.assert.equal(hash.length, 32);
    });
    (0, vitest_1.it)('should register and use Ed25519 signature algorithm', async () => {
        const keyPair = (await crypto.subtle.generateKey('Ed25519', true, [
            'sign',
            'verify',
        ]));
        const ed25519Alg = new Ed25519Signature();
        const testMessage = 'Hello, Ed25519!';
        const signature = await ed25519Alg.Sign(testMessage, keyPair.privateKey, { name: 'Ed25519' });
        vitest_1.assert.ok(signature instanceof ArrayBuffer);
        const isValid = await ed25519Alg.Verify(testMessage, keyPair.publicKey, new Uint8Array(signature));
        vitest_1.assert.ok(isValid);
    });
    (0, vitest_1.it)('should register and use Ed25519 KeyValue', async () => {
        const keyPair = (await crypto.subtle.generateKey('Ed25519', true, [
            'sign',
            'verify',
        ]));
        const keyValue = new xmldsig.KeyValue();
        await keyValue.importKey(keyPair.publicKey);
        vitest_1.assert.ok(keyValue.Value instanceof Ed25519KeyValue);
        const exportedKey = await keyValue.exportKey();
        vitest_1.assert.equal(exportedKey.algorithm.name, 'Ed25519');
        vitest_1.assert.equal(exportedKey.type, 'public');
    });
    (0, vitest_1.it)('should create and verify XML signature with Ed25519 and SHAKE256', async () => {
        const keyPair = (await crypto.subtle.generateKey('Ed25519', true, [
            'sign',
            'verify',
        ]));
        const ed25519Alg = new Ed25519Signature();
        const shake256Alg = new Shake256();
        const testMessage = 'Test message for signing with Ed25519';
        const messageHash = await shake256Alg.Digest(testMessage);
        const signature = await ed25519Alg.Sign(testMessage, keyPair.privateKey, { name: 'Ed25519' });
        const isValid = await ed25519Alg.Verify(testMessage, keyPair.publicKey, new Uint8Array(signature));
        vitest_1.assert.ok(isValid, 'Ed25519 signature should be valid');
        vitest_1.assert.ok(messageHash.length === 32, 'SHAKE256 should produce 32 bytes');
    });
    (0, vitest_1.it)('should preserve backward compatibility with existing algorithms', async () => {
        const keyPair = (await crypto.subtle.generateKey({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        }, true, ['sign', 'verify']));
        const rsaAlg = xmldsig.CryptoConfig.GetSignatureAlgorithm({
            name: 'RSASSA-PKCS1-v1_5',
            hash: { name: 'SHA-256' },
        });
        const testMessage = 'Test message for RSA signing';
        const signature = await rsaAlg.Sign(testMessage, keyPair.privateKey, {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
        });
        const isValid = await rsaAlg.Verify(testMessage, keyPair.publicKey, new Uint8Array(signature));
        vitest_1.assert.ok(isValid, 'RSA signature should still work');
    });
});
