"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vitest_1 = require("vitest");
require("../../../test/config.js");
const application_js_1 = require("../../application.js");
const spki_data_js_1 = require("./spki_data.js");
async function generateTestKey(alg = 'RSASSA-PKCS1-v1_5') {
    if (alg === 'RSASSA-PKCS1-v1_5') {
        return application_js_1.Application.crypto.subtle.generateKey({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        }, true, ['sign', 'verify']);
    }
    else {
        return application_js_1.Application.crypto.subtle.generateKey({
            name: 'ECDSA',
            namedCurve: 'P-256',
        }, true, ['sign', 'verify']);
    }
}
(0, vitest_1.describe)('SPKIData', () => {
    let publicKey;
    let _privateKey;
    (0, vitest_1.beforeAll)(async () => {
        const keyPair = await generateTestKey();
        publicKey = keyPair.publicKey;
        _privateKey = keyPair.privateKey;
    });
    (0, vitest_1.it)('importKey sets SPKIexp and Key', async () => {
        const spkiData = new spki_data_js_1.SPKIData();
        await spkiData.importKey(publicKey);
        (0, vitest_1.expect)(spkiData.SPKIexp).toBeInstanceOf(Uint8Array);
        (0, vitest_1.expect)(spkiData.Key).toBe(publicKey);
    });
    (0, vitest_1.it)('exportKey throws if SPKIexp is not set', async () => {
        const spkiData = new spki_data_js_1.SPKIData();
        await (0, vitest_1.expect)(() => spkiData.exportKey({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' })).rejects.toThrow('SPKI data is not defined');
    });
    (0, vitest_1.it)('exportKey returns CryptoKey and sets Key', async () => {
        const spkiData = new spki_data_js_1.SPKIData();
        await spkiData.importKey(publicKey);
        const key = await spkiData.exportKey({
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
        });
        (0, vitest_1.expect)(key.type).toBe('public');
        (0, vitest_1.expect)(spkiData.Key).toBe(key);
    });
});
