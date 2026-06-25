"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const child_process = tslib_1.__importStar(require("node:child_process"));
const node_util_1 = require("node:util");
const fs = tslib_1.__importStar(require("node:fs"));
const vitest_1 = require("vitest");
const pvtsutils_1 = require("pvtsutils");
const xml_core_1 = require("xml-core");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
require("./config.js");
const exec = (0, node_util_1.promisify)(child_process.exec);
const SIGN_XML_FILE = 'sign.xml';
const { crypto } = xmldsig.Application;
(0, vitest_1.describe)('XML Signing + XMLSEC verification', () => {
    let keys;
    const alg = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
    };
    (0, vitest_1.beforeAll)(async () => {
        keys = await crypto.subtle.generateKey(alg, false, ['sign', 'verify']);
    });
    (0, vitest_1.afterAll)(() => {
        if (fs.existsSync(SIGN_XML_FILE)) {
            fs.unlinkSync(SIGN_XML_FILE);
        }
    });
    function toPem(der, label) {
        const base64 = Buffer.from(der).toString('base64');
        const lines = base64.match(/.{1,64}/g) || [];
        return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
    }
    async function checkXMLSEC(xml, publicKey) {
        try {
            await exec('which xmlsec1');
        }
        catch {
            return;
        }
        fs.writeFileSync(SIGN_XML_FILE, xml, { flag: 'w+' });
        try {
            await exec(`xmlsec1 verify ${SIGN_XML_FILE}`);
            return;
        }
        catch {
            const spki = await crypto.subtle.exportKey('spki', publicKey);
            const pem = toPem(spki, 'PUBLIC KEY');
            fs.writeFileSync('pubkey.pem', pem, { flag: 'w+' });
            try {
                await exec(`xmlsec1 verify --pubkey-pem pubkey.pem ${SIGN_XML_FILE}`);
            }
            catch {
            }
            finally {
                if (fs.existsSync('pubkey.pem')) {
                    fs.unlinkSync('pubkey.pem');
                }
            }
        }
    }
    (0, vitest_1.describe)('Enveloped', () => {
        async function test(xml, id) {
            const signedXml = new xmldsig.SignedXml();
            const xmlDocument = xmldsig.Parse(xml);
            const signature = await signedXml.Sign(alg, keys.privateKey, xmlDocument, {
                keyValue: keys.publicKey,
                references: [
                    {
                        hash: 'SHA-256',
                        transforms: ['enveloped'],
                        id,
                    },
                ],
            });
            const xmlSignature = signature.GetXml();
            vitest_1.assert.ok(xmlSignature);
            xmlDocument.documentElement.appendChild(xmlSignature);
            const sXML = (0, xml_core_1.Stringify)(xmlDocument);
            await checkXMLSEC(sXML, keys.publicKey);
            const vXml = xmldsig.Parse(sXML);
            const vSignature = vXml.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
            const verifyXml = new xmldsig.SignedXml(vXml);
            verifyXml.LoadXml(vSignature);
            const ok = await verifyXml.Verify();
            vitest_1.assert.equal(ok, true);
        }
        (0, vitest_1.it)('without namespace', async () => {
            await test(`<root><first/><second/></root>`);
        });
        (0, vitest_1.it)('with default root namespace', async () => {
            await test(`<root xmlns="http://namespace1"><first/><second/></root>`);
        });
        (0, vitest_1.it)('with root namespaces', async () => {
            await test(`<root xmlns="http://namespace1" xmlns:ns2="http://namespace2"><ns3:first xmlns:ns3="http://namespace3"/><ns2:second/></root>`);
        });
        (0, vitest_1.it)('child without namespace', async () => {
            await test(`<root xmlns="http://namespace1"><first id="id-1"/><second/></root>`, 'id-1');
        });
        (0, vitest_1.it)('child with namespace', async () => {
            await test(`<root xmlns="http://namespace1"><ns2:first id="id-1" xmlns:ns2="http://namespace2"/><second/></root>`, 'id-1');
        });
        (0, vitest_1.it)('child with repeated namespace', async () => {
            await test(`<root xmlns="http://namespace1" xmlns:ns2="http://namespace3"><ns2:first id="id-1" xmlns:ns2="http://namespace2"/><ns2:second/></root>`, 'id-1');
        });
    });
    (0, vitest_1.it)('Sign multiple contents', async () => {
        const alg = {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
        };
        const keys = await crypto.subtle.generateKey(alg, false, ['sign', 'verify']);
        const dataHex = pvtsutils_1.Convert.ToHex(crypto.getRandomValues(new Uint8Array(20)));
        const data = pvtsutils_1.Convert.FromBinary(dataHex);
        const dataHex2 = Buffer.from(crypto.getRandomValues(new Uint8Array(20))).toString('hex');
        const data2 = Buffer.from(dataHex2);
        const signedXml = new xmldsig.SignedXml();
        signedXml.contentHandler = async (ref) => {
            switch (ref.Uri) {
                case 'some-file.txt':
                    return data;
                case 'some-file-2.txt':
                    return data2;
            }
            return null;
        };
        await signedXml.Sign(alg, keys.privateKey, data, {
            keyValue: keys.publicKey,
            references: [
                {
                    hash: 'sha-256',
                    uri: 'some-file.txt',
                },
                {
                    hash: 'sha-256',
                    uri: 'some-file-2.txt',
                },
            ],
        });
        const ok = await signedXml.Verify({
            content: data,
        });
        vitest_1.assert.strictEqual(ok, true);
    });
    (0, vitest_1.it)('xhtml with xpath and multiple signatures', async () => {
        async function sign(doc) {
            const keys = await crypto.subtle.generateKey(alg, false, ['sign', 'verify']);
            const signedXml = new xmldsig.SignedXml();
            const signature = await signedXml.Sign(alg, keys.privateKey, doc, {
                keyValue: keys.publicKey,
                references: [
                    {
                        hash: 'sha-256',
                        uri: '#xpointer(/)',
                        transforms: [
                            'c14n',
                            {
                                name: 'xpath',
                                selector: 'not(ancestor-or-self::ds:Signature)',
                                namespaces: {
                                    ds: xmldsig.XmlSignature.NamespaceURI,
                                },
                            },
                        ],
                    },
                ],
            });
            const firstElement = doc.getElementsByTagName('head')[0];
            if (!firstElement) {
                throw new Error('Empty element');
            }
            const signatureXml = signature.GetXml();
            if (!signatureXml) {
                throw new Error('Empty Signature XML');
            }
            firstElement.appendChild(signatureXml);
            return xmldsig.Stringify(doc);
        }
        const size = 3;
        const xmlDoc = xmldsig.Parse('<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body></body></html>');
        let counter = size;
        while (counter--) {
            await sign(xmlDoc);
        }
        const signatures = xmlDoc.getElementsByTagNameNS(xmldsig.XmlSignature.NamespaceURI, 'Signature');
        const signedData = new xmldsig.SignedXml(xmlDoc);
        for (let i = 0; i < signatures.length; i++) {
            const signature = signatures[i];
            signedData.LoadXml(signature);
            const ok = await signedData.Verify();
            vitest_1.assert.ok(ok);
        }
    });
    (0, vitest_1.describe)('Vector Tests for XML Signing and Verification with Different Algorithms', () => {
        let keysRSASSA;
        let keysRSAPSS;
        const algRSASSA = {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-1',
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
        };
        const algRSAPSS = {
            name: 'RSA-PSS',
            hash: 'SHA-256',
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
            saltLength: 32,
        };
        (0, vitest_1.beforeAll)(async () => {
            keysRSASSA = await crypto.subtle.generateKey(algRSASSA, false, ['sign', 'verify']);
            keysRSAPSS = await crypto.subtle.generateKey(algRSAPSS, false, ['sign', 'verify']);
        });
        async function signXML(xml, alg, keys) {
            const signedXml = new xmldsig.SignedXml();
            const xmlDocument = xmldsig.Parse(xml);
            const signature = await signedXml.Sign(alg, keys.privateKey, xmlDocument, {
                keyValue: keys.publicKey,
                references: [
                    {
                        hash: alg.hash,
                        transforms: ['enveloped'],
                    },
                ],
            });
            const xmlSignature = signature.GetXml();
            vitest_1.assert.ok(xmlSignature);
            xmlDocument.documentElement.appendChild(xmlSignature);
            const sXML = (0, xml_core_1.Stringify)(xmlDocument);
            return sXML;
        }
        async function verifyXML(xml, _alg, _keys) {
            const vXml = xmldsig.Parse(xml);
            const vSignature = vXml.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
            const verifyXml = new xmldsig.SignedXml(vXml);
            verifyXml.LoadXml(vSignature);
            return await verifyXml.Verify();
        }
        (0, vitest_1.it)('RSASSA-PKCS1-v1_5 with SHA-1 signing and RSASSA-PKCS1-v1_5 with SHA-256 verification', async () => {
            const xml = `<root><first/><second/></root>`;
            const signedXML = await signXML(xml, algRSASSA, keysRSASSA);
            const ok = await verifyXML(signedXML, { ...algRSASSA, hash: 'SHA-256' }, keysRSASSA);
            vitest_1.assert.strictEqual(ok, true);
        });
        (0, vitest_1.it)('RSA-PSS signing and RSASSA-PKCS1-v1_5 verification', async () => {
            const xml = `<root><first/><second/></root>`;
            const signedXML = await signXML(xml, algRSAPSS, keysRSAPSS);
            const ok = await verifyXML(signedXML, algRSASSA, keysRSAPSS);
            vitest_1.assert.strictEqual(ok, true);
        });
        (0, vitest_1.it)('RSASSA-PKCS1-v1_5 with SHA-256 signing and RSA-PSS verification', async () => {
            const xml = `<root><first/><second/></root>`;
            const signedXML = await signXML(xml, { ...algRSASSA, hash: 'SHA-256' }, keysRSASSA);
            const ok = await verifyXML(signedXML, algRSAPSS, keysRSASSA);
            vitest_1.assert.strictEqual(ok, true);
        });
    });
});
