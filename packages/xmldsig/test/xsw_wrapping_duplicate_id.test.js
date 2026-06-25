"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const vitest_1 = require("vitest");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
require("./config.js");
(0, vitest_1.describe)('Security: XSW (duplicate Id shadowing)', () => {
    (0, vitest_1.it)('rejects signature when same Id exists in document and ds:Object', async () => {
        const keys = (await xmldsig.Application.crypto.subtle.generateKey({
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
        }, true, ['sign', 'verify']));
        const doc = xmldsig.Parse(`<Transaction><Payment Id="payment-001"><Amount currency="USD">500.00</Amount><Recipient>Bob</Recipient><Reference>Invoice-12345</Reference></Payment></Transaction>`);
        const signer = new xmldsig.SignedXml();
        await signer.Sign({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, keys.privateKey, doc, {
            keyValue: keys.publicKey,
            references: [{ uri: '#payment-001', hash: 'SHA-256', transforms: ['exc-c14n'] }],
        });
        const sigXml = signer.GetXml();
        vitest_1.assert.ok(sigXml);
        doc.documentElement.appendChild(sigXml);
        {
            const verifyDoc = xmldsig.Parse(xmldsig.Stringify(doc));
            const signatureEl = verifyDoc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
            const verifier = new xmldsig.SignedXml(verifyDoc);
            verifier.LoadXml(signatureEl);
            const ok = await verifier.Verify(keys.publicKey);
            vitest_1.assert.equal(ok, true);
        }
        const attackDoc = xmldsig.Parse(xmldsig.Stringify(doc));
        const signatureEl = attackDoc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
        vitest_1.assert.ok(signatureEl);
        const paymentEl = xmldsig.Select(attackDoc, '//*[local-name()="Payment"]')[0];
        vitest_1.assert.ok(paymentEl);
        const originalPayment = paymentEl.cloneNode(true);
        const amountEl = xmldsig.Select(paymentEl, './*[local-name()="Amount"]')[0];
        const recipientEl = xmldsig.Select(paymentEl, './*[local-name()="Recipient"]')[0];
        vitest_1.assert.ok(amountEl);
        vitest_1.assert.ok(recipientEl);
        amountEl.textContent = '999999.99';
        recipientEl.textContent = 'Attacker';
        const objectEl = attackDoc.createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Object');
        objectEl.setAttribute('Id', 'wrapped');
        objectEl.appendChild(originalPayment);
        signatureEl.appendChild(objectEl);
        const verifier2 = new xmldsig.SignedXml(attackDoc);
        verifier2.LoadXml(signatureEl);
        let err = null;
        try {
            await verifier2.Verify(keys.publicKey);
        }
        catch (e) {
            err = e;
        }
        vitest_1.assert.ok(err, 'Expected verification to fail');
        vitest_1.assert.match(String(err.message || err), /Duplicate Id 'payment-001' detected in both the signed document and Signature objects/);
    });
});
