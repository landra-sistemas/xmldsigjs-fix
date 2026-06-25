"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const vitest_1 = require("vitest");
const xml_core_1 = require("xml-core");
require("../test/config.js");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
(0, vitest_1.describe)('Transforms', () => {
    (0, vitest_1.describe)('base64', () => {
        (0, vitest_1.it)('GetOutput error', () => {
            const transform = new xmldsig.XmlDsigBase64Transform();
            vitest_1.assert.throws(() => {
                transform.GetOutput();
            });
        });
        (0, vitest_1.it)('GetOutput with content', () => {
            const transform = new xmldsig.XmlDsigBase64Transform();
            const node = xmldsig.Parse('<test>AQAB</test>').documentElement;
            transform.LoadInnerXml(node);
            const buf = transform.GetOutput();
            vitest_1.assert.equal(ArrayBuffer.isView(buf), true);
            vitest_1.assert.equal(buf.length, 3);
            vitest_1.assert.equal(buf[0], 1);
            vitest_1.assert.equal(buf[1], 0);
            vitest_1.assert.equal(buf[2], 1);
        });
        (0, vitest_1.it)('GetOutput without content', () => {
            const transform = new xmldsig.XmlDsigBase64Transform();
            const node = xmldsig.Parse('<test></test>').documentElement;
            transform.LoadInnerXml(node);
            const buf = transform.GetOutput();
            vitest_1.assert.equal(ArrayBuffer.isView(buf), true);
            vitest_1.assert.equal(buf.length, 0);
        });
        (0, vitest_1.it)('To string', () => {
            const transform = new xmldsig.XmlDsigBase64Transform();
            vitest_1.assert.equal(transform.toString(), `<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`);
        });
    });
    (0, vitest_1.describe)('c14n', () => {
        (0, vitest_1.it)('GetOutput error', () => {
            const transform = new xmldsig.XmlDsigC14NTransform();
            vitest_1.assert.throws(() => {
                transform.GetOutput();
            });
        });
        (0, vitest_1.it)('GetOutput with content', () => {
            const transform = new xmldsig.XmlDsigC14NTransform();
            const node = xmldsig.Parse(`<root xmlns:p="ns"><p:child xmlns:inclusive="ns2"><inclusive:inner xmlns:inclusive="ns2">123</inclusive:inner></p:child></root>`).documentElement;
            transform.LoadInnerXml(node);
            const text = transform.GetOutput();
            vitest_1.assert.equal(text, `<root xmlns:p="ns"><p:child xmlns:inclusive="ns2"><inclusive:inner>123</inclusive:inner></p:child></root>`);
        });
        (0, vitest_1.it)('GetOutput without content', () => {
            const transform = new xmldsig.XmlDsigC14NTransform();
            const node = xmldsig.Parse('<test/>').documentElement;
            transform.LoadInnerXml(node);
            const text = transform.GetOutput();
            vitest_1.assert.equal(text, `<test></test>`);
        });
        (0, vitest_1.it)('To string', () => {
            const transform = new xmldsig.XmlDsigC14NTransform();
            vitest_1.assert.equal(transform.toString(), `<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`);
        });
        (0, vitest_1.it)('with comment', () => {
            const transform = new xmldsig.XmlDsigC14NWithCommentsTransform();
            vitest_1.assert.equal(transform.toString(), `<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`);
        });
    });
    (0, vitest_1.describe)('exc-c14n', () => {
        (0, vitest_1.it)('GetOutput error', () => {
            const transform = new xmldsig.XmlDsigExcC14NTransform();
            vitest_1.assert.throws(() => {
                transform.GetOutput();
            });
        });
        (0, vitest_1.it)('GetOutput with content', () => {
            const transform = new xmldsig.XmlDsigExcC14NTransform();
            const node = xmldsig.Parse(`<root xmlns:p="ns"><p:child xmlns:inclusive="ns2"><inclusive:inner xmlns:inclusive="ns2">123</inclusive:inner></p:child></root>`).documentElement;
            transform.LoadInnerXml(node);
            const text = transform.GetOutput();
            vitest_1.assert.equal(text, `<root><p:child xmlns:p="ns"><inclusive:inner xmlns:inclusive="ns2">123</inclusive:inner></p:child></root>`);
        });
        (0, vitest_1.it)('GetOutput without content', () => {
            const transform = new xmldsig.XmlDsigExcC14NTransform();
            const node = xmldsig.Parse('<test/>').documentElement;
            transform.LoadInnerXml(node);
            const text = transform.GetOutput();
            vitest_1.assert.equal(text, `<test></test>`);
        });
        (0, vitest_1.it)('To string', () => {
            const transform = new xmldsig.XmlDsigExcC14NTransform();
            vitest_1.assert.equal(transform.toString(), `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`);
        });
        (0, vitest_1.it)('with comment', () => {
            const transform = new xmldsig.XmlDsigExcC14NWithCommentsTransform();
            vitest_1.assert.equal(transform.toString(), `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`);
        });
    });
    (0, vitest_1.describe)('enveloped', () => {
        (0, vitest_1.it)('GetOutput error', () => {
            const transform = new xmldsig.XmlDsigEnvelopedSignatureTransform();
            vitest_1.assert.throws(() => {
                transform.GetOutput();
            });
        });
        (0, vitest_1.it)('GetOutput with signature', () => {
            const transform = new xmldsig.XmlDsigEnvelopedSignatureTransform();
            const node = xmldsig.Parse(`<root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></root>`).documentElement;
            transform.LoadInnerXml(node);
            const out = transform.GetOutput();
            vitest_1.assert.equal((0, xml_core_1.Stringify)(out), '<root/>');
        });
        (0, vitest_1.it)('GetOutput without signature', () => {
            const transform = new xmldsig.XmlDsigEnvelopedSignatureTransform();
            const node = xmldsig.Parse(`<root></root>`).documentElement;
            transform.LoadInnerXml(node);
            const out = transform.GetOutput();
            vitest_1.assert.equal((0, xml_core_1.Stringify)(out), '<root/>');
        });
        (0, vitest_1.it)('GetOutput with nested signature should leave it alone', () => {
            const transform = new xmldsig.XmlDsigEnvelopedSignatureTransform();
            const node = xmldsig.Parse(`<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></saml:Assertion></root>`).documentElement;
            transform.LoadInnerXml(node);
            const out = transform.GetOutput();
            vitest_1.assert.equal((0, xml_core_1.Stringify)(out), `<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></saml:Assertion></root>`);
        });
        (0, vitest_1.it)('GetOutput must remove all Signature elements from the document', () => {
            const transform = new xmldsig.XmlDsigEnvelopedSignatureTransform();
            const node = xmldsig.Parse(`<root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></root>`).documentElement;
            transform.LoadInnerXml(node);
            const out = transform.GetOutput();
            vitest_1.assert.equal((0, xml_core_1.Stringify)(out), `<root/>`);
        });
    });
});
