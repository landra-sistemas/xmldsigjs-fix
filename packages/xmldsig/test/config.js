"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.readXml = readXml;
const tslib_1 = require("tslib");
const fs = tslib_1.__importStar(require("node:fs"));
const webcrypto_1 = require("@peculiar/webcrypto");
require("../../core/test/config.js");
const xmldsig = tslib_1.__importStar(require("../src/index.js"));
xmldsig.Application.setEngine('NodeJS', new webcrypto_1.Crypto());
function readXml(path) {
    const data = fs.readFileSync(path, { encoding: 'utf8' });
    const doc = xmldsig.Parse(data);
    return doc;
}
