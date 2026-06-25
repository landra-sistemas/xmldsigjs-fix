"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const xmlCore = tslib_1.__importStar(require("xml-core"));
const xmldom_1 = require("@xmldom/xmldom");
if (!globalThis.__xmlCoreInitialized) {
    xmlCore.setNodeDependencies({
        DOMParser: xmldom_1.DOMParser,
        XMLSerializer: xmldom_1.XMLSerializer,
    });
    globalThis.__xmlCoreInitialized = true;
}
