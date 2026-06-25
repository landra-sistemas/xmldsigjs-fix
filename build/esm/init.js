import * as xmlCore from "xml-core";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
if (!globalThis.__xmlCoreInitialized) {
    xmlCore.setNodeDependencies({
        DOMParser,
        XMLSerializer,
    });
    globalThis.__xmlCoreInitialized = true;
}
