import * as xmlCore from "xml-core";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
if (!xmlCore.__initialized) {
    xmlCore.setNodeDependencies({
        DOMParser,
        XMLSerializer,
    });
    xmlCore.__initialized = true;
}
