
import * as xmlCore from "xml-core";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";

if (!(xmlCore as any).__initialized) {
  xmlCore.setNodeDependencies({
    DOMParser,
    XMLSerializer,
  });

  (xmlCore as any).__initialized = true;
}
