
import * as xmlCore from "xml-core";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";

if (!(globalThis as any).__xmlCoreInitialized) {
  xmlCore.setNodeDependencies({
    DOMParser,
    XMLSerializer,
  });

  (globalThis as any).__xmlCoreInitialized = true;
}