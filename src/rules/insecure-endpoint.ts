import type { Finding, Rule } from "../types.js";
import { finding } from "./util.js";

/**
 * SS014 — Insecure (plaintext) endpoint.
 *
 * A skill or MCP config that talks to an `http://` endpoint on a non-local host
 * sends its traffic in the clear. We ignore localhost, and we ignore the many
 * `http://` URLs that are *identifiers, not endpoints*: XML/schema namespaces,
 * spec and license URLs. Those are never fetched, so flagging them is noise.
 */
const INSECURE_URL = /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)([^\s"'`)<>]+)/gi;

// Hosts whose http:// URLs are namespace/spec/license identifiers, not endpoints.
const NAMESPACE_HOSTS = [
  "www.w3.org",
  "schemas.openxmlformats.org",
  "schemas.microsoft.com",
  "schemas.android.com",
  "purl.org",
  "www.apache.org/licenses",
  "apache.org/licenses",
  "docbook.org",
  "oasis-open.org",
  "iana.org",
  "ns.adobe.com",
  "xml.org",
  "xmlns.com",
  "www.opengis.net",
  "relaxng.org",
  "javax.xml",
  "java.sun.com",
];

function isNamespace(url: string, line: string): boolean {
  const lower = url.toLowerCase();
  if (NAMESPACE_HOSTS.some((h) => lower.includes(h))) return true;
  // XML namespace declarations and DTD/schema locations are identifiers, not calls.
  if (/xmlns|schemalocation|targetnamespace|!doctype|<\?xml/i.test(line)) return true;
  return false;
}

export const insecureEndpoint: Rule = {
  id: "SS014",
  title: "Uses an insecure http:// endpoint",
  severity: "medium",
  description: "Flags plaintext http:// endpoints (non-localhost), ignoring XML/schema namespaces and spec/license URLs.",
  scan(component) {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        const re = new RegExp(INSECURE_URL.source, "gi");
        let m: RegExpExecArray | null;
        while ((m = re.exec(line)) !== null) {
          if (isNamespace(m[0], line)) continue;
          const key = `${file.relativePath}:${i + 1}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push(
            finding(insecureEndpoint, {
              file: file.relativePath,
              line: i + 1,
              evidence: m[0],
              message: "Contacts a non-local endpoint over plaintext http://, which can be read or modified in transit.",
              remediation: "Use https:// for any remote endpoint. Only http:// to localhost is safe.",
            }),
          );
        }
      }
    }
    return findings;
  },
};
