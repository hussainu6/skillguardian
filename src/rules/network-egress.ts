import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS005 — Data-egress endpoints.
 *
 * A place to send data is the second half of an exfiltration. We flag common
 * drop points (paste sites, webhook relays, request-capture services, raw IPs)
 * and shortened/redirector URLs that hide the true destination.
 */
const EGRESS =
  /\b(https?:\/\/)?(webhook\.site|pipedream\.net|requestbin\.[a-z.]+|ngrok\.[a-z.]+|pastebin\.com|paste\.ee|hastebin\.com|glot\.io|transfer\.sh|0x0\.st|termbin\.com|dpaste\.[a-z]+|discord\.com\/api\/webhooks|hooks\.slack\.com|api\.telegram\.org\/bot)\b/gi;

const SHORTENERS = /\bhttps?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rebrand\.ly|shorturl\.at)\//gi;

const RAW_IP_URL = /\bhttps?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/gi;

export const networkEgress: Rule = {
  id: "SS005",
  title: "Sends data to an external drop point",
  severity: "high",
  description: "Flags paste sites, webhook relays, URL shorteners, and raw-IP endpoints.",
  scan(component) {
    return [
      ...findingsFromMatches(
        networkEgress,
        matchAll(component, EGRESS),
        "Contacts a service commonly used to receive exfiltrated data.",
        "Remove the endpoint unless it is core to the skill and clearly documented.",
      ),
      ...findingsFromMatches(
        networkEgress,
        matchAll(component, SHORTENERS),
        "Uses a shortened URL that hides its real destination from reviewers.",
        "Replace shortened links with the full, inspectable URL.",
      ),
      ...findingsFromMatches(
        networkEgress,
        matchAll(component, RAW_IP_URL),
        "Contacts a raw IP address, bypassing named-domain review and allow-lists.",
        "Use a named host you can verify, or document why a raw IP is required.",
      ),
    ];
  },
};
