import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS014 — Insecure (plaintext) endpoint.
 *
 * A skill or MCP config that talks to an `http://` endpoint on a non-local host
 * sends its traffic — often including whatever it was told to fetch or post — in
 * the clear, where anyone on the path can read or tamper with it. Localhost is
 * exempt; loopback traffic never leaves the machine.
 */
const INSECURE_URL = /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)[^\s"'`)]+/gi;

export const insecureEndpoint: Rule = {
  id: "SS014",
  title: "Uses an insecure http:// endpoint",
  severity: "medium",
  description: "Flags plaintext http:// endpoints (non-localhost) that expose traffic to interception and tampering.",
  scan(component) {
    return findingsFromMatches(
      insecureEndpoint,
      matchAll(component, INSECURE_URL),
      "Contacts a non-local endpoint over plaintext http://, which can be read or modified in transit.",
      "Use https:// for any remote endpoint. Only http:// to localhost is safe.",
    );
  },
};
