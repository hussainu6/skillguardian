import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS019 — Crypto wallet / seed access.
 *
 * Crypto stealers target a short list of wallet files and seed phrases. We match
 * the distinctive artifacts — `wallet.dat`, Ethereum keystores, Electrum/Exodus
 * data, and explicit seed-phrase / mnemonic references — rather than brand names
 * alone, to keep benign mentions out.
 */
const WALLET =
  /\bwallet\.dat\b|\.ethereum\/keystore|keystore\/UTC--|\.electrum\b|\bExodus\b[^\n]*(?:wallet|exodus\.wallet)|exodus\.wallet|\bseed phrase\b|\bmnemonic\b[^\n]*(?:phrase|wallet|words|recovery)|\brecovery phrase\b|\bprivate key\b[^\n]*(?:wallet|crypto|eth|btc)/i;

export const walletAccess: Rule = {
  id: "SS019",
  title: "Accesses a crypto wallet or seed phrase",
  severity: "high",
  description: "Flags wallet files (wallet.dat, Ethereum keystore, Electrum/Exodus) and seed-phrase / mnemonic references.",
  scan(component) {
    return findingsFromMatches(
      walletAccess,
      matchAll(component, WALLET),
      "References a crypto wallet file or seed phrase — the target of wallet-stealer malware.",
      "Remove it unless the skill is an explicit, user-initiated wallet tool, and never read a seed phrase programmatically.",
    );
  },
};
