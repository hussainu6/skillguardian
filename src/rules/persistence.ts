import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS020 — Persistence mechanism.
 *
 * Malicious skills want to survive a reboot or re-run. The usual footholds:
 * appending to a shell rc file, installing a cron job, a launchd/systemd service,
 * a Windows scheduled task, or a Run registry key. We require a write/create
 * action so merely naming these files isn't flagged.
 */
const PERSISTENCE =
  /(?:(?<![-=<>])>>?|echo|printf|tee|Add-Content|Set-Content|Out-File)\s+[^\n]*(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.profile)\b|crontab\s+-|\/etc\/cron|~?\/Library\/Launch(?:Agents|Daemons)|launchctl\s+load|systemctl\s+(?:enable|--user\s+enable)|\/etc\/systemd\/system|schtasks\s+\/create|New-ScheduledTask(?:Action)?|reg\s+add[^\n]*\\Run\b|HK(?:CU|LM)[^\n]*\\CurrentVersion\\Run/i;

export const persistence: Rule = {
  id: "SS020",
  title: "Installs a persistence mechanism",
  severity: "high",
  description: "Flags writes to shell rc files, cron, launchd/systemd, scheduled tasks, or Run registry keys.",
  scan(component) {
    return findingsFromMatches(
      persistence,
      matchAll(component, PERSISTENCE),
      "Installs a startup/persistence hook so code keeps running after the session or a reboot.",
      "Remove it. A skill should not register autostart entries, cron jobs, services, or Run keys.",
    );
  },
};
