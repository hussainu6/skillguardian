import type { Grade } from "./types.js";

/** shields.io colors per grade. */
const BADGE_COLOR: Record<Grade, string> = {
  A: "brightgreen",
  B: "green",
  C: "yellow",
  D: "orange",
  F: "red",
};

const REPO_URL = "https://github.com/hussainu6/skillguardian";

/** A shields.io static-badge image URL for a grade. */
export function badgeUrl(grade: Grade): string {
  // Label and message are URL-path segments; "skillguardian" and a single letter need no escaping.
  return `https://img.shields.io/badge/skillguardian-${grade}-${BADGE_COLOR[grade]}`;
}

/** Markdown snippet the user can paste into their README. */
export function badgeMarkdown(grade: Grade): string {
  return `[![skillguardian: ${grade}](${badgeUrl(grade)})](${REPO_URL})`;
}

/** HTML snippet, for READMEs that prefer `<img>`. */
export function badgeHtml(grade: Grade): string {
  return `<a href="${REPO_URL}"><img src="${badgeUrl(grade)}" alt="skillguardian: ${grade}"></a>`;
}
