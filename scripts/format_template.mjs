// Formats internal/report/template.html with prettier while preserving
// Go template expressions ({{ ... }}) that prettier's HTML parser chokes on.
// Uses npx prettier under the hood with a placeholder pre-pass.

import { execFileSync } from "child_process";
import { readFileSync, writeFileSync } from "fs";

const filePath = "internal/report/template.html";
let html = readFileSync(filePath, "utf8");

const placeholders = [];
let counter = 0;

// Replace Go template expressions {{ ... }} with safe placeholder tokens
html = html.replace(/\{\{[^}]*\}\}/g, (match) => {
  // Escape double-quotes inside Go template expressions so they don't
  // break prettier's HTML attribute parsing
  const safe = match.replace(/"/g, "\u0000");
  const id = `__GT_PH_${counter++}__`;
  placeholders.push({ id, original: match, safe });
  return id;
});

writeFileSync(filePath, html, "utf8");

// Run prettier via npx
execFileSync("npx", [
  "--yes",
  "prettier",
  "--write",
  "--parser",
  "html",
  "--html-whitespace-sensitivity",
  "css",
  "--print-width",
  "120",
  "--tab-width",
  "2",
  filePath,
]);

// Restore placeholders to original Go template expressions
let result = readFileSync(filePath, "utf8");
result = result.replace(/__GT_PH_\d+__/g, (match) => {
  const entry = placeholders.find((p) => p.id === match);
  return entry ? entry.original : match;
});

writeFileSync(filePath, result, "utf8");
console.log(`✓ Formatted ${filePath}`);
