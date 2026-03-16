#!/usr/bin/env node
/**
 * KQL Syntax Validator for Sentinel project.
 * Extracts KQL from markdown (```kql blocks) and workbook JSON ("query" fields),
 * then validates using pattern-based linting.
 *
 * Usage:
 *   node validate-kql.mjs                    # validate all files
 *   node validate-kql.mjs workbooks/         # validate specific directory
 *   node validate-kql.mjs "analytic rules/"  # validate analytic rules
 */

import { readdirSync, readFileSync } from 'fs';
import { join, relative } from 'path';

const ROOT = new URL('.', import.meta.url).pathname;

// ── Extract KQL from files ──────────────────────────────────────

function extractKqlFromMarkdown(content, filePath) {
  const queries = [];
  const kqlBlockRegex = /```kql\n([\s\S]*?)```/g;
  let match;
  while ((match = kqlBlockRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length;
    queries.push({ query: match[1].trim(), file: filePath, line: lineNum, source: 'kql block' });
  }
  return queries;
}

function extractKqlFromWorkbookJson(content, filePath) {
  const queries = [];
  const jsonBlockRegex = /```json\n([\s\S]*?)```/g;
  let match;
  while ((match = jsonBlockRegex.exec(content)) !== null) {
    try {
      const json = JSON.parse(match[1]);
      findQueriesInJson(json, queries, filePath);
    } catch {
      // Not valid JSON, skip
    }
  }
  return queries;
}

function findQueriesInJson(obj, queries, filePath) {
  if (!obj || typeof obj !== 'object') return;

  if (typeof obj.query === 'string' && obj.query.trim().length > 0) {
    // Skip Azure Resource Graph queries (ARG uses a different dialect)
    const isArg = obj.queryType === 1 || obj.resourceType?.includes('resourcegraph');
    if (!isArg) {
      queries.push({ query: obj.query.trim(), file: filePath, line: 0, source: 'workbook query' });
    }
  }

  for (const val of Object.values(obj)) {
    if (typeof val === 'object' && val !== null) {
      findQueriesInJson(val, queries, filePath);
    }
  }
}

// ── File discovery ──────────────────────────────────────────────

function findMdFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
      files.push(...findMdFiles(full));
    } else if (entry.name.endsWith('.md') && entry.name !== 'SKILL.md') {
      files.push(full);
    }
  }
  return files;
}

// ── KQL Validation ──────────────────────────────────────────────

function lintKql(query) {
  const errors = [];
  const lines = query.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('//')) continue;

    // Unmatched parentheses — only flag if very unbalanced on a single line
    const openParens = (line.match(/\(/g) || []).length;
    const closeParens = (line.match(/\)/g) || []).length;
    if (Math.abs(openParens - closeParens) > 3) {
      errors.push({ line: i + 1, msg: `Possibly unmatched parentheses (open=${openParens}, close=${closeParens})` });
    }

    // Unmatched quotes — skip lines with:
    // - KQL escaped backslashes like "\\\\" (literal \\)
    // - Single-quoted strings containing double-quotes like '"'
    // - KQL verbatim strings @"...\path\" (string ending with backslash)
    // - KQL @'...' raw strings with embedded double-quotes
    const hasVerbatimString = /@"[^"]*"/.test(line) || /@'[^']*'/.test(line);
    const hasDoubleBackslash = /"\\\\\\\\"/.test(line) || /\\\\",/.test(line);
    const hasSingleQuotedDouble = /'[^']*"[^']*'/.test(line);
    if (!hasVerbatimString && !hasDoubleBackslash && !hasSingleQuotedDouble) {
      const stripped = line.replace(/\\"/g, '').replace(/\\'/g, '');
      const doubleQuotes = (stripped.match(/"/g) || []).length;
      if (doubleQuotes % 2 !== 0) {
        const nextLine = lines[i + 1]?.trim() || '';
        const nextDoubleQuotes = (nextLine.replace(/\\"/g, '').match(/"/g) || []).length;
        if (nextDoubleQuotes % 2 === 0) {
          errors.push({ line: i + 1, msg: 'Unmatched double quotes' });
        }
      }
    }

    // Common typos in KQL operators
    const typoPatterns = [
      { pattern: /\bsummerize\b/i, fix: 'summarize' },
      { pattern: /^\|\s*were\b/i, fix: 'where (did you mean "| where"?)' },
      { pattern: /\bporject\b/i, fix: 'project' },
      { pattern: /\bextned\b/i, fix: 'extend' },
      { pattern: /\bjoion\b/i, fix: 'join' },
      { pattern: /\bunoin\b/i, fix: 'union' },
      { pattern: /\bcount_if\b/, fix: 'countif (no underscore in KQL)' },
      { pattern: /\bsum_if\b/, fix: 'sumif (no underscore in KQL)' },
      { pattern: /\bproejct\b/i, fix: 'project' },
      { pattern: /\bwehre\b/i, fix: 'where' },
      { pattern: /\bexetnd\b/i, fix: 'extend' },
      { pattern: /\bsumamrize\b/i, fix: 'summarize' },
      { pattern: /\bpritn\b/i, fix: 'print' },
      { pattern: /\brneder\b/i, fix: 'render' },
    ];

    for (const { pattern, fix } of typoPatterns) {
      if (pattern.test(line)) {
        errors.push({ line: i + 1, msg: `Typo: "${line.match(pattern)[0]}" → ${fix}` });
      }
    }

    // Missing pipe before operator — but only if prev line is NOT a continuation
    // (i.e., prev line doesn't end with pipe, comma, open paren, or operator keyword)
    const kqlOperators = /^(where|project|extend|summarize|join|sort|order|top|take|limit|count|distinct|render|mv-expand|mv-apply|parse|evaluate|make-series|lookup)\b/;
    if (kqlOperators.test(line) && i > 0) {
      // Walk back to find prev non-empty, non-comment line
      let prevIdx = i - 1;
      while (prevIdx >= 0 && (!lines[prevIdx].trim() || lines[prevIdx].trim().startsWith('//'))) {
        prevIdx--;
      }
      if (prevIdx >= 0) {
        const prevLine = lines[prevIdx].trim();
        const isContinuation = prevLine.endsWith('|') || prevLine.endsWith(',') ||
          prevLine.endsWith('(') || prevLine.endsWith('{') ||
          prevLine.startsWith('let ') || prevLine === '';
        if (!isContinuation) {
          errors.push({ line: i + 1, msg: `Missing pipe: "${line.split(/\s/)[0]}" should be "| ${line.split(/\s/)[0]} ..."` });
        }
      }
    }

    // "union" without pipe is valid at start of let assignment — only flag if not after "="
    if (/^union\b/.test(line) && i > 0) {
      let prevIdx = i - 1;
      while (prevIdx >= 0 && (!lines[prevIdx].trim() || lines[prevIdx].trim().startsWith('//'))) {
        prevIdx--;
      }
      if (prevIdx >= 0) {
        const prevLine = lines[prevIdx].trim();
        // union is valid after "=" (let x = union ...) or after "(" or at query start
        if (prevLine.endsWith('=') || prevLine.endsWith('(') || prevLine.endsWith('|')) {
          // Remove the false positive we may have added above
          const idx = errors.findIndex(e => e.line === i + 1 && e.msg.includes('Missing pipe: "union"'));
          if (idx !== -1) errors.splice(idx, 1);
        }
      }
    }

    // Unclosed dynamic() or pack()
    if (/\bdynamic\s*\(/.test(line)) {
      const afterDynamic = line.substring(line.indexOf('dynamic('));
      let depth = 0;
      for (const ch of afterDynamic) {
        if (ch === '(') depth++;
        if (ch === ')') depth--;
      }
      if (depth > 0 && !lines[i + 1]?.trim()) {
        errors.push({ line: i + 1, msg: 'Possibly unclosed dynamic()' });
      }
    }
  }

  // Check overall query parentheses/bracket balance
  // Strip comments, then all string literals (verbatim @"...", @'...', regular "...", '...')
  const fullQuery = query
    .replace(/(?<!:)\/\/.*$/gm, '')
    .replace(/@"[^"\n]*(?:""[^"\n]*)*"/g, '""')   // verbatim double-quoted strings
    .replace(/@'[^'\n]*(?:''[^'\n]*)*'/g, "''")    // verbatim single-quoted strings
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')        // regular double-quoted strings
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''");       // regular single-quoted strings
  const totalOpen = (fullQuery.match(/\(/g) || []).length;
  const totalClose = (fullQuery.match(/\)/g) || []).length;
  if (totalOpen !== totalClose) {
    errors.push({ line: 0, msg: `Unbalanced parentheses: ${totalOpen} open vs ${totalClose} close` });
  }

  const totalOpenBracket = (fullQuery.match(/\[/g) || []).length;
  const totalCloseBracket = (fullQuery.match(/\]/g) || []).length;
  if (totalOpenBracket !== totalCloseBracket) {
    errors.push({ line: 0, msg: `Unbalanced brackets: ${totalOpenBracket} open vs ${totalCloseBracket} close` });
  }

  return errors;
}

// ── Main ────────────────────────────────────────────────────────

const targetDir = process.argv[2] ? join(ROOT, process.argv[2]) : ROOT;
const files = findMdFiles(targetDir);
let totalQueries = 0;
let totalErrors = 0;
let filesWithErrors = 0;

console.log(`\nScanning ${files.length} markdown files in ${relative(ROOT, targetDir) || '.'}\n`);

for (const file of files) {
  const content = readFileSync(file, 'utf-8');
  const relPath = relative(ROOT, file);

  const queries = [
    ...extractKqlFromMarkdown(content, relPath),
    ...extractKqlFromWorkbookJson(content, relPath),
  ];

  if (queries.length === 0) continue;

  let fileHasErrors = false;

  for (const { query, file: qFile, line, source } of queries) {
    totalQueries++;
    const errors = lintKql(query);

    if (errors.length > 0) {
      if (!fileHasErrors) {
        console.log(`\n--- ${qFile} ---`);
        fileHasErrors = true;
        filesWithErrors++;
      }
      console.log(`  [${source}${line ? ` line ${line}` : ''}]`);
      for (const err of errors) {
        totalErrors++;
        console.log(`    ⚠ ${err.line > 0 ? `line ${err.line}: ` : ''}${err.msg}`);
      }
    }
  }
}

console.log(`\n${'='.repeat(60)}`);
console.log(`Scanned: ${files.length} files, ${totalQueries} KQL queries`);
console.log(`Errors:  ${totalErrors} issues in ${filesWithErrors} files`);
if (totalErrors === 0) {
  console.log('All KQL queries passed lint checks');
}
console.log();
process.exit(totalErrors > 0 ? 1 : 0);
