#!/usr/bin/env node
/**
 * Security unit tests for safeVaultPath()
 *
 * Covers:
 *   - C-01: Path traversal via ../../../../ sequences
 *   - Sibling directory escapes (../sibling)
 *   - Legitimate relative paths (subdir/note.md)
 *   - Empty string (resolves to vault base itself)
 *   - Non-string input
 *   - Absolute path injection
 *   - Mixed traversal sequences
 */

import path from 'path';

// ── Inline safeVaultPath (mirrors the implementation in index.js) ──────────
function safeVaultPath(base, userInput) {
  if (typeof userInput !== 'string') throw new Error('Path must be a string');
  const vaultBase = path.resolve(base);
  const resolved = path.resolve(vaultBase, userInput);
  if (!resolved.startsWith(vaultBase + path.sep) && resolved !== vaultBase) {
    throw new Error(`Path traversal detected: "${userInput}" resolves outside vault`);
  }
  return resolved;
}

// ── Test harness ──────────────────────────────────────────────────────────────
const BASE = '/tmp/test-vault';
let passed = 0;
let failed = 0;

function assert(label, fn) {
  try {
    fn();
    console.log(`  PASS  ${label}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL  ${label}`);
    console.error(`        ${err.message}`);
    failed++;
  }
}

function assertThrows(label, fn, expectedFragment) {
  try {
    fn();
    console.error(`  FAIL  ${label} — expected a throw but got none`);
    failed++;
  } catch (err) {
    if (expectedFragment && !err.message.includes(expectedFragment)) {
      console.error(`  FAIL  ${label} — threw but wrong message: ${err.message}`);
      failed++;
    } else {
      console.log(`  PASS  ${label}`);
      passed++;
    }
  }
}

// ── Test suite ────────────────────────────────────────────────────────────────
console.log('\nsafeVaultPath() — security test suite\n');

// C-01 — classic traversal sequences
console.log('[C-01] Path traversal attacks:');

assertThrows(
  'safeVaultPath(base, "../../../../etc/passwd") throws',
  () => safeVaultPath(BASE, '../../../../etc/passwd'),
  'Path traversal detected',
);

assertThrows(
  'safeVaultPath(base, "../../etc/shadow") throws',
  () => safeVaultPath(BASE, '../../etc/shadow'),
  'Path traversal detected',
);

assertThrows(
  'safeVaultPath(base, "../sibling-vault/secret.md") throws',
  () => safeVaultPath(BASE, '../sibling-vault/secret.md'),
  'Path traversal detected',
);

assertThrows(
  'safeVaultPath(base, "../sibling") throws',
  () => safeVaultPath(BASE, '../sibling'),
  'Path traversal detected',
);

assertThrows(
  'safeVaultPath(base, "subdir/../../..") throws (mixed traversal)',
  () => safeVaultPath(BASE, 'subdir/../../..'),
  'Path traversal detected',
);

assertThrows(
  'safeVaultPath(base, "/etc/passwd") throws (absolute injection)',
  () => safeVaultPath(BASE, '/etc/passwd'),
  'Path traversal detected',
);

assertThrows(
  'safeVaultPath(base, "/tmp/other-vault/file.md") throws (absolute sibling)',
  () => safeVaultPath(BASE, '/tmp/other-vault/file.md'),
  'Path traversal detected',
);

assertThrows(
  'safeVaultPath(base, "../test-vault/../../../etc") throws (complex traversal)',
  () => safeVaultPath(BASE, '../test-vault/../../../etc'),
  'Path traversal detected',
);

// ── Legitimate paths ──────────────────────────────────────────────────────────
console.log('\n[Legitimate] Paths that must be accepted:');

assert(
  'safeVaultPath(base, "subdir/note.md") returns correct path',
  () => {
    const result = safeVaultPath(BASE, 'subdir/note.md');
    if (result !== `${BASE}/subdir/note.md`) {
      throw new Error(`Expected ${BASE}/subdir/note.md, got ${result}`);
    }
  },
);

assert(
  'safeVaultPath(base, "note.md") returns correct path',
  () => {
    const result = safeVaultPath(BASE, 'note.md');
    if (result !== `${BASE}/note.md`) {
      throw new Error(`Expected ${BASE}/note.md, got ${result}`);
    }
  },
);

assert(
  'safeVaultPath(base, "deep/nested/path/file.md") returns correct path',
  () => {
    const result = safeVaultPath(BASE, 'deep/nested/path/file.md');
    if (result !== `${BASE}/deep/nested/path/file.md`) {
      throw new Error(`Expected ${BASE}/deep/nested/path/file.md, got ${result}`);
    }
  },
);

assert(
  'safeVaultPath(base, "") returns vault base',
  () => {
    const result = safeVaultPath(BASE, '');
    if (result !== BASE) {
      throw new Error(`Expected ${BASE}, got ${result}`);
    }
  },
);

assert(
  'safeVaultPath(base, ".") returns vault base',
  () => {
    const result = safeVaultPath(BASE, '.');
    if (result !== BASE) {
      throw new Error(`Expected ${BASE}, got ${result}`);
    }
  },
);

assert(
  'safeVaultPath(base, ".templates") resolves inside vault',
  () => {
    const result = safeVaultPath(BASE, '.templates');
    if (result !== `${BASE}/.templates`) {
      throw new Error(`Expected ${BASE}/.templates, got ${result}`);
    }
  },
);

assert(
  'safeVaultPath(base, "attachments/image.png") resolves correctly',
  () => {
    const result = safeVaultPath(BASE, 'attachments/image.png');
    if (result !== `${BASE}/attachments/image.png`) {
      throw new Error(`Expected ${BASE}/attachments/image.png, got ${result}`);
    }
  },
);

// ── Type safety ───────────────────────────────────────────────────────────────
console.log('\n[Type safety] Non-string inputs:');

assertThrows(
  'safeVaultPath(base, null) throws',
  () => safeVaultPath(BASE, null),
  'Path must be a string',
);

assertThrows(
  'safeVaultPath(base, undefined) throws',
  () => safeVaultPath(BASE, undefined),
  'Path must be a string',
);

assertThrows(
  'safeVaultPath(base, 42) throws',
  () => safeVaultPath(BASE, 42),
  'Path must be a string',
);

// ── Summary ───────────────────────────────────────────────────────────────────
const hr = '-'.repeat(50);
console.log(`\n${hr}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
} else {
  console.log('All security tests passed.\n');
}
