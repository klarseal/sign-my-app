// Explicit partitions: adding a new file requires classifying it first.
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
export const desktop = ['approval-window.test.mjs'];
export const nonDesktop = [
  'desktop-lock.test.mjs', 'window-contract.test.mjs',
  'last-two-review.test.mjs', 'no-runtime-compilation.test.mjs',
  'one-click-review.test.mjs', 'protocol.test.mjs', 'review-findings.test.mjs',
  'runner.test.mjs', 'second-round.test.mjs', 'security-review.test.mjs',
  'session-recovery.test.mjs', 'signing.test.mjs', 'smooth.test.mjs', 'windows.test.mjs',
];
const mode = process.argv[2];
if (!['non-desktop', 'desktop'].includes(mode)) throw new Error('Use non-desktop or desktop');
const actual = readdirSync(new URL('./', import.meta.url)).filter(x => x.endsWith('.test.mjs')).sort();
if (JSON.stringify(actual) !== JSON.stringify([...desktop, ...nonDesktop].sort())) throw new Error('Classify all test files in run-tests.mjs before running');
const selected = mode === 'desktop' ? desktop : nonDesktop;
const child = spawn(process.execPath, ['--test', '--test-concurrency=1', ...selected.map(x => fileURLToPath(new URL(x, import.meta.url)))],
  { stdio: 'inherit', windowsHide: true });
child.once('error', error => { console.error(error.message); process.exitCode = 1; });
child.once('exit', code => { process.exitCode = code ?? 1; });
