// Headless lock tests. Children only write markers and wait; no UI code loads.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ps = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const helper = fileURLToPath(new URL('./Desktop-Lock.ps1', import.meta.url));
const q = s => "'" + s.replaceAll("'", "''") + "'";
const exec = promisify(execFile);
for (const kind of ['Windows', 'Commands']) test(`headless cross-process desktop ${kind} mutex excludes other working directories`, { skip: process.platform !== 'win32' }, async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'klarseal-lock-'));
  t.after(() => { assert.equal(path.dirname(root), tmpdir()); assert.match(path.basename(root), /^klarseal-lock-/); rmSync(root, { recursive: true, force: true }); });
  const log = path.join(root, 'events.txt');
  const script = path.join(root, 'lock.ps1');
  writeFileSync(script, `param($Name)
. ${q(helper)}
$mutex = Enter-DesktopTestLock ${q(kind)}
try {
  [IO.File]::AppendAllText(${q(log)}, "$Name start\n")
  Start-Sleep -Milliseconds 200
  [IO.File]::AppendAllText(${q(log)}, "$Name end\n")
} finally { Exit-DesktopTestLock $mutex }
`);
  await Promise.all(['a', 'b', 'c'].map((name, i) => exec(ps,
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, name],
    { windowsHide: true, cwd: i ? root : path.dirname(helper), timeout: 20000 })));
  const events = readFileSync(log, 'utf8').trim().split('\n');
  assert.equal(events.length, 6);
  for (let i = 0; i < events.length; i += 2) assert.equal(events[i + 1], events[i].replace('start', 'end'));
});
test('headless command lease releases after an action throws', { skip: process.platform !== 'win32' }, async () => {
  const { withDesktopLock } = await import('./desktop-lock.mjs');
  await assert.rejects(withDesktopLock(() => { throw new Error('synthetic failure'); }), /synthetic failure/);
  assert.equal(await withDesktopLock(() => 'next command'), 'next command');
});
test('headless desktop mutex recovers an abruptly killed owner', { skip: process.platform !== 'win32' }, async () => {
  const child = spawn(ps, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
    `. ${q(helper)}; $mutex = Enter-DesktopTestLock; [Console]::Out.WriteLine('held'); Start-Sleep -Seconds 30`],
    { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Owner failed to acquire lock')), 10000);
      child.stdout.once('data', () => { clearTimeout(timer); resolve(); });
      child.once('error', reject);
    });
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill(); await exited;
    const result = await exec(ps, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
      `. ${q(helper)}; Invoke-WithDesktopTestLock { 'recovered' }`], { windowsHide: true, timeout: 10000 });
    assert.equal(result.stdout.trim(), 'recovered');
  } finally { child.kill(); }
});
