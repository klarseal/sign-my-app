import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, cpSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const windows = process.platform === 'win32';
async function fixture(t, source) {
  const root = mkdtempSync(path.join(repo, '.test-runner-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(root)).toLowerCase(), path.resolve(repo).toLowerCase());
    assert.match(path.basename(root), /^\.test-runner-[a-zA-Z0-9]+$/);
    rmSync(root, { recursive: true, force: true });
  });
  cpSync(new URL('../runner.mjs', import.meta.url), path.join(root, 'runner.mjs'));
  cpSync(new URL('../approval-host.ps1', import.meta.url), path.join(root, 'approval-host.ps1'));
  writeFileSync(path.join(root, 'bridge.ps1'), source);
  return import(pathToFileURL(path.join(root, 'runner.mjs')).href);
}

test('runner rejects output larger than 256 KiB', { skip: !windows }, async t => {
  const { runHelper } = await fixture(t, "[Console]::Out.Write(('X' * 300000)); Start-Sleep -Seconds 90");
  await assert.rejects(runHelper({ name: 'not_a_tool', arguments: {} }, { systemDirectory: 'C:\\Windows\\System32' }), /limit/);
});

test('console-free signing host relays UTF-8 approval frames before stdin closes and filters inherited secrets', { skip: !windows }, async t => {
  const { runHelper } = await fixture(t, `
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
if ($env:KLARSEAL_TEST_SECRET -or $env:NODE_OPTIONS) { throw 'Inherited secret' }
$request = [Console]::In.ReadLine() | ConvertFrom-Json
[Console]::Out.WriteLine((@{event='approval';plans=@($request.arguments)} | ConvertTo-Json -Compress))
$reply = [Console]::In.ReadLine() | ConvertFrom-Json
[Console]::Out.WriteLine((@{failed=$true;output=@($request.arguments.file,$reply.sign)} | ConvertTo-Json -Compress))
`);
  const file = 'C:\\build\\应用 æø.exe';
  const old = process.env.KLARSEAL_TEST_SECRET; process.env.KLARSEAL_TEST_SECRET = 'DO_NOT_ECHO';
  try {
    const result = await runHelper({ name: 'sign_files', arguments: { file } }, { systemDirectory: 'C:\\Windows\\System32' }, undefined, {
      approval(plans) { assert.equal(plans[0].file, file); return { sign: 'Cancel' }; }
    });
    assert.deepEqual(result, { failed: true, output: [file, 'Cancel'] });
  } finally { if (old === undefined) delete process.env.KLARSEAL_TEST_SECRET; else process.env.KLARSEAL_TEST_SECRET = old; }
});

test('runner enforces the 45-second deadline', { skip: !windows }, async t => {
  const { runHelper, TIMEOUT_MS } = await fixture(t, 'Start-Sleep -Seconds 90');
  const started = Date.now();
  await assert.rejects(runHelper({ name: 'not_a_tool', arguments: {} }, { systemDirectory: 'C:\\Windows\\System32' }), /limit/);
  const elapsed = Date.now() - started;
  assert.ok(elapsed >= TIMEOUT_MS - 1000 && elapsed < TIMEOUT_MS + 10000, String(elapsed));
});

test('runner discards exception details and stderr', { skip: !windows }, async t => {
  const { runHelper } = await fixture(t, "[Console]::Error.WriteLine('password=DO_NOT_ECHO'); throw 'token=DO_NOT_ECHO'");
  await assert.rejects(runHelper({ name: 'not_a_tool', arguments: {} }, { systemDirectory: 'C:\\Windows\\System32' }), error => !error.message.includes('DO_NOT_ECHO'));
});

test('runner does not pass inherited secrets or module paths to PowerShell', { skip: !windows }, async t => {
  const { runHelper } = await fixture(t, `
if ($env:KLARSEAL_TEST_SECRET -or $env:NODE_OPTIONS -or $env:PSModulePath -like '*hostile*') { throw 'Inherited secret or module path' }
'{"failed":false,"output":["clean environment"]}'
`);
  const old = process.env.KLARSEAL_TEST_SECRET; process.env.KLARSEAL_TEST_SECRET = 'DO_NOT_ECHO';
  try { assert.deepEqual(await runHelper({ name: 'not_a_tool', arguments: {} }, { systemDirectory: 'C:\\Windows\\System32' }), { failed: false, output: ['clean environment'] }); }
  finally { if (old === undefined) delete process.env.KLARSEAL_TEST_SECRET; else process.env.KLARSEAL_TEST_SECRET = old; }
});

test('cancelling signing kills the managed relay and its bridge child', { skip: !windows }, async t => {
  const { runHelper } = await fixture(t, `
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$null = [Console]::In.ReadLine()
[Console]::Out.WriteLine((@{event='approval';plans=@(@{pid=$PID})} | ConvertTo-Json -Compress))
$null = [Console]::In.ReadLine()
Start-Sleep -Seconds 90
`);
  let bridgePid, announce;
  const ready = new Promise(resolve => { announce = resolve; });
  const controller = new AbortController();
  const pending = runHelper({ name: 'sign_files', arguments: {} }, { systemDirectory: 'C:\\Windows\\System32' }, controller.signal, {
    approval(plans) { bridgePid = plans[0].pid; announce(); return { sign: 'Cancel' }; }
  });
  await ready;
  controller.abort();
  await assert.rejects(pending, /cancelled/);
  assert.ok(Number.isInteger(bridgePid) && bridgePid > 0);
  const { stdout } = await promisify(execFile)('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ['-NoProfile', '-Command', `if (Get-Process -Id ${bridgePid} -ErrorAction SilentlyContinue) { 'alive' } else { 'exited' }`], { windowsHide: true, timeout: 10000 });
  assert.equal(stdout.trim(), 'exited');
});
