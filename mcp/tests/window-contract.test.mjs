import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { testOnlySource } from './desktop-lock.mjs';

test('test-only title and message cannot be selected by production requests', () => {
  const source = readFileSync(new URL('../approval-window.ps1', import.meta.url), 'utf8');
  assert.ok(source.includes("$form.Text = 'Sign my app'"));
  assert.doesNotMatch(source, /TEST ONLY|probeRequest|KLARSEAL_TEST|Show-TestApproval/);
  const fixture = testOnlySource(source);
  assert.match(fixture, /\$form.Text = 'TEST ONLY - nothing will be signed'/);
  assert.match(fixture, /\$Message = "TEST ONLY - nothing will be signed/);
});

// Generated wrappers must remain valid PS 5.1 too; parsing executes no source.
test('production and generated desktop fixtures parse without executing', { skip: process.platform !== 'win32' }, async () => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { fileURLToPath } = await import('node:url');
  const source = testOnlySource(readFileSync(new URL('../approval-window.ps1', import.meta.url), 'utf8'));
  const files = ['../approval-window.ps1', '../sign-operation.ps1', 'Desktop-Lock.ps1', 'Approval-Probe.ps1', 'Decision-Probe.ps1', 'Click-Approval.ps1', 'Foreground-Fixture.ps1', '../../tests/Run-Tests.ps1', '../../tests/SecondRound-Tests.ps1', '../../tests/SecurityReview-Tests.ps1', '../../tests/ReReview-Tests.ps1', '../../tests/Discovery-Signing-Tests.ps1'].map(x => fileURLToPath(new URL(x, import.meta.url)));
  const q = value => "'" + value.replaceAll("'", "''") + "'";
  const command = `$ErrorActionPreference='Stop'
  foreach ($file in @(${files.map(q).join(',')})) {
    $tokens=$null; $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ($file + ': ' + ($errors -join '; ')) }
  }
  $tokens=$null; $errors=$null
  $source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(source).toString('base64')}'))
  $null=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
  if ($errors.Count) { throw ($errors -join '; ') }
  'parsed'`;
  const result = await promisify(execFile)('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { windowsHide: true, timeout: 15000 });
  assert.equal(result.stdout.trim(), 'parsed');
});
