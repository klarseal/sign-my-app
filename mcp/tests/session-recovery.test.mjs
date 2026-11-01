import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { createSigning } from '../signing.mjs';
import { fileState } from '../trust.mjs';
import { helperResult } from '../tools.mjs';

const exec = promisify(execFile);
const repo = fileURLToPath(new URL('../../', import.meta.url));
const ps = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const q = value => "'" + value.replaceAll("'", "''") + "'";
const hash = file => createHash('sha256').update(readFileSync(file)).digest('hex');

test('actual bridge returns calm session result, logs reason, preserves bytes and Always trust across restart', { skip: process.platform !== 'win32' }, async t => {
  const root = mkdtempSync(path.join(repo, '.test-session-'));
  const install = path.join(root, 'install'), build = path.join(root, 'build'), state = path.join(root, 'state');
  for (const folder of [install, build, state]) mkdirSync(folder);
  const fixture = fileURLToPath(new URL('Fixture.ps1', import.meta.url));
  const lifecycle = action => exec(ps, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', fixture, '-Action', action, '-Root', root], { windowsHide: true, timeout: 60000 });
  t.after(async () => {
    if (existsSync(path.join(root, 'certificate.json'))) { await lifecycle('Remove'); await lifecycle('AssertAbsent'); }
    assert.equal(path.dirname(root).toLowerCase(), path.resolve(repo).toLowerCase());
    assert.match(path.basename(root), /^\.test-session-[a-zA-Z0-9]+$/);
    rmSync(root, { recursive: true, force: true });
  });
  cpSync(path.join(repo, 'scripts'), path.join(install, 'scripts'), { recursive: true });
  cpSync(path.join(repo, 'mcp'), path.join(install, 'mcp'), { recursive: true, filter: source => path.basename(source) !== 'tests' });
  writeFileSync(path.join(install, 'mcp', 'approval-window.ps1'), "function Request-NativeSigningApproval { throw 'Non-desktop test reached native approval' }");
  // Parallel test files must not contend with this fake provider's mutex.
  // The production name is unchanged; this copied install is test-only.
  const operation = path.join(install, 'mcp', 'sign-operation.ps1');
  writeFileSync(operation, readFileSync(operation, 'utf8').replace('Local\\Klarseal.SignMyApp.Signing', `Local\\Klarseal.SignMyApp.Signing.${path.basename(root)}`));
  for (const name of ['SKILL.md', 'VERSION']) cpSync(path.join(repo, name), path.join(install, name));
  await lifecycle('Create');
  const identity = JSON.parse(readFileSync(path.join(root, 'certificate.json'), 'utf8').replace(/^\uFEFF/, ''));
  assert.match(identity.Subject, /^CN=sign-my-app disposable test [a-f0-9]{32}$/);
  const fake = path.join(root, 'FakeProvider.exe'), source = path.join(root, 'FakeProvider.cs');
  writeFileSync(source, `using System; using System.IO; using System.Threading;
class FakeProvider { static int Main(string[] args) {
 File.WriteAllText(args[args.Length - 1], "partial snapshot");
 string mode = File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "mode.txt"));
 if (mode == "wait") Thread.Sleep(120000);
 Console.Error.WriteLine("SignTool Error: " + mode); return 1;
} }`);
  await exec(ps, ['-NoProfile', '-NonInteractive', '-Command', `& ([IO.Path]::Combine([IO.Directory]::GetParent([Environment]::SystemDirectory).FullName, 'Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe')) /nologo /target:exe ${q('/out:' + fake)} ${q(source)}; exit $LASTEXITCODE`], { windowsHide: true });
  writeFileSync(path.join(install, 'scripts', 'Find-SignTool.ps1'), `param(); return ${q(fake)}`);
  const safety = path.join(install, 'scripts', 'Signing-Safety.ps1');
  // No network; the short timeout tests the same production timeout/cleanup path.
  writeFileSync(safety, readFileSync(safety, 'utf8').replace('Assert-SigningTimestamp $TimestampUrl -ResolveHost', 'Assert-SigningTimestamp $TimestampUrl').replace("{ 60000 } else { 45000 }", "{ 250 } else { 45000 }"));
  const { runHelper } = await import(pathToFileURL(path.join(install, 'mcp', 'runner.mjs')));
  const options = { systemDirectory: 'C:\\Windows\\System32', roots: [build] }, audit = [], trust = fileState(state);
  const flow = () => createSigning({ helper: runHelper, options, trust, audit: line => { audit.push(line); trust.audit(line); }, landingFolders: () => [] });
  const file = path.join(build, 'First app.exe'), before = hash(file), args = { files: [file], thumbprint: identity.Thumbprint };
  const check = (result, reason) => {
    assert.equal(result.failed, true); assert.equal(result.sessionRequired, true);
    assert.equal(result.sessionReason, reason);
    const wire = helperResult('sign_files', result);
    assert.equal(wire.isError, true); // Not signed; never report a signing success.
    const text = JSON.stringify(wire.content);
    assert.match(text, /sessionRequired/);
    assert.match(text, /certificate session looks closed/);
    assert.match(text, /log in to SimplySign Desktop/i);
    assert.match(text, /ask to sign again/);
    assert.doesNotMatch(text, /SignTool Error|declined|cancelled|refused|Signing checks or verification could not complete/i);
    assert.equal(hash(file), before);
    assert.ok(audit.some(line => line.outcome === `certificate session required: ${reason}`));
  };
  writeFileSync(path.join(root, 'mode.txt'), '0x80090016');
  const ticket = await flow().begin(args);
  assert.equal(typeof ticket.finish, 'function');
  check(await ticket.finish({ action: 'accept', content: { decision: 'Always for this project' } }), '0x80090016');
  // A new server lifetime retains trust and the pause separately.
  writeFileSync(path.join(root, 'mode.txt'), '0x8010006F');
  const next = await flow().begin(args); assert.ok(next.finish); check(await next.finish({ action: 'accept', content: { decision: 'Sign once' } }), '0x8010006F');
  writeFileSync(path.join(root, 'mode.txt'), 'wait');
  const waited = await flow().begin(args); assert.ok(waited.finish); check(await waited.finish({ action: 'accept', content: { decision: 'Sign once' } }), 'provider-wait-timeout');
  assert.ok(audit.some(line => line.approvalPath === 'elicitation' && line.outcome === 'approved signing attempt'));
  assert.equal(JSON.parse(readFileSync(path.join(state, 'project-trust.json'), 'utf8')).records.length, 1);
});
