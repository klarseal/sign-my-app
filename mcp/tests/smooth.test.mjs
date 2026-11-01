import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createSigning, accepted, approvalForm } from '../signing.mjs';
import { fileState, scopesFor } from '../trust.mjs';
import { validateArguments } from '../tools.mjs';
import { buildRecipe } from '../recipe.mjs';

const answer = decision => ({ action: 'accept', content: { decision } });
function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'klarseal-smooth-'));
  t.after(() => { assert.equal(path.dirname(root), tmpdir()); assert.match(path.basename(root), /^klarseal-smooth-/); rmSync(root, { recursive: true, force: true }); });
  const build = path.join(root, 'build'), state = path.join(root, 'state'); mkdirSync(build); mkdirSync(state);
  const file = path.join(build, 'app.exe'); writeFileSync(file, 'synthetic payload');
  let clock = 100000, session = true, signs = 0, nativeDecision, failAfter;
  const options = { roots: [build] }, args = { files: [file], thumbprint: '1'.repeat(40) }, audit = [], trust = fileState(state);
  const helper = async ({ arguments: a }, o, signal, cb) => {
    const plans = a.files.map(File => ({ File, SHA256: createHash('sha256').update(readFileSync(File)).digest('hex').toUpperCase(),
      Thumbprint: a.thumbprint, Publisher: 'CN=Fixture', TimestampUrl: a.timestamp_url ?? 'http://time.certum.pl', MachineStore: a.machine_store === true, PlanHash: 'A'.repeat(64) }));
    const reply = await cb.approval(plans);
    if (reply.path === 'window') {
      if (!nativeDecision || nativeDecision === 'Cancel') return { failed: true, output: [] };
      cb.windowApproved(nativeDecision); reply.sign = 'Sign';
    }
    if (signal?.aborted || reply.sign !== 'Sign') return { failed: true, output: [] };
    for (const p of plans) {
      if (!session) return { failed: true, sessionRequired: true, output: ['Please sign in to your signing app, then tell me.'] };
      signs++; cb.signed(p); if (signs === failAfter) session = false;
    }
    return { failed: false, output: [{ Verification: 'synthetic only' }] };
  };
  const flow = () => createSigning({ helper, options, trust, landingFolders: () => [], audit: line => { audit.push(line); trust.audit(line); }, now: () => clock });
  return { root, build, file, state, trust, options, args, audit, flow, signs: () => signs, session: value => { session = value; }, failAfter: value => { failAfter = value; }, native: value => { nativeDecision = value; }, advance: ms => { clock += ms; } };
}

test('Always is opt-in; only an exact person answer creates persistent trust', async t => {
  const f = fixture(t);
  for (const reply of [answer('Sign once'), answer('Always'), { ...answer('Always for this project'), content: { decision: 'Always for this project', approved: true } },
    { ...answer('Always for this project'), automatic: true }, { action: 'decline', content: { decision: 'Always for this project' } }, { action: 'accept' }]) {
    const ticket = await f.flow().begin(f.args); await ticket.finish(reply);
    assert.equal(f.trust.has(scopesFor(ticket.plans, f.args, f.options.roots)), false);
  }
  for (const extra of [{ always: true }, { trust: true }, { approval: 'Always for this project' }, { env: { KLARSEAL_TRUST: true } }]) assert.throws(() => validateArguments('sign_files', { ...f.args, ...extra }, f.options.roots));
  writeFileSync(path.join(f.build, 'project-trust.json'), JSON.stringify({ always: true }));
  const ticket = await f.flow().begin(f.args); assert.ok(ticket.finish); await ticket.finish(answer('Always for this project'));
  const next = await f.flow().begin(f.args); assert.equal(next.result.failed, false);
  assert.ok(f.audit.some(x => x.approvalPath === 'project-trust' && x.outcome === 'signed and verified'));
  const log = readFileSync(path.join(f.state, 'signing-audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.ok(log.every(line => line.time && line.approvalPath));
});

for (const change of ['thumbprint', 'folder', 'timestamp', 'store']) test(`changed ${change} asks again; outside refuses`, async t => {
  const f = fixture(t); const first = await f.flow().begin(f.args); await first.finish(answer('Always for this project'));
  let args = { ...f.args };
  if (change === 'thumbprint') args.thumbprint = '2'.repeat(40);
  if (change === 'timestamp') args.timestamp_url = 'https://time.certum.pl';
  if (change === 'store') args.machine_store = true;
  if (change === 'folder') { const child = path.join(f.build, 'new-output'); mkdirSync(child); const file = path.join(child, 'app.exe'); writeFileSync(file, 'new'); f.options.roots = [child]; args.files = [file]; }
  const ticket = await f.flow().begin(args); assert.equal(typeof ticket.finish, 'function'); await ticket.finish(answer('Cancel'));
  const outside = path.join(f.root, 'outside.exe'); writeFileSync(outside, 'outside');
  assert.throws(() => validateArguments('sign_files', { ...args, files: [outside] }, f.options.roots));
});

test('forget removes trust and recovery without approval, including during a prompt', async t => {
  const f = fixture(t), flow = f.flow(); const ticket = await flow.begin(f.args); await ticket.finish(answer('Always for this project'));
  assert.match(flow.forget({}).output[0], /Removed 1/);
  const next = await flow.begin(f.args); assert.ok(next.finish);
  flow.forget({}); assert.equal((await next.finish(answer('Always for this project'))).failed, true);
  assert.equal(f.trust.has(scopesFor(next.plans, f.args, f.options.roots)), false);
});

test('native private relay persists Always only after its explicit decision', async t => {
  const f = fixture(t); f.native('Sign once');
  await (await f.flow().begin(f.args)).finish({ window: true });
  let next = await f.flow().begin(f.args); assert.ok(next.finish); await next.finish(answer('Cancel'));
  f.native('Always for this project'); await (await f.flow().begin(f.args)).finish({ window: true });
  next = await f.flow().begin(f.args); assert.equal(next.result.failed, false);
  assert.ok(f.audit.some(line => line.approvalPath === 'window' && line.outcome === 'project trust created by person answer'));
});

test('environment and malformed trust records cannot grant signing', async t => {
  const f = fixture(t);
  for (const name of ['KLARSEAL_ALWAYS', 'KLARSEAL_TRUST', 'SIGN_MY_APP_SKIP_APPROVAL']) {
    const previous = process.env[name]; process.env[name] = '1';
    try { const next = await f.flow().begin(f.args); assert.ok(next.finish); await next.finish(answer('Cancel')); }
    finally { if (previous === undefined) delete process.env[name]; else process.env[name] = previous; }
  }
  writeFileSync(path.join(f.state, 'project-trust.json'), JSON.stringify({ version: 1, records: [{ folder: f.build, thumbprint: f.args.thumbprint, approved: true }] }));
  const result = await f.flow().begin(f.args); assert.equal(result.result.failed, true); assert.equal(f.signs(), 0);
  f.flow().forget({}); assert.equal(JSON.parse(readFileSync(path.join(f.state, 'project-trust.json'), 'utf8')).records.length, 0);
});

test('expired session resumes the unchanged approved plan; changed bytes ask again', async t => {
  const f = fixture(t), flow = f.flow(); f.session(false);
  const ticket = await flow.begin(f.args); assert.equal((await ticket.finish(answer('Sign once'))).sessionRequired, true);
  f.session(true); assert.equal((await flow.begin(f.args)).result.failed, false);
  assert.ok(f.audit.some(x => x.approvalPath === 'session-recovery'));
  f.session(false); const second = await flow.begin(f.args); await second.finish(answer('Sign once'));
  writeFileSync(f.file, 'changed bytes'); f.session(true);
  const changed = await flow.begin(f.args); assert.ok(changed.finish); await changed.finish(answer('Cancel'));
});

test('Always pauses after each session failure across restart, then continues after one approval', async t => {
  const f = fixture(t); f.session(false);
  const first = await f.flow().begin(f.args);
  assert.equal((await first.finish(answer('Always for this project'))).sessionRequired, true);
  for (let attempt = 0; attempt < 4; attempt++) {
    const next = await f.flow().begin(f.args);
    assert.ok(next.finish); assert.equal((await next.finish(answer('Sign once'))).sessionRequired, true);
  }
  f.session(true);
  const recovered = await f.flow().begin(f.args);
  assert.ok(recovered.finish); assert.equal((await recovered.finish(answer('Sign once'))).failed, false);
  assert.equal(f.signs(), 1);
  const next = await f.flow().begin(f.args);
  assert.equal(next.result.failed, false); assert.equal(f.signs(), 2);
  assert.ok(f.audit.some(line => line.outcome === 'certificate session required: key unavailable'));
  assert.ok(!f.audit.some(line => /refused|declined/.test(line.outcome)));
});

test('recovery expires ten minutes from the first failure, even after failed retries', async t => {
  const f = fixture(t), flow = f.flow(); f.session(false);
  const first = await flow.begin(f.args);
  assert.equal((await first.finish(answer('Sign once'))).sessionRequired, true);
  f.advance(300000);
  assert.equal((await flow.begin(f.args)).result.sessionRequired, true);
  f.advance(299999);
  assert.equal((await flow.begin(f.args)).result.sessionRequired, true);
  f.advance(1); f.session(true);
  const expired = await flow.begin(f.args);
  assert.ok(expired.finish); assert.equal(f.signs(), 0);
  assert.equal((await expired.finish(answer('Sign once'))).failed, false);
});

test('recipe is exact, read-only, and uses the same operation with explicit scopes', t => {
  const f = fixture(t);
  const quote = s => "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Buffer.from(s, 'utf8').toString('base64') + "')))";
  const entry = fileURLToPath(new URL('../build-sign.mjs', import.meta.url));
  const expected = '#Requires -Version 5.1\r\n$ErrorActionPreference = \'Stop\'\r\n$OutputEncoding = New-Object Text.UTF8Encoding($false)\r\n' +
    '# From the folder containing sign.ps1, run in PowerShell:\r\n' +
    '# & ([IO.Path]::Combine([Environment]::SystemDirectory, \'WindowsPowerShell\\v1.0\\powershell.exe\')) -NoProfile -ExecutionPolicy Bypass -File ".\\sign.ps1"\r\n' +
    '# Bypass applies only to this process; no saved execution policy is changed.\r\n' +
    '# Keep your signing app session open. Sign payload, build installer, then sign installer.\r\n' +
    '# This uses the same policy and calls Microsoft SignTool, then verifies the timestamp.\r\n' +
    `${quote(JSON.stringify({ name: 'sign_files', arguments: f.args }))} | & ${quote(process.execPath)} ${quote(entry)} --allow-root ${quote(f.build)}\r\n` +
    "if ($LASTEXITCODE -ne 0) { throw 'Signing did not complete. Please sign in to your signing app, then tell me. Review the result before retrying.' }\r\n";
  assert.equal(buildRecipe(f.args, [f.build]), expected);
  assert.ok(buildRecipe(f.args, [f.build], 'D:\\Windows\\System32').includes('--windows-drive ' + quote('D:')));
  assert.equal(approvalForm([]).requestedSchema.properties.decision.default, 'Cancel');
  assert.equal(accepted(answer('Sign')), false);
});

test('session expiry mid-batch resumes only the remaining files', async t => {
  const f = fixture(t), flow = f.flow(), second = path.join(f.build, 'second.dll'); writeFileSync(second, 'second payload');
  const args = { ...f.args, files: [f.file, second] }; f.failAfter(1);
  const failed = await (await flow.begin(args)).finish(answer('Sign once'));
  assert.equal(failed.sessionRequired, true); assert.equal(f.signs(), 1);
  const pending = failed.output.find(line => line.ResumeAfterManualLogin).ResumeAfterManualLogin;
  assert.deepEqual(pending.files, [second]);
  f.session(true); assert.equal((await flow.begin(pending)).result.failed, false); assert.equal(f.signs(), 2);
});

test('Windows state helper restricts a temporary directory to the user and SYSTEM', { skip: process.platform !== 'win32' }, async t => {
  const f = fixture(t), script = path.join(f.root, 'state-probe.ps1');
  const source = readFileSync(new URL('../state-directory.ps1', import.meta.url), 'utf8')
    .replace("Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Klarseal\\SignMyApp'", "'" + f.state.replaceAll("'", "''") + "'");
  writeFileSync(script, source + `\n$acl = Get-Acl -LiteralPath $folder\n@{ Protected = $acl.AreAccessRulesProtected; User = $sid.Value; Rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value }) } | ConvertTo-Json -Compress\n`);
  const { stdout } = await promisify(execFile)('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script], { windowsHide: true, timeout: 15000 });
  const acl = JSON.parse(stdout.trim().split(/\r?\n/).at(-1));
  assert.equal(acl.Protected, true); assert.deepEqual(new Set(acl.Rules), new Set([acl.User, 'S-1-5-18']));
});
