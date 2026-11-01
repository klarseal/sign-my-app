import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { timestampUrl, launchOptions } from '../safety.mjs';
import { buildRecipe } from '../recipe.mjs';
import { fileState, scopesFor } from '../trust.mjs';
import { createSigning } from '../signing.mjs';

const ps = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const args = { files: ['C:\\src\\app\\dist\\app.exe'], thumbprint: '1'.repeat(40) };
function savedPolicyEnv() {
  const env = { ...process.env };
  // An inherited process bypass must not hide a missing launcher flag.
  for (const key of Object.keys(env)) if (key.toLowerCase() === 'psexecutionpolicypreference') delete env[key];
  return env;
}
function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'klarseal-review-'));
  t.after(() => { assert.equal(path.dirname(root), tmpdir()); assert.match(path.basename(root), /^klarseal-review-/); rmSync(root, { recursive: true, force: true }); });
  return root;
}
const hostile = ["'", '"', '`', '\u2018', '\u2019', '\u201a', '\u201b', '\u201c', '\u201d', '\u201e', '\u201f', '\uff07', '\uff02', '\u02bc', '\u00e9', '\u2028', '\u0000'];

test('review 1: timestamp URL uses an ASCII scheme, host, optional port and path only', () => {
  for (const c of hostile) assert.throws(() => timestampUrl(`http://time.certum.pl/${c};whoami;${c}`), undefined, JSON.stringify(c));
  for (const url of ['https://time.certum.pl:0/', 'https://time.certum.pl:65536/', 'https://time.certum.pl/%zz', 'https://time.certum.pl/?a', 'https://time.certum.pl/#x', 'https://user@time.certum.pl/', 'https://time.certum.pl\\evil', 'https://-bad.example/']) assert.throws(() => timestampUrl(url), undefined, url);
  for (const url of ['http://time.certum.pl', 'https://tsa.example:8443/rfc3161/v1%20tsa']) assert.equal(timestampUrl(url), url);
});

test('review 1: recipes reject every hostile value, including paths and thumbprints', () => {
  for (const c of hostile) {
    for (const changed of [{ ...args, timestamp_url: `http://time.certum.pl/${c};whoami;${c}` }, { ...args, thumbprint: c + '1'.repeat(39) }, { ...args, files: [`C:\\src\\app\\dist\\app${c}.exe`] }]) {
      assert.throws(() => buildRecipe(changed, ['C:\\src\\app\\dist']), undefined, JSON.stringify(changed));
    }
    assert.throws(() => buildRecipe(args, [`C:\\src\\app\\dist${c}`]));
    assert.throws(() => buildRecipe(args, [], `C:\\Windows\\System32${c}`));
  }
});

test('review 1: PowerShell parser sees only data even if recipe validation is bypassed', { skip: process.platform !== 'win32' }, t => {
  const root = fixture(t);
  // Test the code generation layer independently of input validation. Never execute a recipe.
  const source = readFileSync(new URL('../recipe.mjs', import.meta.url), 'utf8').replace(/^import .*;\r?\n/gm, '').replaceAll('export ', '').replaceAll('import.meta.url', 'moduleUrl');
  const unchecked = vm.runInNewContext(source + '\nbuildRecipe', {
    fileURLToPath, moduleUrl: import.meta.url, Buffer, process, URL,
    recipeValue: value => value, timestampUrl: value => value, localPath: value => value
  });
  const scripts = [];
  for (const c of hostile) {
    const attack = `${c};whoami;${c}`;
    scripts.push(unchecked({ ...args, timestamp_url: 'http://time.certum.pl/' + attack }, ['C:\\src\\app\\dist']));
    scripts.push(unchecked({ ...args, thumbprint: attack }, ['C:\\src\\app\\dist']));
    scripts.push(unchecked({ ...args, files: ['C:\\src\\app\\dist\\' + attack + '.exe'] }, ['C:\\src\\app\\dist']));
    scripts.push(unchecked(args, ['C:\\src\\app\\' + attack]));
  }
  writeFileSync(path.join(root, 'scripts.json'), JSON.stringify(scripts));
  const probe = path.join(root, 'parse.ps1');
  writeFileSync(probe, `param([string]$InputFile)
$ErrorActionPreference = 'Stop'
$scripts = Get-Content -Raw -LiteralPath $InputFile | ConvertFrom-Json
foreach ($source in $scripts) {
  $tokens = $null; $errors = $null
  $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
  if ($errors.Count -or $ast.EndBlock.Statements.Count -ne 4) { throw 'Recipe escaped its expected statements' }
  $commands = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true))
  if ($commands.Count -ne 2 -or @($commands | Where-Object { $_.GetCommandName() -eq 'whoami' }).Count) { throw 'Injected command' }
}
Write-Output $scripts.Count
`);
  const result = spawnSync(ps, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', probe, '-InputFile', path.join(root, 'scripts.json')], { env: savedPolicyEnv(), encoding: 'utf8', windowsHide: true, timeout: 30000 });
  assert.equal(result.error, undefined, `PowerShell parser helper could not run: ${result.error?.message}`);
  assert.equal(result.status, 0, `PowerShell parser helper failed (exit ${result.status}, signal ${result.signal}):\n${result.stderr}\n${result.stdout}`);
  assert.equal(result.stdout.trim(), String(scripts.length), 'PowerShell parser helper did not confirm every hostile recipe');
  t.diagnostic(`Windows PowerShell parsed all ${scripts.length} hostile recipes without executing them.`);
});

test('generated build launch command runs a harmless script under the saved Windows policy', { skip: process.platform !== 'win32' }, t => {
  const root = fixture(t);
  // Exercise only the printed launcher, never a signing recipe or certificate.
  writeFileSync(path.join(root, 'sign.ps1'), "Write-Output 'BUILD LAUNCHER RAN'\n");
  const command = buildRecipe(args, ['C:\\src\\app\\dist']).split('\r\n').find(line => line.startsWith('# & '));
  assert.ok(command, 'Generated sign.ps1 must show how to launch it');
  const result = spawnSync(ps, ['-NoProfile', '-NonInteractive', '-Command', command.slice(2)], { cwd: root, env: savedPolicyEnv(), encoding: 'utf8', windowsHide: true, timeout: 30000 });
  assert.equal(result.error, undefined, `Build launcher could not start: ${result.error?.message}`);
  assert.equal(result.status, 0, `Build launcher failed under saved policy:\n${result.stderr}\n${result.stdout}`);
  assert.equal(result.stdout.trim(), 'BUILD LAUNCHER RAN');
});

test('review 2: forgetting a subfolder revokes covering trust and next signing asks', async t => {
  const root = fixture(t), build = path.join(root, 'dist'), child = path.join(build, 'release');
  mkdirSync(child, { recursive: true });
  const file = path.join(child, 'app.exe'); writeFileSync(file, 'synthetic');
  const request = { ...args, files: [file] }, options = { roots: [build] }, trust = fileState(root);
  const plans = [{ File: file, SHA256: 'A'.repeat(64), Thumbprint: args.thumbprint, Publisher: 'CN=Fixture', TimestampUrl: 'http://time.certum.pl' }];
  const scopes = scopesFor(plans, request, options.roots); trust.remember(scopes);
  const flow = createSigning({ options, trust, audit: () => {}, helper: async (_a, _o, _s, cb) => ({ failed: (await cb.approval(plans)).sign !== 'Sign', output: [] }) });
  const result = flow.forget({ project_folder: child.toUpperCase(), thumbprint: args.thumbprint.toLowerCase() });
  assert.match(result.output[0], /Removed 1/); assert.equal(trust.has(scopes), false);
  const next = await flow.begin(request); assert.equal(typeof next.finish, 'function'); await next.finish({ action: 'cancel' });
});

test('review 2: zero removals report no change and filtered revocation preserves other publishers', t => {
  const root = fixture(t), trust = fileState(root);
  const scope = { folder: path.join(root, 'dist'), thumbprint: args.thumbprint, machine_store: false, timestamp_url: 'http://time.certum.pl' };
  trust.remember([scope, { ...scope, thumbprint: '2'.repeat(40) }]);
  assert.equal(trust.forget(path.join(scope.folder, 'release'), args.thumbprint), 1);
  assert.equal(trust.has([{ ...scope, thumbprint: '2'.repeat(40) }]), true);
  const flow = createSigning({ trust, audit: () => {} });
  const result = flow.forget({ project_folder: path.join(root, 'unrelated') });
  assert.equal(result.failed, true); assert.match(result.output[0], /No .*removed|No .*changed/); assert.doesNotMatch(result.output[0], /Future signing asks again/);
});

test('review 3: manual Claude marketplace install is pinned to the release', () => {
  const guide = readFileSync(new URL('../INSTALL-FOR-AGENTS.md', import.meta.url), 'utf8');
  assert.match(guide, /klarseal\/sign-my-app#v1\.1\.0/);
  assert.doesNotMatch(guide, /--marketplace klarseal\/sign-my-app(?!#v1\.1\.0)/);
});

test('review 4: drive children and profile roots cannot be allowed output folders', () => {
  for (const folder of ['C:\\src', 'D:\\build', 'C:\\Users\\Alex', homedir(), 'C:\\']) assert.throws(() => launchOptions(['--allow-root', folder]), /build output folder/i, folder);
});

test('review 4: source projects and their parents are refused; actual output is accepted', t => {
  const root = fixture(t), project = path.join(root, 'project'), output = path.join(project, 'dist'); mkdirSync(output, { recursive: true });
  writeFileSync(path.join(project, 'package.json'), '{}'); writeFileSync(path.join(output, 'app.exe'), 'synthetic');
  for (const folder of [root, project]) assert.throws(() => launchOptions(['--allow-root', folder]), /build output folder/i);
  assert.deepEqual(launchOptions(['--allow-root', output]).roots, [output]);
  const plans = [{ File: path.join(output, 'app.exe') }];
  assert.throws(() => scopesFor(plans, args, [project]), /build output folder/i);
});
