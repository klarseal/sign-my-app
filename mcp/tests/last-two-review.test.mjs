import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSigning } from '../signing.mjs';
import { fileState, scopesFor } from '../trust.mjs';
import { launchOptions, landingFolders as windowsLandingFolders, projectTrustFolder } from '../safety.mjs';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const friendly = "Always works on your project's build folder; this folder is one that downloads land in. Choose Sign once, or use your build folder.";
const answer = decision => ({ action: 'accept', content: { decision } });
function fixture(t) {
  const root = mkdtempSync(path.join(repo, '.test-last-two-'));
  t.after(() => {
    assert.equal(path.dirname(root), path.resolve(repo));
    assert.match(path.basename(root), /^\.test-last-two-/);
    rmSync(root, { recursive: true, force: true });
  });
  return root;
}
function signing(folder, state, landingFolders) {
  mkdirSync(folder, { recursive: true });
  const file = path.join(folder, 'app.exe'); writeFileSync(file, 'synthetic, never executed');
  const args = { files: [file], thumbprint: '1'.repeat(40) }, options = { roots: [folder] };
  const trust = fileState(state), plans = [{ File: file, SHA256: 'A'.repeat(64), Thumbprint: args.thumbprint,
    Publisher: 'CN=Fixture', TimestampUrl: 'http://time.certum.pl' }];
  let signs = 0;
  const flow = () => createSigning({ options, trust, landingFolders, audit: () => {}, helper: async (_a, _o, _s, cb) => {
    const reply = await cb.approval(plans);
    if (reply.path === 'window') cb.windowApproved(decision);
    if (reply.path === 'window' || reply.sign === 'Sign') { signs++; return { failed: false, output: [] }; }
    return { failed: true, output: [] };
  } });
  let decision;
  return { args, options, plans, trust, flow, signs: () => signs, native: value => { decision = value; } };
}

test('Always refuses scopes containing, equal to, or anywhere inside landing folders', () => {
  const folders = [
    'D:\\Data\\Alex\\Downloads', 'D:\\Data\\Alex\\Desktop', 'D:\\Data\\Alex\\Documents',
    'D:\\Scratch\\Temp', 'C:\\Users\\Public', 'C:\\Users\\LandingFixtureUser'
  ];
  for (const base of folders) {
    for (const scope of [path.win32.dirname(base), base, path.win32.join(base, 'a'), path.win32.join(base, 'a', 'b', 'dist')]) {
      assert.throws(() => projectTrustFolder(scope, folders), error => error.message === friendly, scope);
    }
  }
  assert.throws(() => projectTrustFolder('C:\\Users\\Public\\Documents\\a\\b', folders), error => error.message === friendly);
  for (const scope of ['C:\\MyApp\\dist', 'D:\\src\\app\\bin\\Release', 'D:\\Data\\Alex\\Downloads-backup', 'D:\\Scratch\\Temp-build']) {
    assert.equal(projectTrustFolder(scope, folders), scope);
  }
});

test('Always canonicalises both sides, including existing ancestors of missing folders', { skip: process.platform !== 'win32' }, t => {
  const root = fixture(t), landing = path.join(root, 'Redirected', 'Downloads');
  mkdirSync(landing, { recursive: true });
  for (const [scope, base] of [
    [path.dirname(landing).toUpperCase(), landing],
    [path.dirname(landing), landing.toUpperCase()],
    [path.join(landing.toUpperCase(), 'a', 'b'), landing],
    [path.join(landing, 'a', 'b'), landing.toUpperCase()],
    [path.join(landing, 'a', 'b'), path.join(landing.toUpperCase(), 'a')]
  ]) assert.throws(() => projectTrustFolder(scope, [base]), error => error.message === friendly, scope);
});

test('last two: every remote install source in README and agent guide pins v1.1.0', () => {
  const release = readFileSync(new URL('../../VERSION', import.meta.url), 'utf8').trim();
  assert.equal(release, 'v1.1.0');
  for (const relative of ['../../README.md', '../INSTALL-FOR-AGENTS.md']) {
    const text = readFileSync(new URL(relative, import.meta.url), 'utf8');
    const lines = text.split(/\r?\n/).filter(line => /(?:--marketplace |marketplace add )klarseal\/sign-my-app/.test(line));
    assert.ok(lines.length, relative);
    for (const line of lines) {
      assert.match(line, /klarseal\/sign-my-app(?:#v1\.1\.0|@v1\.1\.0| --ref v1\.1\.0)(?=[`\s.]|$)/, `${relative}: ${line}`);
    }
    const prompts = text.split(/\r?\n/).filter(line => /Install the Klarseal MCP(?: v[0-9.]+)? from/.test(line));
    assert.ok(prompts.length, `Missing versioned install prompt: ${relative}`);
    for (const line of prompts) {
      assert.ok(line.includes(release), `Natural-language install must request ${release}: ${line}`);
    }
  }
});

test('last two: environment landing roots and direct children refuse Always but allow Sign once', { skip: process.platform !== 'win32' }, async t => {
  const root = fixture(t), state = path.join(root, 'state'); mkdirSync(state);
  const saved = Object.fromEntries(['USERPROFILE', 'TEMP', 'TMP', 'PUBLIC'].map(key => [key, process.env[key]]));
  try {
    for (const key of Object.keys(saved)) process.env[key] = path.join(root, key.toLowerCase());
    const resolved = windowsLandingFolders();
    const landing = [process.env.TEMP, process.env.TMP, process.env.PUBLIC,
      ...['Downloads', 'Desktop', 'Documents'].flatMap(name => [path.join(process.env.USERPROFILE, name), path.join(process.env.PUBLIC, name)])];
    for (const base of landing) for (const folder of [base, path.join(base, 'extracted')]) {
      const f = signing(folder, state, () => resolved);
      const flow = f.flow();
      // These are still valid one-time output scopes, including before a first build.
      assert.deepEqual(launchOptions(['--allow-root', folder]).roots, [folder]);
      for (const native of [false, true]) {
        f.native('Always for this project');
        const ticket = await flow.begin(f.args);
        const result = await ticket.finish(native ? { window: true } : answer('Always for this project'));
        assert.equal(result.failed, true, folder);
        assert.ok(result.output.includes(friendly), folder);
        assert.equal(f.signs(), native ? 1 : 0, 'Always must not reach even the synthetic signing step');
        assert.equal(f.trust.has(scopesFor(f.plans, f.args, f.options.roots)), false);
        f.native('Sign once');
        const once = await flow.begin(f.args);
        assert.equal((await once.finish(native ? { window: true } : answer('Sign once'))).failed, false, folder);
      }
    }
  } finally {
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});

test('last two: native Windows lookup protects actual known folders and their direct children', { skip: process.platform !== 'win32' }, () => {
  const folders = windowsLandingFolders();
  assert.ok(folders.length >= 9);
  for (const folder of folders.filter(p => /^[a-z]:[\\/]/i.test(p))) {
    for (const candidate of [folder, path.win32.join(folder, 'downloaded-release')]) {
      assert.throws(() => projectTrustFolder(candidate, folders), error => error.message === friendly, candidate);
    }
  }
});

test('last two: redirected non-English known folders reject new and previously saved Always trust', { skip: process.platform !== 'win32' }, async t => {
  const root = fixture(t), state = path.join(root, 'state'); mkdirSync(state);
  const known = ['Nedlastinger', 'Skrivebord', 'Dokumenter', 'Offentlig', 'Felles nedlastinger'].map(name => path.join(root, 'omdirigert', name));
  const landingFolders = () => known;
  for (const base of known) for (const folder of [path.dirname(base), base, path.join(base, 'utpakket'), path.join(base, 'a', 'b')]) {
    const f = signing(folder, state, landingFolders);
    const ticket = await f.flow().begin(f.args);
    const result = await ticket.finish(answer('Always for this project'));
    assert.equal(result.failed, true, folder); assert.ok(result.output.includes(friendly)); assert.equal(f.signs(), 0);
    const scopes = scopesFor(f.plans, f.args, f.options.roots);
    f.trust.remember(scopes); // Simulate trust written by an older release, never a real certificate.
    const dropped = path.join(folder, 'dropped.exe'); writeFileSync(dropped, 'new synthetic download, never executed');
    f.args.files = [dropped]; f.plans[0].File = dropped;
    const next = await f.flow().begin(f.args);
    assert.equal(typeof next.finish, 'function', 'Unsafe saved trust must ask again');
    assert.equal((await next.finish(answer('Sign once'))).failed, false);
    f.trust.forget();
  }
});

test('last two: failed known-folder lookup refuses only Always and never reuses saved trust', { skip: process.platform !== 'win32' }, async t => {
  const root = fixture(t), state = path.join(root, 'state'); mkdirSync(state);
  const f = signing(path.join(root, 'project', 'dist'), state, () => { throw new Error('Lookup failed'); });
  const flow = f.flow(), ticket = await flow.begin(f.args);
  const result = await ticket.finish(answer('Always for this project'));
  assert.equal(result.failed, true); assert.equal(f.signs(), 0);
  f.trust.remember(scopesFor(f.plans, f.args, f.options.roots));
  const once = await flow.begin(f.args);
  assert.equal(typeof once.finish, 'function');
  assert.equal((await once.finish(answer('Sign once'))).failed, false);
});
