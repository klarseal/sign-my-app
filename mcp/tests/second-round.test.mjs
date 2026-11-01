import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { display, localPath, launchOptions, allowedPath } from '../safety.mjs';
import { startServer } from '../server.mjs';
import { Client, meta } from './client.mjs';

test('round 2: generated invisible ranges match Unicode categories and properties', t => {
  const table = JSON.parse(readFileSync(new URL('../../scripts/Unicode-Safety.json', import.meta.url), 'utf8'));
  if (table.unicodeVersion !== process.versions.unicode) {
    t.skip(`Regeneration uses Unicode ${table.unicodeVersion}; this Node has ${process.versions.unicode}`);
    return;
  }
  const rule = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Co}\p{Default_Ignorable_Code_Point}\u2800]|[^\S ]/u;
  for (let cp = 0; cp <= 0x10FFFF; cp++) {
    const c = String.fromCodePoint(cp);
    assert.equal(display(c) !== c, rule.test(c), `U+${cp.toString(16)}`);
  }
});

test('round 2: default-ignorable letters and variation selectors are refused and escaped', () => {
  for (const cp of [0x3164, 0x115F, 0xFE0F, 0xE0100]) {
    const c = String.fromCodePoint(cp);
    assert.throws(() => localPath(`C:\\build\\App${c}Setup.exe`));
    assert.ok(!display(`App${c}Setup.exe`).includes(c));
  }
});

test('round 2: international allow-roots work without accepting ambiguous folds', { skip: process.platform !== 'win32' }, async t => {
  const repo = fileURLToPath(new URL('../../', import.meta.url));
  const root = mkdtempSync(path.join(repo, '.test-international-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(repo));
    assert.match(path.basename(root), /^\.test-international-[a-zA-Z0-9]+$/);
    rmSync(root, { recursive: true, force: true });
  });
  for (const name of ['Bj\u00F8rn', '\u00C5se', 'Jos\u00E9', '\u7530\u4E2D', '\u0418\u0432\u0430\u043D', '\u00E6\u00F8\u00E5\u00F6\u00FC\u00E9']) {
    const folder = path.join(root, name); mkdirSync(folder);
    const file = path.join(folder, 'app.exe'); writeFileSync(file, 'fixture');
    assert.deepEqual(launchOptions(['--allow-root', folder]).roots, [folder]);
    assert.equal(allowedPath(file, [folder]), file);
    const client = new Client({ args: ['--allow-root', folder] });
    try { assert.equal((await client.request('tools/list')).result.tools.length, 8); }
    finally { await client.close(); }
  }
  for (const c of ['\u212A', '\u017F', '\u0130', '\u0131']) {
    assert.throws(() => launchOptions(['--allow-root', `C:\\build\\${c}`]));
  }
});

test('round 2: MCP notice is observable before prepare/verify helper starts', { skip: process.platform !== 'win32' }, async t => {
  const repo = fileURLToPath(new URL('../../', import.meta.url));
  const root = mkdtempSync(path.join(repo, '.test-notice-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(repo));
    assert.match(path.basename(root), /^\.test-notice-[a-zA-Z0-9]+$/);
    rmSync(root, { recursive: true, force: true });
  });
  const file = path.join(root, 'app.exe'); writeFileSync(file, 'fixture');
  for (const name of ['prepare_signing', 'verify_signature']) {
    const input = new PassThrough(), output = new PassThrough();
    let visible = '';
    output.on('data', b => { visible += b; });
    let beforeHelper;
    startServer({ input, output, options: { roots: [root] }, helper: async () => {
      beforeHelper = visible;
      return { failed: false, output: [] };
    } });
    input.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {
      _meta: meta, name, arguments: name === 'prepare_signing' ? { files: [file], thumbprint: 'A'.repeat(40) } : { file }
    } }) + '\n');
    assert.equal(typeof beforeHelper, 'string');
    const notices = beforeHelper.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    assert.ok(notices.some(n => n.method === 'notifications/message' && n.params.level === 'warning' &&
      /Windows.*addresses.*file.*certificate/i.test(n.params.data)), beforeHelper);
    input.end();
  }
});
