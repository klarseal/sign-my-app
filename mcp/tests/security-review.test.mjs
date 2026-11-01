import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';
import vm from 'node:vm';
import path from 'node:path';
import { display, localPath, within, allowedPath } from '../safety.mjs';

test('S1: Unicode folding cannot widen allowed roots', () => {
  for (const [planted, real] of [['pac\u212Aaging', 'packaging'], ['di\u017Ft', 'dist'], ['d\u0131st', 'dist']]) {
    assert.equal(within(`C:\\${planted}\\x.exe`, `C:\\${real}`), false);
    assert.throws(() => localPath(`C:\\${planted}\\x.exe`));
  }
  assert.equal(within('C:\\BUILD\\app.exe', 'c:\\build'), true);
});

test('S1: filesystem-resolved containment and actual Windows case pairs', { skip: process.platform !== 'win32' }, t => {
  const repo = fileURLToPath(new URL('../../', import.meta.url));
  const root = mkdtempSync(path.join(repo, '.test-case-'));
  t.after(() => {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(repo));
    assert.match(path.basename(root), /^\.test-case-[a-zA-Z0-9]+$/);
    rmSync(root, { recursive: true, force: true });
  });
  for (const [real, alias] of [['packaging', 'pac\u212Aaging'], ['dist', 'di\u017Ft'], ['disk', 'd\u0131sk']]) {
    mkdirSync(path.join(root, real));
    const file = path.join(root, real, 'app.exe'); writeFileSync(file, 'fixture');
    assert.equal(allowedPath(file, [path.join(root, real).toUpperCase()]), file);
    const planted = path.join(root, alias);
    t.diagnostic(`NTFS alias U+${Array.from(alias).find(c => c.codePointAt(0) > 127).codePointAt(0).toString(16).toUpperCase()}: ${existsSync(planted)}`);
    if (real === 'packaging') assert.equal(existsSync(planted), false);
    if (!existsSync(planted)) mkdirSync(planted);
    writeFileSync(path.join(planted, 'app.exe'), 'planted fixture');
    assert.throws(() => allowedPath(path.join(planted, 'app.exe'), [path.join(root, real)]));
  }
});

test('S3: ambiguous blanks and private-use text are escaped and refused', () => {
  for (const cp of [0xA0, 0x2003, 0x3000, 0x2800, 0xE000, 0xF0000, 0x100000]) {
    const c = String.fromCodePoint(cp);
    assert.equal(display(`First${c}app.exe`), `First\\u{${cp.toString(16).toUpperCase()}}app.exe`);
    assert.throws(() => localPath(`C:\\build\\First${c}app.exe`));
  }
  assert.equal(localPath('C:\\build\\First app.exe'), 'C:\\build\\First app.exe');
});

test('S5: every runner child has a System32 executable and explicit safe cwd', async () => {
  // Exercise cancellation with a spawn recorder; no Windows process is launched.
  const calls = [];
  let helper;
  const spawn = (exe, args, options) => {
    calls.push({ exe, args, options });
    const child = new EventEmitter();
    child.stdin = new EventEmitter(); child.stdin.end = () => {};
    child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
    child.kill = () => queueMicrotask(() => child.emit('close', 1));
    if (calls.length === 1) { helper = child; child.pid = 1234; }
    else queueMicrotask(() => child.emit('close', 0));
    return child;
  };
  const source = readFileSync(new URL('../runner.mjs', import.meta.url), 'utf8')
    .replace(/^import .*;\r?\n/gm, '').replaceAll('export ', '')
    .replace('import.meta.url', 'moduleUrl').replace('process.platform', "'win32'");
  const runHelper = vm.runInNewContext(`${source}\nrunHelper`, {
    spawn, path, fileURLToPath: () => 'C:\\installed\\mcp\\runner.mjs', moduleUrl: 'unused',
    Buffer, setTimeout, clearTimeout
  });
  const controller = new AbortController();
  const pending = runHelper({}, { systemDirectory: 'C:\\Windows\\System32' }, controller.signal);
  controller.abort();
  await assert.rejects(pending, /cancelled/);
  assert.equal(calls.length, 2);
  for (const { exe, options } of [...calls].reverse()) {
    assert.ok(exe.startsWith('C:\\Windows\\System32\\'));
    assert.equal(options.cwd, 'C:\\Windows\\System32');
    assert.equal(options.shell, false);
  }
  assert.ok(helper);
});
