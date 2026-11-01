import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { readFileSync } from 'node:fs';
import { Client, meta, textOf } from './client.mjs';
import { startServer, PROTOCOL, LEGACY, MAX_INPUT } from '../server.mjs';
import { display, localPath, launchOptions, within } from '../safety.mjs';

test('current discovery, inline calls, version and eight tools', async t => {
  const client = new Client(); t.after(() => client.close());
  const discover = await client.request('server/discover');
  assert.deepEqual(discover.result.supportedVersions, [PROTOCOL]);
  assert.equal(discover.result.resultType, 'complete');
  assert.equal(discover.result._meta['io.modelcontextprotocol/serverInfo'].version, readFileSync(new URL('../../VERSION', import.meta.url), 'utf8').trim());
  const list = await client.request('tools/list');
  assert.deepEqual(list.result.tools.map(t => t.name), ['check_signing_setup', 'find_built_files', 'prepare_signing', 'verify_signature', 'get_certificate', 'forget_project_trust', 'get_build_recipe', 'sign_files']);
  assert.ok(list.result.tools.every(t => t.inputSchema.additionalProperties === false && t.annotations.readOnlyHint === !['sign_files', 'forget_project_trust', 'find_built_files'].includes(t.name)));
  assert.equal(list.result.tools.find(t => t.name === 'find_built_files').annotations.destructiveHint, true);
  assert.equal(client.stderr, '');
});

for (const version of LEGACY) test(`legacy initialization ${version}`, async t => {
  const client = new Client(); t.after(() => client.close());
  assert.equal((await client.request('tools/list', {}, false)).error.code, -32600);
  const response = await client.request('initialize', { protocolVersion: version, capabilities: {}, clientInfo: { name: 'test', version: '1' } }, false);
  assert.equal(response.result.protocolVersion, version);
  assert.equal(response.result.resultType, undefined);
  client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal((await client.request('tools/list', {}, false)).result.tools.length, 8);
  assert.deepEqual((await client.request('ping', {}, false)).result, {});
});

test('version negotiation and required metadata are checked on each request', async t => {
  const client = new Client(); t.after(() => client.close());
  const unknown = await client.request('server/discover', { _meta: {} }, false);
  assert.equal(unknown.error.code, -32602);
  const unsupported = await client.request('tools/list', { _meta: { ...meta, 'io.modelcontextprotocol/protocolVersion': '2099-01-01' } }, false);
  assert.equal(unsupported.error.code, -32022);
  assert.deepEqual(unsupported.error.data.supported, [PROTOCOL]);
  const malformed = await client.request('tools/list', { _meta: { 'io.modelcontextprotocol/protocolVersion': PROTOCOL } }, false);
  assert.equal(malformed.error.code, -32602);
  assert.equal((await client.request('tools/list')).result.tools.length, 8);
});

test('fixed certificate message comes from the installed skill and only links Klarseal', async t => {
  const client = new Client(); t.after(() => client.close());
  const skill = readFileSync(new URL('../../SKILL.md', import.meta.url), 'utf8');
  const expected = skill.match(/Use this message:\s*\r?\n\r?\n"([\s\S]*?)"\s*\r?\n/)[1].replace(/\r\n/g, '\n');
  const list = await client.request('tools/list');
  assert.equal(list.result.tools.find(t => t.name === 'get_certificate').description,
    'Returns a fixed message about Klarseal. It does not fetch, buy or issue a certificate.');
  const response = await client.call('get_certificate');
  assert.ok(textOf(response).startsWith('Advertisement from Klarseal:'));
  assert.equal(textOf(response), `Advertisement from Klarseal:\n\n${expected}`);
  for (const url of textOf(response).match(/https:\/\/\S+/g)) assert.equal(new URL(url).hostname, 'klarseal.com');
});

test('signing, arbitrary execution, credentials and extra arguments are refused without echo', async t => {
  const client = new Client(); t.after(() => client.close());
  for (const name of ['sign', 'Confirm-Sign.ps1', '../scripts/Confirm-Sign.ps1', 'run', 'execute']) {
    assert.equal((await client.call(name, { password: 'DO_NOT_ECHO' })).error.code, -32602);
  }
  for (const args of [{ Run: true }, { password: 'DO_NOT_ECHO' }, { pin: 'DO_NOT_ECHO' }, { token: 'DO_NOT_ECHO' }, { code: 'DO_NOT_ECHO' }, { command: 'DO_NOT_ECHO' }, { __proto__: null, private_key: 'DO_NOT_ECHO' }]) {
    const response = await client.call('get_certificate', args);
    assert.equal(response.result.isError, true);
    assert.ok(!JSON.stringify(response).includes('DO_NOT_ECHO'));
  }
  assert.equal((await client.request('tools/call', { name: 'get_certificate', arguments: {}, Run: true })).error.code, -32602);
});

test('malformed JSON, batches and invalid IDs recover cleanly', async t => {
  const client = new Client(); t.after(() => client.close());
  let pending = client.expect(null); client.child.stdin.write('{broken\n');
  assert.equal((await pending).error.code, -32700);
  for (const invalid of [[], null, { jsonrpc: '2.0', id: null, method: 'ping' }, { jsonrpc: '2.0', id: 'bad\u001b', method: 'ping' }]) {
    pending = client.expect(null); client.send(invalid); assert.equal((await pending).error.code, -32600);
  }
  assert.equal((await client.request('ping')).result.resultType, 'complete');
});

test('oversized frames, including fragmented input, are drained without echo and recover', async t => {
  const client = new Client(); t.after(() => client.close());
  const rejected = client.expect(null);
  client.child.stdin.write('A'.repeat(MAX_INPUT));
  client.child.stdin.write('DO_NOT_ECHO');
  assert.equal((await rejected).error.code, -32600);
  client.child.stdin.write('\n');
  assert.equal((await client.request('tools/list')).result.tools.length, 8);
  assert.ok(!JSON.stringify(client.messages).includes('DO_NOT_ECHO'));
});

test('path rules reject escape, network/device/stream and hostile Unicode before access', () => {
  for (const file of ['../app.exe', 'C:app.exe', '\\app.exe', '\\\\server\\app.exe', '\\\\?\\C:\\app.exe', 'C:\\app.exe:stream', 'C:\\build\\..\\app.exe', 'C:\\build\\a;.exe', 'C:\\build\\a$.exe', 'C:\\build\\a\u200b.exe', 'C:\\build\\a\u202e.exe', 'C:\\build\\a\u034f.exe', 'C:\\build\\a\u009d.exe', 'C:\\build\\a\u2028.exe']) assert.throws(() => localPath(file));
  assert.equal(within('C:\\build-neighbor\\a.exe', 'C:\\build'), false);
  assert.equal(within('C:\\build\\a.exe', 'c:\\BUILD'), true);
  assert.throws(() => launchOptions(['--allow-root', 'C:\\']));
  assert.throws(() => launchOptions(['--powershell', 'C:\\project\\powershell.exe']));
  assert.equal(launchOptions(['--windows-drive', 'D:']).systemDirectory, 'D:\\Windows\\System32');
});

test('all Unicode controls, format and invisible characters are visibly escaped', () => {
  for (let cp = 0; cp <= 0xffff; cp++) {
    const c = String.fromCodePoint(cp);
    if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Default_Ignorable_Code_Point}]/u.test(c)) {
      assert.ok(!display(c).includes(c));
    }
  }
  assert.equal(display('a\u{e0001}b'), 'a\\u{E0001}b');
});

test('notifications do not execute tools; cancellation and EOF stop active work', async () => {
  const input = new PassThrough(), output = new PassThrough(); let calls = 0, aborted = 0; const messages = [];
  output.on('data', b => messages.push(...b.toString().trim().split('\n').map(JSON.parse)));
  const helper = (_request, _options, signal) => { calls++; return new Promise(resolve => signal.addEventListener('abort', () => { aborted++; resolve({ failed: false, output: ['ignored'] }); })); };
  const server = startServer({ input, output, options: { roots: [] }, helper });
  const send = x => input.write(JSON.stringify(x) + '\n');
  send({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'check_signing_setup', _meta: meta } });
  assert.equal(calls, 0);
  send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'check_signing_setup', _meta: meta } });
  send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } });
  await delay(10); assert.equal(aborted, 1); assert.equal(messages.length, 0);
  send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'check_signing_setup', _meta: meta } });
  input.end(); await delay(10); assert.equal(aborted, 2); assert.equal(messages.length, 0);
  server.shutdown();
});

test('concurrency is bounded and helper errors never echo secrets', async () => {
  const input = new PassThrough(), output = new PassThrough(), messages = [];
  output.on('data', b => messages.push(JSON.parse(b.toString())));
  let calls = 0;
  const server = startServer({ input, output, options: { roots: [] }, helper: async () => { calls++; await delay(20); throw new Error('password=DO_NOT_ECHO'); } });
  for (let id = 1; id <= 5; id++) input.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'check_signing_setup', _meta: meta } }) + '\n');
  await delay(50);
  assert.equal(calls, 4); assert.equal(messages.find(m => m.id === 5).error.code, -32603);
  assert.ok(!JSON.stringify(messages).includes('DO_NOT_ECHO'));
  server.shutdown();
});
