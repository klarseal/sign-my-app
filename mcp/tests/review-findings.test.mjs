import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { PassThrough } from 'node:stream';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createSigning, approvalForm, unsafeClient } from '../signing.mjs';
import { startServer, PROTOCOL } from '../server.mjs';
import { validateArguments } from '../tools.mjs';

const yes = { action: 'accept', content: { decision: 'Sign once' } };
const plan = { File: 'C:\\build\\app.exe', SHA256: 'A'.repeat(64), Thumbprint: '1'.repeat(40), Publisher: 'CN=Fixture', TimestampUrl: 'http://time.certum.pl' };
function fixture(t) {
  let clock = 100000, prompts = 0;
  const root = mkdtempSync(fileURLToPath(new URL('../../.test-fatigue-', import.meta.url)));
  t.after(() => { assert.match(path.basename(root), /^\.test-fatigue-/); rmSync(root, { recursive: true, force: true }); });
  const file = path.join(root, 'fixture.exe'); writeFileSync(file, 'not executable');
  const args = { files: [file], thumbprint: plan.Thumbprint };
  const helper = async (request, options, signal, cb) => {
    prompts++;
    const reply = await cb.approval([{ ...plan, File: file, Thumbprint: request.arguments.thumbprint }]);
    if (reply.path === 'window') return { failed: true, output: ['Native cancelled'] };
    return { failed: reply.sign !== 'Sign', output: [] };
  };
  const now = () => clock;
  return { args, helper, now, options: { roots: [root] }, advance: n => { clock += n; }, prompts: () => prompts,
    flow: createSigning({ helper, now, audit: () => {} }) };
}
for (const answer of [{ action: 'decline' }, { action: 'cancel' }, { action: 'accept', content: { decision: 'Cancel' } }]) {
  test(`R3: ${JSON.stringify(answer)} blocks all plans for exactly 60 seconds`, async t => {
    const f = fixture(t), ticket = await f.flow.begin(f.args);
    await ticket.finish(answer);
    const changed = { ...f.args, thumbprint: '2'.repeat(40) };
    await assert.rejects(f.flow.begin(changed), error => {
      assert.match(error.message, /Stop.*ask the person in words/i);
      assert.doesNotMatch(error.message, /60|second|wait|restart|relaunch|reset/i);
      return true;
    });
    f.advance(59999); await assert.rejects(f.flow.begin(f.args), /Stop/i);
    f.advance(1); await (await f.flow.begin(changed)).finish(yes);
    assert.equal(f.prompts(), 2);
  });
}
test('R3: three declines pause prompts but never require a restart', async t => {
  const f = fixture(t);
  for (let i = 0; i < 3; i++) {
    await (await f.flow.begin(f.args)).finish({ action: 'decline' });
    f.advance(60000);
  }
  f.advance(86400000);
  assert.equal((await (await f.flow.begin(f.args)).finish(yes)).failed, false);
  const fresh = createSigning({ helper: f.helper, now: f.now, audit: () => {} });
  assert.equal((await (await fresh.begin(f.args)).finish(yes)).failed, false);
});
test('R3: native cancellation and transport abort keep cooldown; unanswered timeout does not', async t => {
  for (const mode of ['window', 'timeout', 'abort']) {
    const f = fixture(t), controller = new AbortController();
    const flow = createSigning({ helper: f.helper, now: f.now, timeout: 15, audit: () => {} });
    const ticket = await flow.begin(f.args, controller.signal);
    if (mode === 'timeout') await delay(30);
    if (mode === 'abort') controller.abort();
    await ticket.finish(mode === 'window' ? { window: true } : yes);
    if (mode === 'timeout') {
      assert.equal((await (await flow.begin(f.args)).finish(yes)).failed, false);
    } else await assert.rejects(flow.begin(f.args), /Stop.*ask the person in words/i);
  }
});
test('R3: real server refuses 25 rapid reasks and changed publishers; one outstanding MRTR prompt', async t => {
  const f = fixture(t), input = new PassThrough(), output = new PassThrough(), messages = [];
  const server = startServer({ input, output, helper: f.helper, now: f.now, options: f.options, audit: () => {}, environment: {} });
  t.after(() => server.shutdown());
  output.on('data', b => messages.push(...b.toString().trim().split('\n').map(JSON.parse)));
  const send = (id, extra = {}) => input.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: {
    name: 'sign_files', arguments: f.args, _meta: { 'io.modelcontextprotocol/protocolVersion': PROTOCOL, 'io.modelcontextprotocol/clientCapabilities': { elicitation: { form: {} } } }, ...extra
  } }) + '\n');
  const wait = async id => { for (let i = 0; i < 200; i++) { const x = messages.find(x => x.id === id); if (x) return x; await delay(2); } throw Error('missing reply'); };
  send(1); const first = (await wait(1)).result;
  send(2); assert.ok((await wait(2)).error); assert.equal(f.prompts(), 1);
  send(3, { requestState: first.requestState, inputResponses: { signing_approval: { action: 'decline' } } }); await wait(3);
  for (let i = 4; i < 29; i++) {
    send(i, { arguments: { ...f.args, thumbprint: (i % 2 ? '2' : '1').repeat(40) } });
    assert.match(JSON.stringify(await wait(i)), /Stop.*ask the person in words/i);
  }
  assert.equal(f.prompts(), 1);
});
test('R4: fictitious Claude environment settings are not claimed as detection', () => {
  for (const env of [{ CLAUDE_CODE_PERMISSION_MODE: 'bypassPermissions' }, { CLAUDE_CODE_DANGEROUSLY_SKIP_PERMISSIONS: '1' }]) assert.equal(unsafeClient(env), false);
  assert.equal(unsafeClient({ CI: '1' }), true);
  assert.equal(unsafeClient({}, { permissionMode: 'bypassPermissions' }), true);
});
test('R3: cancelling an outstanding MRTR request consumes its prompt and starts cooldown', async t => {
  const f = fixture(t), input = new PassThrough(), output = new PassThrough(), messages = [];
  const server = startServer({ input, output, helper: f.helper, now: f.now, options: f.options, audit: () => {}, environment: {} });
  t.after(() => server.shutdown());
  output.on('data', b => messages.push(...b.toString().trim().split('\n').map(JSON.parse)));
  const params = { name: 'sign_files', arguments: f.args, _meta: { 'io.modelcontextprotocol/protocolVersion': PROTOCOL, 'io.modelcontextprotocol/clientCapabilities': { elicitation: { form: {} } } } };
  const send = (id, method, params) => input.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  const wait = async id => { for (let i = 0; i < 200; i++) { const x = messages.find(x => x.id === id); if (x) return x; await delay(2); } throw Error('missing reply'); };
  send(1, 'tools/call', params); const first = (await wait(1)).result;
  send(undefined, 'notifications/cancelled', { requestId: 1 });
  await delay(10);
  send(2, 'tools/call', params);
  assert.match(JSON.stringify(await wait(2)), /Stop.*ask the person in words/i);
  send(3, 'tools/call', { ...params, requestState: first.requestState, inputResponses: { signing_approval: yes } });
  assert.equal((await wait(3)).error.code, -32602); assert.equal(f.prompts(), 1);
});
test('R5: edge and internal space padding is escaped in approval', () => {
  const message = approvalForm([{ ...plan, Publisher: ' '.repeat(1000) + 'CN=Good' + ' '.repeat(1000) + 'Bad' + ' '.repeat(1000) }]).message;
  assert.ok(!message.includes('  ')); assert.match(message, /CN=Good/); assert.match(message, /Bad/);
});
test('R5: non-ASCII timestamp authority is rejected before URL punycode normalization', t => {
  const f = fixture(t);
  for (const timestamp_url of ['https://t\u0456me.certum.pl', 'https://time.c\u0435rtum.pl', 'https://\uFF54ime.certum.pl']) {
    assert.throws(() => validateArguments('sign_files', { ...f.args, timestamp_url }, f.options.roots));
    assert.throws(() => approvalForm([{ ...plan, TimestampUrl: timestamp_url }]));
  }
});
