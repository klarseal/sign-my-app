import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { launchOptions } from './safety.mjs';
import { runHelper } from './runner.mjs';
import { randomUUID } from 'node:crypto';
import { createSigning, approvalForm, unsafeClient, APPROVAL_MS } from './signing.mjs';
import { userState } from './trust.mjs';
import { buildRecipe } from './recipe.mjs';
import { tools, instructions, certificateMessage, networkNotice, validateArguments, helperResult } from './tools.mjs';

export const PROTOCOL = '2026-07-28';
export const LEGACY = ['2025-11-25', '2025-06-18', '2024-11-05'];
export const MAX_INPUT = 65536;
const identity = { name: 'klarseal-local-signing', version: readFileSync(new URL('../VERSION', import.meta.url), 'utf8').trim() };
const capabilities = { tools: {}, logging: {} };
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const own = (x, key) => Object.hasOwn(x, key);
const rpcError = (code, message, data) => ({ code, message, ...(data ? { data } : {}) });

export function startServer({ input = process.stdin, output = process.stdout, options, helper = runHelper, audit, trust, environment = process.env, now = Date.now, elapsedNow }) {
  let legacyVersion, initialized = false, buffer = Buffer.alloc(0), discard = false, closed = false;
  const active = new Map();
  const state = trust ?? (audit ? undefined : userState(options));
  const signing = createSigning({ helper, options, audit: audit ?? state.audit, trust: state, now, elapsedNow });
  const responses = new Map(), continuations = new Map();
  let clientCapabilities = {}, sequence = 0;
  function elicit(params, signal) {
    if (signal.aborted) return Promise.resolve({ action: 'cancel' });
    const id = `approval:${++sequence}`;
    return new Promise(resolve => {
      const done = value => { clearTimeout(timer); responses.delete(id); signal.removeEventListener('abort', cancel); resolve(value); };
      const cancel = () => done({ action: 'cancel' });
      const timer = setTimeout(() => done({ timedOut: true }), APPROVAL_MS);
      responses.set(id, done); signal.addEventListener('abort', cancel, { once: true });
      send({ jsonrpc: '2.0', id, method: 'elicitation/create', params });
    });
  }
  const send = value => {
    if (!closed && !output.destroyed) {
      output.write(JSON.stringify(value) + '\n');
      if (output.writableLength > 1024 * 1024) shutdown();
    }
  };
  function shutdown() {
    closed = true;
    for (const controller of active.values()) controller.abort();
    for (const done of responses.values()) done({ action: 'cancel' });
    for (const entry of continuations.values()) { entry.controller.abort(); void entry.ticket.finish({ action: 'cancel' }); }
    continuations.clear();
    active.clear(); buffer = Buffer.alloc(0);
    input.destroy();
  }
  async function receive(line) {
    let request;
    try { request = JSON.parse(line.toString('utf8')); }
    catch { send({ jsonrpc: '2.0', id: null, error: rpcError(-32700, 'Invalid JSON.') }); return; }
    const hasId = object(request) && own(request, 'id');
    if (object(request) && request.jsonrpc === '2.0' && !own(request, 'method') && responses.has(request.id)) {
      // Only a response on the client transport, never a tools/call argument.
      if (own(request, 'result') && !own(request, 'error')) responses.get(request.id)(request.result);
      else responses.get(request.id)(undefined); // Every error or unsupported response uses the window.
      return;
    }
    const validId = hasId && (Number.isSafeInteger(request.id) || (typeof request.id === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(request.id)));
    if (!object(request) || request.jsonrpc !== '2.0' || typeof request.method !== 'string' ||
        (hasId && !validId) || (own(request, 'params') && !object(request.params)) || own(request, 'result') || own(request, 'error')) {
      send({ jsonrpc: '2.0', id: validId ? request.id : null, error: rpcError(-32600, 'Invalid request.') }); return;
    }
    const { id, method } = request;
    const params = request.params ?? {};
    if (!hasId) {
      if (method === 'notifications/initialized' && legacyVersion) initialized = true;
      if (method === 'notifications/cancelled') {
        active.get(params.requestId)?.abort(); active.delete(params.requestId);
        // MRTR has already returned input_required, so its original controller
        // is no longer in active. Cancellation must still consume that prompt.
        for (const [token, entry] of continuations) {
          if (entry.requestId !== params.requestId) continue;
          continuations.delete(token); entry.controller.abort();
          void entry.ticket.finish({ action: 'cancel' });
        }
      }
      return; // Notifications never trigger tools or receive replies.
    }
    if (active.has(id)) { send({ jsonrpc: '2.0', id, error: rpcError(-32600, 'Request ID is already active.') }); return; }
    if (active.size >= 4) { send({ jsonrpc: '2.0', id, error: rpcError(-32603, 'Too many active requests.') }); return; }
    const controller = new AbortController(); active.set(id, controller);
    let modern = false;
    try {
      const meta = params._meta;
      const requestedVersion = object(meta) ? meta['io.modelcontextprotocol/protocolVersion'] : undefined;
      modern = requestedVersion !== undefined || (object(meta) && own(meta, 'io.modelcontextprotocol/clientCapabilities')) || method === 'server/discover';
      if (modern) {
        if (typeof requestedVersion !== 'string') throw rpcError(-32602, 'Protocol version metadata is required.');
        if (requestedVersion !== PROTOCOL) throw rpcError(-32022, 'Unsupported protocol version.', { supported: [PROTOCOL] });
        if (!object(meta['io.modelcontextprotocol/clientCapabilities'])) throw rpcError(-32602, 'Client capabilities metadata is required.');
      } else if (method !== 'initialize' && !(legacyVersion && (initialized || method === 'ping'))) {
        throw rpcError(-32600, 'Initialize first, or supply current protocol metadata.');
      }
      let result;
      switch (method) {
        case 'initialize':
          if (modern || legacyVersion || !object(params.capabilities) || typeof params.protocolVersion !== 'string' || !object(params.clientInfo)) throw rpcError(-32602, 'Invalid initialization.');
          legacyVersion = LEGACY.includes(params.protocolVersion) ? params.protocolVersion : LEGACY[0];
          clientCapabilities = params.capabilities;
          result = { protocolVersion: legacyVersion, capabilities, serverInfo: identity, instructions }; break;
        case 'server/discover': result = { supportedVersions: [PROTOCOL], capabilities, instructions }; break;
        case 'ping': result = {}; break;
        case 'tools/list':
          if (params.cursor !== undefined) throw rpcError(-32602, 'This server has no further pages.');
          result = { tools }; break;
        case 'tools/call': {
          if (Object.keys(params).some(key => !['name', 'arguments', '_meta', ...(modern ? ['requestState', 'inputResponses'] : [])].includes(key))) {
            if (params.name === 'sign_files') signing.refuse({ files: [], thumbprint: 'unavailable' }, 'unexpected tool fields');
            throw rpcError(-32602, 'Invalid tool call fields.');
          }
          if (!tools.some(tool => tool.name === params.name)) throw rpcError(-32602, 'Unknown tool.');
          let args;
          try { args = validateArguments(params.name, params.arguments ?? {}, options.roots); }
          catch {
            if (params.name === 'sign_files') signing.refuse({ files: [], thumbprint: 'unavailable' });
            result = { content: [{ type: 'text', text: 'Invalid arguments. Use only the listed fields and allowed full local paths. Rename unsafe files; links and traversal are refused. No approval bypass or credentials are accepted.' }], isError: true }; break;
          }
          if (params.name === 'sign_files') {
            send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'warning', logger: identity.name, data: networkNotice } });
            if (unsafeClient(environment, meta ?? {})) {
              signing.refuse(args, 'detectable automatic or bypass mode');
              result = helperResult('sign_files', { failed: true, output: ['Automatic or bypass mode detected. Start an interactive session with human approval enabled. Only you can approve.'] }); break;
            }
            if (own(params, 'requestState') || own(params, 'inputResponses')) {
              const entry = continuations.get(params.requestState);
              if (!entry || entry.key !== JSON.stringify(args)) { signing.refuse(args, 'unknown, changed or repeated approval'); throw rpcError(-32602, 'Approval is unknown, changed, expired or consumed.'); }
              continuations.delete(params.requestState);
              controller.signal.addEventListener('abort', () => entry.controller.abort(), { once: true });
              const values = params.inputResponses;
              let reply = object(values) && Object.keys(values).length === 1 ? values.signing_approval : undefined;
              result = helperResult('sign_files', await entry.ticket.finish(reply)); break;
            }
            const ticket = await signing.begin(args, controller.signal);
            if (ticket.result) { result = helperResult('sign_files', ticket.result); break; }
            const caps = modern ? meta['io.modelcontextprotocol/clientCapabilities'] : clientCapabilities;
            const supportsForm = object(caps.elicitation) && (own(caps.elicitation, 'form') || Object.keys(caps.elicitation).length === 0);
            if (supportsForm && modern) {
              const token = randomUUID();
              continuations.set(token, { ticket, key: JSON.stringify(args), controller, requestId: id });
              ticket.task.finally(() => continuations.delete(token)).catch(() => {});
              result = { resultType: 'input_required', requestState: token, inputRequests: { signing_approval: { method: 'elicitation/create', params: approvalForm(ticket.plans) } } };
            } else {
              const reply = supportsForm ? await elicit(approvalForm(ticket.plans), controller.signal) : { window: true };
              result = helperResult('sign_files', await ticket.finish(reply));
            }
            break;
          }
          if (params.name === 'forget_project_trust') result = helperResult(params.name, signing.forget(args));
          else if (params.name === 'get_build_recipe') result = helperResult(params.name, { failed: false, output: [buildRecipe(args, options.roots, options.systemDirectory)] });
          else if (params.name === 'get_certificate') result = { content: [{ type: 'text', text: certificateMessage }], isError: false };
          else {
            // The bridge buffers results, so a notice inside its final JSON is
            // too late. Emit a client-visible notification before starting it.
            if (['prepare_signing', 'verify_signature'].includes(params.name)) {
              send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'warning', logger: identity.name, data: networkNotice } });
            }
            try { result = helperResult(params.name, await helper({ name: params.name, arguments: args }, options, controller.signal)); }
            catch { result = { content: [{ type: 'text', text: 'The Windows helper could not complete or reached its time or size limit. Check Windows setup and use a smaller allowed build folder. Nothing signed; verification has not passed.' }], isError: true }; }
          }
          break;
        }
        default: throw rpcError(-32601, 'Method not found.');
      }
      if (modern) result = { ...result, resultType: result.resultType ?? 'complete', _meta: { 'io.modelcontextprotocol/serverInfo': identity } };
      if (!controller.signal.aborted) send({ jsonrpc: '2.0', id, result });
    } catch (error) {
      if (!controller.signal.aborted) send({ jsonrpc: '2.0', id, error: Number.isInteger(error.code) ? rpcError(error.code, error.message, error.data) : rpcError(-32603, 'Request could not complete.') });
    } finally { if (active.get(id) === controller) active.delete(id); }
  }
  input.on('data', chunk => {
    if (closed) return;
    let start = 0;
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] !== 10) continue;
      const part = chunk.subarray(start, i); start = i + 1;
      if (!discard && buffer.length + part.length <= MAX_INPUT) {
        const line = Buffer.concat([buffer, part]);
        if (line.length) void receive(line);
      } else if (!discard) send({ jsonrpc: '2.0', id: null, error: rpcError(-32600, 'Input size limit exceeded.') });
      discard = false; buffer = Buffer.alloc(0);
    }
    const tail = chunk.subarray(start);
    if (!discard && buffer.length + tail.length > MAX_INPUT) {
      discard = true; buffer = Buffer.alloc(0);
      send({ jsonrpc: '2.0', id: null, error: rpcError(-32600, 'Input size limit exceeded.') });
    } else if (!discard) buffer = Buffer.concat([buffer, tail]);
  });
  input.on('end', shutdown); input.on('error', shutdown); output.on('error', shutdown);
  return { shutdown };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (Number(process.versions.node.split('.')[0]) < 20) throw new Error();
    const server = startServer({ options: launchOptions(process.argv.slice(2)) });
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { server.shutdown(); process.exitCode = 0; });
  } catch { process.stderr.write('Could not start: use Node 20+ and valid --allow-root folder options.\n'); process.exitCode = 1; }
}
