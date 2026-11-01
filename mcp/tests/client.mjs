import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { PROTOCOL } from '../server.mjs';

export const meta = { 'io.modelcontextprotocol/protocolVersion': PROTOCOL, 'io.modelcontextprotocol/clientCapabilities': {} };
export class Client {
  constructor({ server = fileURLToPath(new URL('./test-server.mjs', import.meta.url)), args = [], cwd, env } = {}) {
    this.child = spawn(process.execPath, [server, ...args], { cwd, env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    this.pending = new Map(); this.sequence = 0; this.messages = []; this.stderr = '';
    this.child.stderr.on('data', b => { this.stderr += b; });
    createInterface({ input: this.child.stdout }).on('line', line => {
      const message = JSON.parse(line); this.messages.push(message);
      const waiter = this.pending.get(message.id);
      if (waiter) { clearTimeout(waiter.timer); this.pending.delete(message.id); waiter.resolve(message); }
    });
    this.child.on('exit', () => {
      for (const waiter of this.pending.values()) { clearTimeout(waiter.timer); waiter.reject(new Error('Server exited.')); }
      this.pending.clear();
    });
  }
  send(value) { this.child.stdin.write(JSON.stringify(value) + '\n'); }
  request(method, params = {}, modern = true) {
    const id = ++this.sequence;
    const promise = this.expect(id);
    this.send({ jsonrpc: '2.0', id, method, params: modern ? { ...params, _meta: meta } : params });
    return promise;
  }
  expect(id) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('Response timed out.')); }, 60000);
      this.pending.set(id, { resolve, reject, timer });
    });
  }
  call(name, args = {}) { return this.request('tools/call', { name, arguments: args }); }
  async close() {
    if (this.child.exitCode !== null) return;
    const exit = once(this.child, 'exit');
    this.child.stdin.end();
    const timer = setTimeout(() => this.child.kill(), 5000);
    try { await exit; } finally { clearTimeout(timer); }
  }
}
export const textOf = response => response.result?.content.map(c => c.text).join('\n') ?? '';
