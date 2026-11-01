import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const install = path.dirname(fileURLToPath(import.meta.url));
export const MAX_OUTPUT = 256 * 1024;
export const TIMEOUT_MS = 45000;

export function runHelper(request, { systemDirectory }, signal, callbacks = {}) {
  if (process.platform !== 'win32') return Promise.reject(new Error('Signing helpers require Windows.'));
  const powershell = path.win32.join(systemDirectory, 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const windows = path.win32.dirname(systemDirectory);
  const environment = { SystemRoot: windows, WINDIR: windows, PATH: systemDirectory,
    PSModulePath: path.win32.join(windows, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') };
  return new Promise((resolve, reject) => {
    const child = spawn(powershell, ['-NoLogo', '-NoProfile', '-STA', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', path.join(install, request.name === 'sign_files' ? 'approval-host.ps1' : 'bridge.ps1')], {
      cwd: systemDirectory, shell: false, windowsHide: true,
      // The managed host clears startup SW_HIDE before launching the bridge.
      // Private byte pipes preserve UTF-8 framing in both directions.
      // No inherited secrets, module search paths, profiles or project environment.
      env: environment,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    let output = Buffer.alloc(0), size = 0, stopped = false, settled = false;
    let frames = Buffer.alloc(0);
    function finish(error, result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', stop);
      if (error) reject(error); else resolve(result);
    }
    function stop() {
      if (stopped || settled) return;
      stopped = true;
      // Kill SignTool descendants as well as PowerShell; no shell is involved.
      if (child.pid) {
        const killer = spawn(path.win32.join(systemDirectory, 'taskkill.exe'),
          ['/PID', String(child.pid), '/T', '/F'], { cwd: systemDirectory, shell: false, windowsHide: true, stdio: 'ignore', env: environment });
        killer.on('error', () => child.kill());
        killer.on('close', () => child.kill());
      } else child.kill();
    }
    // Five minutes to answer, plus startup and signing/verification headroom.
    const timer = setTimeout(stop, request.name === 'sign_files' ? 480000 : TIMEOUT_MS);
    signal?.addEventListener('abort', stop, { once: true });
    child.on('error', () => finish(new Error('Could not start Windows PowerShell from System32. Check the Windows drive.')));
    child.stdin.on('error', () => {});
    child.stdout.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_OUTPUT) stop();
      else if (request.name !== 'sign_files') output = Buffer.concat([output, chunk]);
      else {
        frames = Buffer.concat([frames, chunk]);
        let end;
        while ((end = frames.indexOf(10)) !== -1) {
          const line = frames.subarray(0, end); frames = frames.subarray(end + 1);
          try {
            const value = JSON.parse(line.toString('utf8').replace(/^\uFEFF/u, ''));
            if (value.event === 'approval') {
              if (!callbacks.approval) { stop(); continue; }
              Promise.resolve(callbacks.approval(value.plans)).then(reply => {
                if (!stopped && !settled) child.stdin.write(JSON.stringify(reply) + '\n');
              }).catch(stop);
            } else if (['window_state', 'window_result'].includes(value.event)) callbacks.windowEvent?.(value);
            else if (value.event === 'signing_started') callbacks.signingStarted?.();
            else if (value.event === 'signed') callbacks.signed?.(value.plan, value.contentComparison);
            else if (value.event === 'window_approved') {
              if (!callbacks.windowApproved) { stop(); continue; }
              callbacks.windowApproved(value.decision);
              // Do not mutate until the private parent has logged/persisted the answer.
              child.stdin.end('{"recorded":true}\n');
            }
            else if (typeof value.failed === 'boolean') output = line;
            else stop();
          } catch { stop(); }
        }
      }
    });
    // Discard stderr entirely. Never return parser errors or environment details.
    child.stderr.on('data', chunk => { size += chunk.length; if (size > MAX_OUTPUT) stop(); });
    child.on('close', code => {
      if (stopped) { finish(new Error('Helper cancelled or reached its time or output limit. Narrow the folder and retry.')); return; }
      try {
        if (code !== 0) throw new Error();
        const result = JSON.parse(output.toString('utf8').replace(/^\uFEFF/u, ''));
        if (typeof result.failed !== 'boolean' || !Array.isArray(result.output)) throw new Error();
        finish(null, result);
      } catch { finish(new Error('The signing helper could not complete. Check local paths and Windows setup.')); }
    });
    if (request.name === 'sign_files') child.stdin.write(JSON.stringify(request) + '\n');
    else child.stdin.end(JSON.stringify(request) + '\n');
    if (signal?.aborted) stop();
  });
}
