// Named OS mutexes recover after killed runs; there are no stale lock files.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const helper = fileURLToPath(new URL('./Desktop-Lock.ps1', import.meta.url));
const lockSource = readFileSync(helper, 'utf8').replace('param([switch]$Lease)', '');
export async function withDesktopLock(action) {
  if (process.platform !== 'win32') throw new Error('Desktop tests require Windows');
  const child = spawn('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helper, '-Lease'],
    { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let errors = '';
  child.stdin.on('error', () => {}); // Exit/error promise reports a failed broker.
  child.stderr.on('data', chunk => { errors += chunk; });
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', code => code === 0 ? resolve() : reject(new Error(`Desktop lock exited ${code}: ${errors}`)));
  });
  exited.catch(() => {});
  let output = '';
  const acquired = new Promise(resolve => child.stdout.on('data', chunk => {
    output += chunk;
    if (output.includes('LOCKED')) resolve();
  }));
  try {
    await Promise.race([acquired, exited.then(() => { throw new Error('Desktop lock exited before acquisition'); })]);
    return await action();
  } finally {
    child.stdin.end('\n');
    await exited;
  }
}
export const testOnlyTitle = 'TEST ONLY - nothing will be signed';
export function testOnlySource(source) {
  if (!source.includes("$form.Text = 'Sign my app'")) throw new Error('Missing production title');
  // Embed the window lock in private copies, including real-bridge fixtures.
  return lockSource + '\n' + source.replace('function Request-NativeSigningApproval(', 'function Invoke-UnlockedTestApproval(')
    .replace("$form.Text = 'Sign my app'", `$form.Text = '${testOnlyTitle}'`)
    .replace('$text.Text = ($Message', "$Message = \"TEST ONLY - nothing will be signed`r`n\" + $Message\n    $text.Text = ($Message") + `
function Request-NativeSigningApproval($Message, $RemainingMilliseconds, $OnEvent) {
    Invoke-WithDesktopTestLock { Invoke-UnlockedTestApproval $Message $RemainingMilliseconds $OnEvent }
}
`;
}
