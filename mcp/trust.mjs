import { appendFileSync, existsSync, readFileSync, realpathSync, renameSync, writeFileSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { allowedPath, noLinks, within, outputFolder } from './safety.mjs';

export function scopesFor(plans, args, roots) {
  return [...new Set(plans.map(p => {
    const file = realpathSync.native(allowedPath(p.File, roots));
    const folder = roots.map(root => { noLinks(root); return realpathSync.native(root); })
      .filter(root => within(file, root)).sort((a, b) => b.length - a.length)[0];
    if (!folder) throw new Error('No allowed output folder.');
    outputFolder(folder);
    return JSON.stringify({ folder, thumbprint: args.thumbprint.toUpperCase(), machine_store: args.machine_store === true,
      timestamp_url: args.timestamp_url ?? 'http://time.certum.pl' });
  }))].map(JSON.parse);
}
const key = scope => JSON.stringify(scope);

// Directory injection is a module-level test seam, never a tool/config/env option.
export function fileState(directory) {
  const file = name => { noLinks(directory); const result = path.join(directory, name); if (existsSync(result)) noLinks(result); return result; };
  const load = (name = 'project-trust.json') => {
    const target = file(name);
    if (!existsSync(target)) return [];
    const bytes = readFileSync(target, 'utf8');
    if (bytes.length > 1024 * 1024) throw new Error('Trust file too large.');
    const data = JSON.parse(bytes);
    if (data.version !== 1 || !Array.isArray(data.records) || data.records.some(r => !r ||
      Object.keys(r).sort().join(',') !== 'folder,machine_store,thumbprint,timestamp_url' || typeof r.folder !== 'string' ||
      !/^[A-F0-9]{40}$/.test(r.thumbprint) || typeof r.machine_store !== 'boolean' || typeof r.timestamp_url !== 'string')) throw new Error('Invalid trust file.');
    return data.records;
  };
  const save = (records, name = 'project-trust.json') => {
    const temporary = file(`trust-${randomUUID()}.tmp`);
    try { writeFileSync(temporary, JSON.stringify({ version: 1, records }, null, 2) + '\n', { flag: 'wx' }); renameSync(temporary, file(name)); }
    finally { if (existsSync(temporary)) unlinkSync(temporary); }
  };
  return {
    has(scopes) { const records = load().map(key); return scopes.length > 0 && scopes.every(s => records.includes(key(s))); },
    remember(scopes) { const records = load(); save([...new Map([...records, ...scopes].map(r => [key(r), r])).values()]); },
    paused(scopes) { const records = load('project-pauses.json').map(key); return scopes.some(s => records.includes(key(s))); },
    pause(scopes) { const records = load('project-pauses.json'); save([...new Map([...records, ...scopes].map(r => [key(r), r])).values()], 'project-pauses.json'); },
    resume(scopes) { const records = load('project-pauses.json'); const keep = records.filter(r => !scopes.some(s => key(s) === key(r))); if (keep.length !== records.length) save(keep, 'project-pauses.json'); },
    forget(folder, thumbprint) { let records, malformed = false;
      try { records = load(); } catch (error) { if (folder || thumbprint) throw error; records = []; malformed = true; }
      const keep = records.filter(r =>
      folder && !within(folder, r.folder) && !within(r.folder, folder) || thumbprint && r.thumbprint !== thumbprint.toUpperCase());
      if (malformed || keep.length !== records.length) save(keep);
      return malformed ? -1 : records.length - keep.length; },
    audit(line) { appendFileSync(file('signing-audit.jsonl'), JSON.stringify(line) + '\n'); }
  };
}

export function userState(options) {
  let state;
  const get = () => {
    if (state) return state;
    const system = options.systemDirectory;
    const windows = path.win32.dirname(system);
    const result = spawnSync(path.win32.join(system, 'WindowsPowerShell/v1.0/powershell.exe'),
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', fileURLToPath(new URL('./state-directory.ps1', import.meta.url))],
      { cwd: system, windowsHide: true, encoding: 'utf8', timeout: 15000, maxBuffer: 8192,
        env: { SystemRoot: windows, WINDIR: windows, PATH: system, PSModulePath: path.win32.join(system, 'WindowsPowerShell/v1.0/Modules') } });
    const directory = result.stdout?.trim();
    if (result.status !== 0 || !directory || !path.win32.isAbsolute(directory) ||
      options.roots.some(root => within(directory, root) || within(root, directory))) throw new Error('Private per-user signing state unavailable or overlaps output.');
    state = fileState(directory); return state;
  };
  return Object.fromEntries(['has', 'remember', 'paused', 'pause', 'resume', 'forget', 'audit'].map(method => [method, (...args) => get()[method](...args)]));
}
