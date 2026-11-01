import path from 'node:path';
import { lstatSync, realpathSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Generated from Unicode categories and Default_Ignorable_Code_Point. PowerShell
// uses this same table, rather than .NET Framework's older Unicode categories.
const { ranges } = JSON.parse(readFileSync(new URL('../scripts/Unicode-Safety.json', import.meta.url), 'utf8'));
const invisible = { test: value => Array.from(value).some(c => {
  const cp = c.codePointAt(0);
  let low = 0, high = ranges.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1, [first, last] = ranges[mid];
    if (cp < first) high = mid - 1;
    else if (cp > last) low = mid + 1;
    else return true;
  }
  return false;
}) };
// Refuse ASCII/Turkic fold ambiguities; ordinary international letters are valid.
// Containment folds ASCII only, then checks filesystem-resolved paths ordinally.
const unsafeCase = value => /[\u212A\u017F\u0130\u0131]/u.test(value);
const asciiLower = value => value.replace(/[A-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + 32));
export function display(value) {
  return Array.from(String(value), c => invisible.test(c)
    ? `\\u{${c.codePointAt(0).toString(16).toUpperCase()}}` : c).join('');
}

export function timestampUrl(value) {
  // Validate the original spelling, including the path, before URL normalisation.
  const parts = typeof value === 'string' && /^https?:\/\/([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?(\/[A-Za-z0-9._~!$&()*+,;=:@%/-]*)?$/i.exec(value);
  if (!parts || /[^\x21-\x7e]/u.test(value) || parts[1].length > 253 || parts[1].split('.').some(label => !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)) ||
      parts[2] && (+parts[2] < 1 || +parts[2] > 65535) || /%(?![A-Fa-f0-9]{2})/.test(value)) {
    throw new Error('Use a public HTTP(S) timestamp URL with an ASCII host, optional port and path; no quotes, credentials, query or fragment.');
  }
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error('Use a public HTTP(S) timestamp URL with an ASCII host and no credentials, query or fragment.');
  }
  return value;
}

// Recipe source has a deliberately smaller alphabet than live signing paths.
export function recipeValue(value) {
  if (typeof value !== 'string' || /[^\x20-\x7e]|['"`]/u.test(value)) {
    throw new Error('Use ASCII values without quotes for sign.ps1, including the installed helper and build output paths.');
  }
  return value;
}

export function localPath(value) {
  if (typeof value !== 'string' || value.length > 1024 || !/^[a-z]:[\\/]/i.test(value) ||
      invisible.test(value) || unsafeCase(value) || /['"\u2018-\u201f`$;&|<>*?]/u.test(value) ||
      value.slice(2).includes(':') || value.split(/[\\/]/).some(p => p === '..' || /[. ]$/.test(p))) {
    throw new Error('Use a full local drive path without links, traversal, invisible text, ambiguous case folds or shell characters. Rename unsafe files.');
  }
  return path.win32.normalize(value);
}

export function within(file, root) {
  if (unsafeCase(file) || unsafeCase(root)) return false;
  return ordinalWithin(asciiLower(path.win32.normalize(file)), asciiLower(path.win32.normalize(root)));
}

function ordinalWithin(file, root) {
  return file === root || file.startsWith(root.endsWith('\\') ? root : root + '\\');
}

export function noLinks(file) {
  let current = path.win32.parse(file).root;
  for (const part of file.slice(current.length).split('\\').filter(Boolean)) {
    current = path.win32.join(current, part);
    if (lstatSync(current).isSymbolicLink()) throw new Error('Use local files without links or junctions.');
  }
}

export function allowedPath(value, roots) {
  const file = localPath(value);
  if (!roots.some(root => within(file, root))) throw new Error('Path is outside the folders allowed when this server was started.');
  // Validate every ancestor, including the allowed root. PowerShell repeats this check.
  noLinks(file);
  // Let the filesystem resolve case, short names and case-sensitive directories.
  // Never feed these paths to win32.relative (it lowercases internally).
  const realFile = realpathSync.native(file);
  if (!roots.some(root => { noLinks(root); return ordinalWithin(realFile, realpathSync.native(root)); })) {
    throw new Error('Resolved path is outside the folders allowed when this server was started.');
  }
  return file;
}

export function outputFolder(value) {
  const folder = localPath(value), parts = folder.slice(3).split('\\').filter(Boolean);
  const refuse = () => { throw new Error('Choose the actual build output folder, such as your app\'s dist folder. Please avoid source folders and folders shared by projects.'); };
  if (parts.length < 2 || within(homedir(), folder) || /^users$/i.test(parts[0]) && parts.length <= 2 ||
      /^documents and settings$/i.test(parts[0]) && parts.length <= 2) refuse();
  // A source project anywhere below this folder means the scope is too broad.
  // Bound the walk; large or unreadable trees need a narrower output folder.
  const pending = [folder]; let entries = 0, directories = 0;
  while (pending.length) {
    const current = pending.pop();
    if (!existsSync(current)) continue; // Setup may precede the first build.
    if (++directories > 512) refuse();
    noLinks(current);
    let children;
    try { children = readdirSync(current, { withFileTypes: true }); } catch { refuse(); }
    for (const child of children) {
      if (++entries > 8192) refuse();
      if (/^(?:\.git|\.hg|\.svn|package\.json|Cargo\.toml|pyproject\.toml|go\.mod|CMakeLists\.txt|Makefile|meson\.build|build\.gradle(?:\.kts)?|pom\.xml)$|\.(?:sln|slnx|csproj|fsproj|vbproj|vcxproj)$/i.test(child.name)) refuse();
      if (child.isDirectory() && !/^(?:node_modules|vendor)$/i.test(child.name)) pending.push(path.win32.join(current, child.name));
    }
  }
  return folder;
}

export const landingFolderMessage = "Always works on your project's build folder; this folder is one that downloads land in. Choose Sign once, or use your build folder.";

// These paths restrict persistent trust only, never a one-time signing request.
// Environment paths supplement Windows' actual known folders: redirected and
// localised folders must stay protected even if an agent changes its environment.
export function landingFolders(systemDirectory = 'C:\\Windows\\System32') {
  const folders = [homedir(), tmpdir(), process.env.TEMP, process.env.TMP];
  for (const profile of [homedir(), process.env.USERPROFILE, process.env.PUBLIC]) {
    if (!profile) continue;
    folders.push(profile, ...['Downloads', 'Desktop', 'Documents'].map(name => path.win32.join(profile, name)));
  }
  if (process.platform === 'win32') {
    const windows = path.win32.dirname(systemDirectory);
    const result = spawnSync(path.win32.join(systemDirectory, 'WindowsPowerShell/v1.0/powershell.exe'),
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', fileURLToPath(new URL('./landing-folders.ps1', import.meta.url))],
      { cwd: systemDirectory, windowsHide: true, encoding: 'utf8', timeout: 15000, maxBuffer: 32768,
        env: { SystemRoot: windows, WINDIR: windows, PATH: systemDirectory, PSModulePath: path.win32.join(systemDirectory, 'WindowsPowerShell/v1.0/Modules') } });
    let known;
    try { known = JSON.parse(result.stdout); } catch { /* Refuse Always when Windows lookup fails. */ }
    if (result.status !== 0 || !Array.isArray(known) || known.length < 8 || known.some(p => typeof p !== 'string' || !p)) {
      throw new Error('Windows folder lookup unavailable. Choose Sign once, or restart the signing server and try again.');
    }
    folders.push(...known);
  }
  return folders.filter(Boolean);
}

export function projectTrustFolder(value, folders) {
  const folder = localPath(value);
  const canonical = p => {
    const missing = [];
    let current = p;
    while (!existsSync(current)) {
      const parent = path.win32.dirname(current);
      if (parent === current) return p;
      missing.unshift(path.win32.basename(current));
      current = parent;
    }
    return path.win32.join(realpathSync.native(current), ...missing);
  };
  const file = canonical(folder);
  for (const candidate of folders) {
    // UNC known folders cannot be signing scopes; ignore them, not the other paths.
    if (!/^[a-z]:[\\/]/i.test(candidate)) continue;
    const base = canonical(path.win32.normalize(candidate));
    if (ordinalWithin(file, base) || ordinalWithin(base, file)) throw new Error(landingFolderMessage);
  }
  return folder;
}

export function launchOptions(args) {
  const roots = [];
  let drive = 'C:';
  for (let i = 0; i < args.length; i += 2) {
    if (args[i] === '--allow-root' && roots.length < 8) roots.push(localPath(args[i + 1]));
    else if (args[i] === '--windows-drive' && /^[a-z]:$/i.test(args[i + 1] ?? '')) drive = args[i + 1].toUpperCase();
    else throw new Error('Use --allow-root with a full build folder path, or --windows-drive with a drive letter.');
  }
  roots.forEach(outputFolder);
  return { roots, systemDirectory: `${drive}\\Windows\\System32` };
}
