import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('shipped plugin contains no runtime compilation or native interop declarations', () => {
  const repo = fileURLToPath(new URL('../../', import.meta.url));
  function inspect(folder) {
    for (const item of readdirSync(folder, { withFileTypes: true })) {
      if (item.name === 'tests') continue;
      const file = path.join(folder, item.name);
      if (item.isDirectory()) { inspect(file); continue; }
      if (!/\.(?:ps1|mjs|cs)$/i.test(item.name)) continue;
      const source = readFileSync(file, 'utf8');
      assert.doesNotMatch(source, /DllImport|Reflection\.Emit|Assembly\]::Load\s*\(/i, file);
      for (const line of source.split(/\r?\n/)) {
        if (/\bAdd-Type\b/i.test(line)) assert.match(line, /^\s*Add-Type\s+-AssemblyName\s+[\w., ]+\s*$/i, file);
      }
    }
  }
  inspect(path.join(repo, 'mcp')); inspect(path.join(repo, 'scripts'));
});
