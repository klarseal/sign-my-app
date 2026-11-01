import { readFileSync } from 'node:fs';
import { launchOptions } from './safety.mjs';
import { startServer } from './server.mjs';

try {
  // Installation configuration limits paths; it never creates signing trust.
  const roots = JSON.parse(readFileSync(new URL('./output-roots.json', import.meta.url), 'utf8').replace(/^\uFEFF/u, ''));
  if (!Array.isArray(roots) || roots.length > 8 || roots.some(root => typeof root !== 'string')) throw new Error();
  startServer({ options: launchOptions(roots.flatMap(root => ['--allow-root', root])) });
} catch { process.stderr.write('Choose the build output folder during plugin setup. No signing is allowed until setup completes.\n'); process.exitCode = 1; }
