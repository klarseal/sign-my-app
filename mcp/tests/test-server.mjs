// Isolate protocol refusals from per-user production audit/trust storage.
import { startServer } from '../server.mjs';
import { launchOptions } from '../safety.mjs';
try { startServer({ options: launchOptions(process.argv.slice(2)), audit: () => {} }); }
catch { process.exitCode = 1; }
