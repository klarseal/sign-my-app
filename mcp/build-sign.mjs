import { launchOptions } from './safety.mjs';
import { validateArguments } from './tools.mjs';
import { createSigning, unsafeClient } from './signing.mjs';
import { userState } from './trust.mjs';
import { runHelper } from './runner.mjs';

try {
  if (unsafeClient()) throw new Error('Use an interactive release session with human approval enabled.');
  const options = launchOptions(process.argv.slice(2));
  let input = '';
  for await (const chunk of process.stdin) { input += chunk; if (input.length > 65536) throw new Error('Recipe input limit.'); }
  const request = JSON.parse(input.trim().replace(/^\uFEFF/u, ''));
  if (request.name !== 'sign_files' || Object.keys(request).some(k => !['name', 'arguments'].includes(k))) throw new Error('Invalid recipe.');
  const args = validateArguments('sign_files', request.arguments, options.roots);
  const state = userState(options);
  const signing = createSigning({ helper: runHelper, options, trust: state, audit: state.audit });
  const ticket = await signing.begin(args);
  const result = ticket.result ?? await ticket.finish({ window: true });
  for (const line of result.output) process.stdout.write((typeof line === 'string' ? line : JSON.stringify(line)) + '\n');
  process.exitCode = result.failed ? 1 : 0;
} catch {
  process.stderr.write('Signing could not complete. Please sign in to your signing app, then tell me. Keep credentials private; inspect the files before retrying.\n');
  process.exitCode = 1;
}
