import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { display, timestampUrl, landingFolders as windowsLandingFolders, projectTrustFolder } from './safety.mjs';
import { scopesFor } from './trust.mjs';

export const APPROVAL_MS = 300000;
export const AUTO_DECLINE_MS = 1500;
export const timeoutOutput = "The Sign window got no answer, so nothing was signed. Ask me to try again when you're ready.";
const unavailableOutput = ["I couldn't show you the approval here.",
  'Tell the person that approval could not be shown. Ask them to open an interactive Windows desktop and request signing again there. Do not retry automatically.'];
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
export function approvalForm(plans, { native = false } = {}) {
  // Keep ordinary backslashes readable, but distinguish literal escape notation
  // from escaped invisible characters. Never trim away hostile edge characters.
  const text = value => display(String(value).replace(/\\(?=u\{)/g, '\\u{5C}'))
    .replace(/ {2,}|^ | $/g, spaces => `\\u{20}x${spaces.length}`);
  const message = plans.map((p, i) => [
      `File ${i + 1} of ${plans.length}: ${text(p.File)}`,
      `Publisher: ${text(p.Publisher)}`, `SHA-256: ${p.SHA256}`, `Thumbprint: ${p.Thumbprint}`,
      `Store: ${p.MachineStore === true ? 'LocalMachine' : 'CurrentUser'}`,
      ...(p.TrustFolder ? [`Output folder: ${text(p.TrustFolder)}`] : []),
      `Timestamp service: ${timestampUrl(p.TimestampUrl)}`
    ].join('\n')).join('\n\n') + '\n\n' +
    `Sign ${plans.length} ${plans.length === 1 ? 'file' : 'files'}? Signing changes the files and contacts the timestamp service. Only you can approve.\n` +
    (native ? 'Scroll through all details. Signing stays off until every line has been displayed.\n' :
      'Review every file, scrolling if needed. This chat cannot check which details you have seen.\n') +
    'Always for this project lets an agent sign files in these output folders under your name without asking while your certificate session is open. Use it only for projects you trust. Say "forget project trust" to undo it.\n' +
    'Allowing the tool is separate from approving these files.';
  return { mode: 'form', message, requestedSchema: { type: 'object', properties: {
    decision: { type: 'string', title: 'Sign my app', enum: ['Cancel', 'Sign once', 'Always for this project'], default: 'Cancel' }
  }, required: ['decision'] } };
}
export const accepted = answer => answer?.action === 'accept' && ['Sign once', 'Always for this project'].includes(answer.content?.decision) &&
  Object.keys(answer.content).length === 1 && Object.keys(answer).every(k => ['action', 'content', '_meta'].includes(k));

// Client identity/capabilities do not attest to human presence. These signals can
// only make us refuse; no environment setting can grant approval.
export function unsafeClient(env = process.env, meta = {}) {
  return ['KLARSEAL_AUTO_APPROVE', 'MCP_AUTO_APPROVE', 'CI'].some(k => env[k] && !['0','false'].includes(env[k])) ||
    meta.permissionMode === 'bypassPermissions' || meta.approval_policy === 'never';
}

export function createSigning({ helper, options, audit, trust, now = Date.now, elapsedNow = () => performance.now(), timeout = APPROVAL_MS, landingFolders = windowsLandingFolders }) {
  let busy = false, declines = 0, blockedUntil = 0;
  let recovery;
  let activeController;
  const recoveryIdentity = (plans, scopes) => JSON.stringify({ scopes, plans: plans.map(p => [p.File, p.SHA256, p.PlanHash]) });
  const record = (args, plans, path, outcome, contentComparison, window) => {
    for (const file of args.files.length ? args.files : ['unavailable']) {
      const p = plans?.find(p => p.File === file);
      let hash = p?.SHA256;
      if (!hash) { try { hash = createHash('sha256').update(readFileSync(file)).digest('hex').toUpperCase(); } catch { hash = 'unavailable'; } }
      audit({ time: new Date(now()).toISOString(), file: display(file), hash, publisher: display(p?.Publisher ?? 'unavailable'), thumbprint: args.thumbprint,
        machineStore: args.machine_store === true, timestamp: args.timestamp_url ?? 'http://time.certum.pl', approvalPath: path, outcome,
        ...(contentComparison ? { contentComparison: `content-comparison: ${contentComparison}` } : {}), ...(window ? { window } : {}) });
    }
  };
  return {
    refuse(args, reason = 'invalid request') { record(args, [], 'none', reason); },
    forget(args) {
      activeController?.abort();
      recovery = undefined;
      const count = trust.forget(args.project_folder, args.thumbprint);
      audit({ time: new Date(now()).toISOString(), approvalPath: 'revocation', outcome: count < 0 ? 'unreadable trust cleared' : count ? 'trust removed' : 'no matching trust removed', count });
      return { failed: count === 0, output: [count < 0 ? 'Cleared unreadable saved project trust. Future signing asks again.' : count
        ? `Removed ${count} project trust record(s). Future signing in the removed scopes asks again; other project or publisher trust is unchanged.`
        : 'No matching project trust records were removed. Saved trust is unchanged.'] };
    },
    async begin(args, signal) {
      const reason = now() < blockedUntil ? 'Stop signing requests and ask the person in words. The person declined or cancelled signing. Do not retry automatically.' : undefined;
      if (reason) { record(args, [], 'none', reason); throw Object.assign(new Error(reason), { code: -32000 }); }
      if (busy) { record(args, [], 'none', 'another signing operation is active'); throw new Error('Another signing operation is active.'); }
      if (declines >= 3) declines = 0; // Three declines end the prompt burst, never the server lifetime.
      busy = true;
      const parentSignal = signal;
      const operation = new AbortController();
      activeController = operation;
      const cancelOperation = () => operation.abort();
      parentSignal?.addEventListener('abort', cancelOperation, { once: true });
      if (parentSignal?.aborted) operation.abort();
      signal = operation.signal;
      const ready = deferred(), answer = deferred();
      let plans, scopes, recoveryKey, expires, timer, consumed = false, approvalPath = 'none', logged = new Set();
      let approved = false, declined = false, unavailable = false, timedOut = false, signingAttempted = false, windowOutcome, windowRemaining, windowClick, presentedAt, trustIssue, trustRefusal;
      const requireTrustFolder = () => {
        if (trustIssue) { trustRefusal = trustIssue.message; throw trustIssue; }
      };
      const decline = () => {
        if (!declined) { declined = true; declines = Math.min(3, declines + 1); blockedUntil = now() + 60000; recovery = undefined; }
      };
      const abort = () => answer.resolve({ action: 'cancel' });
      signal?.addEventListener('abort', abort, { once: true });
      const task = (async () => {
        try {
          const result = await helper({ name: 'sign_files', arguments: args }, options, signal, {
            async approval(value) {
              if (plans || !Array.isArray(value) || value.length !== args.files.length || value.some((p, i) => p.File !== args.files[i] || !/^[A-F0-9]{64}$/i.test(p.SHA256) || p.Thumbprint.toUpperCase() !== args.thumbprint.toUpperCase() || (p.MachineStore === true) !== (args.machine_store === true) || p.TimestampUrl !== (args.timestamp_url ?? 'http://time.certum.pl'))) throw new Error('Invalid plan.');
              plans = value; expires = now() + timeout; approvalPath = 'elicitation';
              scopes = options?.roots ? scopesFor(plans, args, options.roots) : [];
              for (const p of plans) p.TrustFolder = options?.roots ? scopesFor([p], args, options.roots)[0]?.folder : undefined;
              if (scopes.length) {
                try {
                  const folders = landingFolders(options?.systemDirectory);
                  for (const scope of scopes) projectTrustFolder(scope.folder, folders);
                } catch (error) { trustIssue = error; }
              }
              recoveryKey = recoveryIdentity(plans, scopes);
              const savedTrust = !trustIssue && trust?.has(scopes);
              const paused = savedTrust && trust.paused(scopes);
              if (!paused && (savedTrust || recovery?.key === recoveryKey && recovery.expires > now())) {
                approvalPath = savedTrust ? 'project-trust' : 'session-recovery';
                approved = true;
                record(args, plans, approvalPath, 'approved signing attempt');
                return { path: 'elicitation', sign: 'Sign', remaining: timeout };
              }
              recovery = undefined; // An explicit new approval starts a new recovery window.
              timer = setTimeout(() => { if (approvalPath !== 'window') { timedOut = true; answer.resolve({ timedOut: true }); } }, timeout);
              presentedAt = elapsedNow();
              ready.resolve(true);
              const reply = await answer.promise;
              if (signal?.aborted) { decline(); return { path: 'elicitation', sign: 'Cancel', remaining: 0 }; }
              if (reply?.timedOut || now() >= expires) { timedOut = true; return { path: 'elicitation', sign: 'Cancel', remaining: 0, timedOut: true }; }
              if (reply?.window === true) { approvalPath = 'window'; windowRemaining = Math.max(0, expires - now()); record(args, plans, approvalPath, 'native approval requested'); return { path: 'window', message: approvalForm(plans, { native: true }).message, remaining: windowRemaining }; }
              approvalPath = 'elicitation';
              const sign = accepted(reply) ? 'Sign' : 'Cancel';
              if (sign === 'Sign' && reply.content.decision === 'Always for this project') requireTrustFolder();
              if (sign === 'Sign') { approved = true; trust?.resume(scopes); } else decline();
              // A writable audit log is required before allowing any mutation.
              record(args, plans, approvalPath, sign === 'Sign' ? 'approved signing attempt' : 'refused');
              if (sign === 'Sign' && !signal.aborted && reply.content.decision === 'Always for this project') {
                if (!trust || !scopes.length) throw new Error('Private trust storage unavailable.');
                trust.remember(scopes);
                record(args, plans, approvalPath, 'project trust created by person answer');
              }
              return { path: 'elicitation', sign, remaining: Math.max(0, expires - now()) };
            },
            windowEvent(event) {
              if (!plans || approvalPath !== 'window' || approved) throw new Error('Unexpected window event.');
              if (event.event === 'window_state') {
                const { visible, active, minimized, bounds, monitor, onScreen, topMost, taskbar, stage } = event;
                if ([visible, active, minimized, onScreen, topMost, taskbar].some(v => typeof v !== 'boolean') ||
                    !bounds || ['x', 'y', 'width', 'height'].some(k => !Number.isInteger(bounds[k])) ||
                    typeof monitor !== 'string' || monitor.length > 256 || !['shown', 'after 1 s', 'after 5 s', 'restored on screen'].includes(stage)) throw new Error('Invalid window state.');
                record(args, plans, approvalPath, stage === 'shown' ? 'window shown' : stage === 'restored on screen' ? 'window restored on screen' : `window state ${stage}`, undefined,
                  { visible, active, minimized, bounds: { x: bounds.x, y: bounds.y, width: bounds.width, height: bounds.height }, monitor: display(monitor), onScreen, topMost, taskbar });
              } else if (event.event === 'window_result' && ['click', 'cancel', 'close', 'timeout'].includes(event.source)) {
                if (windowOutcome) throw new Error('Repeated window outcome.');
                if (event.source === 'click') {
                  // Only the installed form, over the private helper pipe, can
                  // attest to a click. Public answers cannot supply this proof.
                  if (!Number.isInteger(event.elapsedMilliseconds) || event.elapsedMilliseconds < 2000 ||
                      event.elapsedMilliseconds >= windowRemaining || event.remainingMilliseconds !== windowRemaining ||
                      !['Sign once', 'Always for this project'].includes(event.decision)) throw new Error('Invalid native click.');
                  windowClick = event.decision;
                }
                windowOutcome = event.source;
                timedOut = event.source === 'timeout';
                record(args, plans, approvalPath, timedOut ? 'window timed out, no answer' : `window ${event.source === 'click' ? 'answer by click' : event.source === 'cancel' ? 'Cancel' : 'closed'}`);
              } else throw new Error('Invalid window outcome.');
            },
            windowApproved(decision = 'Sign once') {
              const clickedInTime = windowOutcome === 'click' && windowClick === decision;
              if (plans && approvalPath === 'window' && !approved && !clickedInTime && now() >= expires) timedOut = true;
              if (!plans || approvalPath !== 'window' || approved || timedOut || signal.aborted ||
                  (!clickedInTime && now() >= expires) || (windowClick && windowClick !== decision) ||
                  !['Sign once', 'Always for this project'].includes(decision)) throw new Error('Invalid native decision.');
              if (decision === 'Always for this project') requireTrustFolder();
              approved = true; record(args, plans, approvalPath, 'approved signing attempt');
              trust?.resume(scopes);
              if (decision === 'Always for this project') {
                if (!trust || !scopes.length) throw new Error('Private trust storage unavailable.');
                trust.remember(scopes); record(args, plans, approvalPath, 'project trust created by person answer');
              }
            },
            signingStarted() {
              if (!approved || signal.aborted) throw new Error('Unexpected signing step.');
              signingAttempted = true;
            },
            signed(p, comparison) { signingAttempted = true; record({ ...args, files: [p.File] }, plans, approvalPath, 'signed; verification pending', comparison); logged.add(p.File); }
          });
          timedOut = !approved && (timedOut || result.approvalTimedOut === true);
          if (timedOut) {
            if (windowOutcome !== 'timeout') record(args, plans, approvalPath, approvalPath === 'window' ? 'window timed out, no answer' : 'approval timed out, no answer');
            return { failed: true, approvalTimedOut: true, signingAttempted: false, output: [timeoutOutput] };
          }
          unavailable = result.approvalUnavailable === true && !approved;
          if (unavailable) result.output = [...unavailableOutput];
          if (plans && !approved && !trustRefusal && !unavailable) decline();
          record(args, plans, approvalPath, result.sessionRequired ? `certificate session required: ${display(result.sessionReason ?? 'key unavailable')}` : unavailable ? 'approval unavailable' : result.failed ? 'refused or verification failed; inspect before retrying' : 'signed and verified');
          if (declined) result.output.push('Stop signing requests and ask the person in words. Do not retry automatically.');
          if (result.sessionRequired && approved) {
            const pending = plans.filter(p => !logged.has(p.File));
            const pendingArgs = { ...args, files: pending.map(p => p.File) };
            const pendingScopes = scopesFor(pending, pendingArgs, options.roots);
            const key = recoveryIdentity(pending, pendingScopes);
            recovery = { key, expires: recovery?.key === key ? recovery.expires : now() + 600000 };
            if (trust?.has(scopes)) {
              trust.pause(scopes);
              result.output.push('The next signing request will show approval once. Always for this project stays saved.');
            }
            result.output.push({ ResumeAfterManualLogin: pendingArgs, Message: 'The certificate session looks closed. Log in to SimplySign Desktop privately, then ask to sign again with these remaining files.' });
          }
          if (!result.failed) { declines = 0; recovery = undefined; }
          return result;
        } catch {
          if (timedOut && !approved) {
            if (windowOutcome !== 'timeout') record(args, plans, approvalPath, approvalPath === 'window' ? 'window timed out, no answer' : 'approval timed out, no answer');
            return { failed: true, approvalTimedOut: true, signingAttempted: false, output: [timeoutOutput] };
          }
          unavailable = approvalPath === 'window' && !approved && !trustRefusal;
          record(args, plans, approvalPath, unavailable ? 'approval unavailable' : logged.size ? 'incomplete; inspect signed files before retrying' : 'refused');
          return { failed: true, signingAttempted, output: unavailable ? [...unavailableOutput] : [trustRefusal ?? (signingAttempted ? 'Signing could not complete. Please sign in to your signing app, then tell me. Inspect the files before retrying; a signature may exist without a timestamp.' : 'Signing could not complete. Nothing was signed. Ask to try again when ready.')] };
        } finally {
          if (plans && !approved && !trustRefusal && !unavailable && !timedOut) decline();
          clearTimeout(timer); busy = false; ready.resolve(false);
          activeController = undefined;
          parentSignal?.removeEventListener('abort', cancelOperation);
          signal?.removeEventListener('abort', abort);
        }
      })();
      if (!await ready.promise) return { result: await task };
      return { plans, expires, task,
        async finish(reply) {
          if (consumed) { record(args, plans, approvalPath, 'repeated approval refused'); return { failed: true, output: ['Approval already consumed.'] }; }
          consumed = true;
          if (now() < expires && !signal.aborted && reply?.window !== true && !accepted(reply)) {
            const elapsed = Math.max(0, elapsedNow() - presentedAt);
            const negative = reply && Object.keys(reply).every(k => ['action', 'content', '_meta'].includes(k)) &&
              (['decline', 'cancel'].includes(reply.action) && reply.content === undefined ||
               reply.action === 'accept' && reply.content?.decision === 'Cancel' && Object.keys(reply.content).length === 1);
            if (!negative || elapsed < AUTO_DECLINE_MS) {
              record(args, plans, negative ? 'elicitation-auto-declined' : 'elicitation-unavailable',
                `client could not show approval; response after ${elapsed} ms; falling back to window`);
              reply = { window: true };
            }
          }
          answer.resolve(now() < expires ? reply : { action: 'cancel' });
          return task;
        }
      };
    }
  };
}
