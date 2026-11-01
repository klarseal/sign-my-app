import test from 'node:test';
import { withDesktopLock, testOnlySource } from './desktop-lock.mjs';
const desktopTest = (name, options, fn) => test(name, options, t => withDesktopLock(() => fn(t)));
import assert from 'node:assert/strict';
import { mkdtempSync, cpSync, writeFileSync, readFileSync, rmSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { approvalForm, createSigning, timeoutOutput } from '../signing.mjs';
import { helperResult } from '../tools.mjs';
import { Client, textOf } from './client.mjs';

export const longPlan = { File: 'C:\\build\\' + 'long-release-directory\\'.repeat(40) + 'Example-app.exe', SHA256: 'A'.repeat(64), Publisher: 'CN=Disposable Test Publisher', Thumbprint: '1'.repeat(40), TimestampUrl: 'http://time.certum.pl' };
for (const {scale, count, small} of [{scale:1,count:1}, {scale:1,count:8}, {scale:1.5,count:1}, {scale:1.5,count:8}, {scale:1.5,count:8,small:true}]) desktopTest(`R1/R2: real hidden-runner window at ${scale * 100}%, ${count} files${small ? ', small working area' : ''}, requires all wrapped lines to be viewed`, { skip: process.platform !== 'win32' }, async t => {
  const root = mkdtempSync(fileURLToPath(new URL('../../.test-window-', import.meta.url)));
  t.after(() => { assert.match(path.basename(root), /^\.test-window-/); rmSync(root, { recursive: true, force: true }); });
  cpSync(new URL('../runner.mjs', import.meta.url), path.join(root, 'runner.mjs'));
  cpSync(new URL('../approval-host.ps1', import.meta.url), path.join(root, 'approval-host.ps1'));
  const probe = fileURLToPath(new URL('./Approval-Probe.ps1', import.meta.url));
  writeFileSync(path.join(root, 'bridge.ps1'), `. '${probe.replaceAll("'", "''")}'\n$r = Invoke-ApprovalProbe ([Console]::In.ReadLine() | ConvertFrom-Json)\n[Console]::Out.WriteLine(($r | ConvertTo-Json -Depth 8 -Compress))`);
  // Model a desktop-app server: Node itself has no console and piped stdio.
  const script = `import { runHelper } from ${JSON.stringify(pathToFileURL(path.join(root, 'runner.mjs')).href)};
    console.log(JSON.stringify(await runHelper(JSON.parse(process.argv[1]), {systemDirectory:'C:\\\\Windows\\\\System32'})));`;
  const source = process.env.KLARSEAL_TEST_WINDOW_SOURCE ?? fileURLToPath(new URL('../approval-window.ps1', import.meta.url));
  const plans = count === 1 ? [longPlan] : Array.from({ length: count }, (_, i) => ({ ...longPlan, File: `C:\\build\\app-${i + 1}.exe` }));
  const evidenceFolder = fileURLToPath(new URL('../../test-output/', import.meta.url));
  mkdirSync(evidenceFolder, { recursive: true });
  const report = path.join(evidenceFolder, `approval-cancel-${scale}-${count}${small ? '-small' : ''}.json`);
  const { stdout } = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', script,
    JSON.stringify({ name: 'sign_files', source, message: approvalForm(plans, { native: true }).message, scale, small, hold: 25000, review: true, report })],
    { windowsHide: true, timeout: 40000 });
  const result = JSON.parse(stdout.trim());
  const evidence = result.output[0];
  assert.equal(evidence.visible, true, JSON.stringify(evidence));
  assert.equal(evidence.topMost, true, JSON.stringify(evidence));
  assert.equal(evidence.stdioRedirected, true);
  assert.equal(evidence.wrap, true);
  assert.equal(evidence.crlf, true);
  assert.equal(evidence.onScreen, true);
  assert.equal(evidence.buttonsVisible, true);
  assert.equal(evidence.approved, false);
  assert.equal(evidence.cancelClicked, true);
  assert.equal(existsSync(report.replace(/\.json$/, '.png')), true);
  t.diagnostic(`Visible topmost window captured from desktop pixels: ${report.replace(/\.json$/, '.png')}; Cancel clicked; no console.`);
  assert.match(evidence.text, new RegExp(`${count} file`));
  const { top, bottom, finished } = evidence.review;
  assert.equal(top.enabled, evidence.allTextVisible, JSON.stringify(evidence));
  if (count === 8) {
    assert.equal(top.enabled, false);
    assert.ok(bottom.seen < bottom.total, JSON.stringify(evidence));
    assert.equal(bottom.enabled, false, 'jumping to the end must not skip unseen files in the middle');
  }
  assert.equal(finished.seen, finished.total, JSON.stringify(evidence));
  assert.equal(finished.enabled, true, JSON.stringify(evidence));
});

for (const available of [true, false]) desktopTest(`desktop-like server: instant elicitation decline -> ${available ? 'visible window Cancel' : 'unavailable desktop'}`, { skip: process.platform !== 'win32' }, async t => {
  const root = mkdtempSync(fileURLToPath(new URL('../../.test-fallback-', import.meta.url)));
  let client;
  t.after(async () => {
    await client?.close();
    assert.equal(path.dirname(root), fileURLToPath(new URL('../../', import.meta.url)).replace(/[\\/]$/, ''));
    assert.match(path.basename(root), /^\.test-fallback-/); rmSync(root, { recursive: true, force: true });
  });
  const install = path.join(root, 'mcp'), scripts = path.join(root, 'scripts'), build = path.join(root, 'build');
  for (const dir of [install, scripts, build]) mkdirSync(dir);
  for (const name of ['runner.mjs', 'approval-host.ps1', 'bridge.ps1', 'sign-operation.ps1']) cpSync(new URL(`../${name}`, import.meta.url), path.join(install, name));
  const file = path.join(build, 'synthetic.exe'); writeFileSync(file, 'synthetic non-executable payload; never signed');
  const original = readFileSync(file);
  const quote = s => "'" + s.replaceAll("'", "''") + "'";
  // These private stubs cannot look up certificates, obtain keys or invoke SignTool.
  writeFileSync(path.join(scripts, 'Signing-Safety.ps1'), '# Synthetic preview only. No signing functions.');
  writeFileSync(path.join(scripts, 'Invoke-Sign.ps1'), `param($FilePath,$Thumbprint,[switch]$PassThruPlan)
    [pscustomobject]@{File=$FilePath;SHA256=(Get-FileHash -LiteralPath $FilePath).Hash;Thumbprint=$Thumbprint;Publisher='CN=Synthetic Preview';TimestampUrl='http://time.certum.pl';PlanHash=('B'*64)}`);
  writeFileSync(path.join(scripts, 'Find-SignTool.ps1'), "throw 'TEST MUST NEVER REACH SIGNING'");
  const report = fileURLToPath(new URL('../../test-output/desktop-fallback-cancel.json', import.meta.url));
  mkdirSync(path.dirname(report), { recursive: true });
  writeFileSync(path.join(install, 'approval-window.ps1'), available ? `function Request-NativeSigningApproval($Message,$RemainingMilliseconds) {
    . ${quote(fileURLToPath(new URL('./Approval-Probe.ps1', import.meta.url)))}
    $r = Invoke-ApprovalProbe ([pscustomobject]@{source=${quote(fileURLToPath(new URL('../approval-window.ps1', import.meta.url)))};message=$Message;scale=1;hold=12000;review=$true;report=${quote(report)}})
    if ($r.output[0].approved) { throw 'Test must only Cancel' }
    return 'Cancel'
  }` : "function Request-NativeSigningApproval { throw 'Synthetic unavailable desktop' }");
  const auditFile = path.join(root, 'audit.jsonl');
  const server = path.join(root, 'server.mjs');
  writeFileSync(server, `import {startServer} from ${JSON.stringify(new URL('../server.mjs', import.meta.url).href)};
    import {runHelper} from ${JSON.stringify(pathToFileURL(path.join(install, 'runner.mjs')).href)};
    import {appendFileSync} from 'node:fs';
    startServer({helper:runHelper,options:{roots:[${JSON.stringify(build)}],systemDirectory:'C:\\\\Windows\\\\System32'},
      environment:{},audit:line=>appendFileSync(${JSON.stringify(auditFile)},JSON.stringify(line)+'\\n')});`);
  client = new Client({ server }); // windowsHide + private pipes, as in a desktop app.
  await client.request('initialize', { protocolVersion: '2025-11-25', capabilities: { elicitation: {} }, clientInfo: { name: 'synthetic-desktop', version: '1' } }, false);
  client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  const resultPromise = client.request('tools/call', { name: 'sign_files', arguments: { files: [file], thumbprint: '1'.repeat(40) } }, false);
  let request;
  for (let i = 0; i < 1000 && !request; i++) { request = client.messages.find(x => x.method === 'elicitation/create'); if (!request) await delay(10); }
  assert.ok(request, 'server must attempt elicitation first');
  client.send({ jsonrpc: '2.0', id: request.id, result: { action: 'decline' } });
  const result = await resultPromise;
  assert.equal(result.result.isError, true, textOf(result));
  assert.deepEqual(readFileSync(file), original);
  const audit = readFileSync(auditFile, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(audit.slice(0, 2).map(x => x.approvalPath), ['elicitation-auto-declined', 'window']);
  if (available) {
    const evidence = JSON.parse(readFileSync(report, 'utf8'));
    assert.equal(evidence.visible, true); assert.equal(evidence.topMost, true);
    assert.equal(evidence.stdioRedirected, true); assert.equal(evidence.cancelClicked, true); assert.equal(evidence.approved, false);
    assert.match(textOf(result), /Signing was declined or cancelled/);
    assert.match(textOf(result), /Stop signing requests/);
    t.diagnostic(`Real bridge fallback captured from desktop pixels: ${report.replace(/\.json$/, '.png')}; Cancel clicked; unchanged payload.`);
  } else {
    assert.match(textOf(result), /I couldn't show you the approval here/);
    assert.doesNotMatch(textOf(result), /declined|cancelled|sign in|Stop signing requests/i);
    assert.equal(audit.at(-1).outcome, 'approval unavailable');
  }
});

for (const outcome of ['timeout', 'cancel', 'close', 'offscreen', 'sign-late-close']) desktopTest(`real managed host/bridge records ${outcome} without signing`, { skip: process.platform !== 'win32' }, async t => {
  const repo = fileURLToPath(new URL('../../', import.meta.url)).replace(/[\\/]$/, '');
  const root = mkdtempSync(path.join(repo, '.test-outcome-'));
  t.after(() => { assert.equal(path.dirname(root), repo); assert.match(path.basename(root), /^\.test-outcome-/); rmSync(root, { recursive: true, force: true }); });
  const install = path.join(root, 'mcp'), scripts = path.join(root, 'scripts'), build = path.join(root, 'build');
  for (const folder of [install, scripts, build]) mkdirSync(folder);
  for (const name of ['runner.mjs', 'approval-host.ps1', 'bridge.ps1', 'sign-operation.ps1']) cpSync(new URL(`../${name}`, import.meta.url), path.join(install, name));
  // Synthetic preview never opens a certificate store or invokes a signing tool.
  writeFileSync(path.join(scripts, 'Signing-Safety.ps1'), '# synthetic preview only');
  writeFileSync(path.join(scripts, 'Invoke-Sign.ps1'), `param($FilePath,$Thumbprint,[switch]$PassThruPlan)
    [pscustomobject]@{File=$FilePath;SHA256=(Get-FileHash -LiteralPath $FilePath).Hash;Thumbprint=$Thumbprint;Publisher='CN=Synthetic outcome';TimestampUrl='http://time.certum.pl';PlanHash=('B'*64)}`);
  writeFileSync(path.join(scripts, 'Find-SignTool.ps1'), "throw 'MUST NEVER REACH SIGNING'");
  const consumed = path.join(root, 'consumed.txt');
  if (outcome === 'sign-late-close') {
    writeFileSync(path.join(scripts, 'Find-SignTool.ps1'), "return 'C:\\synthetic\\never-executed.exe'");
    writeFileSync(path.join(scripts, 'Signing-Safety.ps1'), `
function Assert-SigningApproval {}
function Invoke-ApprovedSigning {
    param($FilePath,$ExpectedSHA256,$ApprovePlan,$Thumbprint,$TimestampUrl,$MachineStore,$RequestApproval,$OnSigningStarted)
    $answer = & $RequestApproval $ApprovePlan
    if ($answer -cne ('SIGN ' + $ApprovePlan)) { throw 'Wrong plan answer' }
    [IO.File]::AppendAllText('${consumed.replaceAll("'", "''")}', 'consumed-once')
    throw 'TEST ONLY - stop after plan consumption; no signing implementation exists'
}`);
  }
  let source = testOnlySource(readFileSync(new URL('../approval-window.ps1', import.meta.url), 'utf8')).replace('function Request-NativeSigningApproval(', 'function Show-TestApproval(');
  if (outcome === 'offscreen') source = source.replace('$reviewed = $false', `if (-not $script:perturbed -and $watch.ElapsedMilliseconds -ge 400) {
    $script:perturbed = $true; $form.Location = New-Object Drawing.Point(-20000, -20000)
  }
  $reviewed = $false`);
  else if (outcome === 'sign-late-close') source = source.replace('$timer.Start()', `
    $lateDriver = New-Object Windows.Forms.Timer
    $lateDriver.Interval = 10
    $lateState = @{ clicked = $false }
    $lateDriver.Add_Tick({
        if (-not $lateState.clicked -and $watch.ElapsedMilliseconds -ge ($RemainingMilliseconds - 200)) {
            $lateState.clicked = $true; $form.Activate(); $sign.PerformClick()
        }
    }.GetNewClosure())
    $form.Add_FormClosing({ Start-Sleep -Milliseconds 350 })
    $form.Add_FormClosed({ $lateDriver.Stop(); $lateDriver.Dispose() }.GetNewClosure())
    $lateDriver.Start()
    $timer.Start()`);
  else if (outcome !== 'timeout') source = source.replace('$reviewed = $false', `if ($watch.ElapsedMilliseconds -ge 400) { ${outcome === 'cancel' ? '$cancel.PerformClick()' : '$form.Close()'}; return }
        $reviewed = $false`);
  source += `\nfunction Request-NativeSigningApproval($Message,$RemainingMilliseconds,$OnEvent) {
    ${outcome === 'sign-late-close' ? 'Show-TestApproval $Message $RemainingMilliseconds $OnEvent' : `if ($RemainingMilliseconds -lt 290000 -or $RemainingMilliseconds -gt 300000) { throw 'Wrong production wait' }
    Show-TestApproval $Message 2500 $OnEvent`}
  }`;
  writeFileSync(path.join(install, 'approval-window.ps1'), source);
  const file = path.join(build, 'synthetic.exe'); writeFileSync(file, 'synthetic payload, never executed or signed');
  const original = readFileSync(file), audit = [];
  const { runHelper } = await import(pathToFileURL(path.join(install, 'runner.mjs')).href);
  const flow = createSigning({ helper: runHelper, timeout: outcome === 'sign-late-close' ? 6000 : 300000, options: { roots: [build], systemDirectory: 'C:\\Windows\\System32' }, landingFolders: () => [], audit: event => audit.push(event) });
  const args = { files: [file], thumbprint: '1'.repeat(40) };
  const result = await (await flow.begin(args)).finish({ window: true });
  assert.equal(result.failed, true);
  assert.equal(result.signingAttempted, false);
  assert.deepEqual(readFileSync(file), original);
  const shown = audit.find(x => x.outcome === 'window shown');
  assert.ok(shown, JSON.stringify(audit));
  assert.equal(shown.window.visible, true); assert.equal(shown.window.topMost, true); assert.equal(shown.window.taskbar, true); assert.equal(shown.window.minimized, false);
  assert.ok(shown.window.bounds.width > 0 && shown.window.bounds.height > 0); assert.ok(shown.window.monitor);
  const expected = { timeout: 'window timed out, no answer', offscreen: 'window timed out, no answer', cancel: 'window Cancel', close: 'window closed', 'sign-late-close': 'window answer by click' }[outcome];
  assert.equal(audit.filter(x => x.outcome === expected).length, 1, JSON.stringify(audit));
  const text = helperResult('sign_files', result).content.map(x => x.text).join('\n');
  assert.doesNotMatch(text, /signature may exist|SimplySign has expired/);
  if (outcome === 'sign-late-close') {
    assert.equal(readFileSync(consumed, 'utf8'), 'consumed-once');
    assert.ok(audit.some(x => x.outcome === 'approved signing attempt'), JSON.stringify(audit));
    assert.doesNotMatch(JSON.stringify(audit), /window timed out/);
    return;
  }
  if (['timeout', 'offscreen'].includes(outcome)) {
    assert.deepEqual(result.output, [timeoutOutput]);
    assert.doesNotMatch(JSON.stringify(audit), /refused or verification failed/);
    if (outcome === 'offscreen') {
      assert.ok(audit.some(x => x.outcome === 'window restored on screen' && x.window.onScreen));
      assert.ok(audit.some(x => x.outcome === 'window state after 1 s' && x.window.onScreen));
    }
    // Same server accepts the next explicit request immediately after timeout.
    await (await flow.begin(args)).finish({ window: true });
  } else await assert.rejects(flow.begin(args), /Stop signing requests/);
});

for (const scenario of [
  { decision: 'Sign once', nativeInput: true }, { decision: 'Always for this project', nativeInput: true },
  { decision: 'Sign once', small: true },
  { decision: 'Sign once', background: true, nativeInput: true },
  { decision: 'Sign once', at: 2800, limit: 3000, slowClose: true, nativeInput: true },
  { decision: 'Sign once', limit: 3000, sameTick: true },
  { decision: 'Timeout', at: 3500, limit: 3000 },
]) desktopTest(`production decision handler: ${JSON.stringify(scenario)}`, { skip: process.platform !== 'win32' }, async () => {
  const ps = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
  const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', fileURLToPath(new URL('./Decision-Probe.ps1', import.meta.url)),
    '-Source', fileURLToPath(new URL('../approval-window.ps1', import.meta.url)),
    '-Decision', scenario.decision, '-At', String(scenario.at ?? 3000), '-Limit', String(scenario.limit ?? 6000)];
  for (const [key, flag] of [['small', '-Small'], ['background', '-Background'], ['nativeInput', '-NativeInput'], ['slowClose', '-SlowClose'], ['sameTick', '-SameTick']]) if (scenario[key]) args.push(flag);
  const { stdout } = await promisify(execFile)(ps, args, { windowsHide: true, timeout: 15000 });
  const result = JSON.parse(stdout.trim());
  assert.equal(result.decision, scenario.decision, stdout);
  assert.equal(result.samples.find(x => x.stage === 'early').enabled, false, stdout);
  const ready = result.samples.find(x => x.stage === 'ready');
  for (const key of ['enabled', 'visible', 'topmost', 'taskbar', 'onScreen', 'buttonsVisible']) assert.equal(ready[key], true, stdout);
  if (scenario.small) { assert.ok(ready.width <= 800 && ready.height <= 450, stdout); assert.ok(ready.textHeight < 450, stdout); }
  if (scenario.background) {
    assert.equal(ready.active, false, stdout);
    assert.equal(ready.typedInTarget, true, stdout);
    assert.equal(ready.approvalUnchanged, true, stdout);
  }
  if (scenario.decision !== 'Timeout') {
    assert.ok(result.clickedAt >= 2000 && result.clickedAt < (scenario.limit ?? 6000), stdout);
    assert.equal(result.events.at(-1).source, 'click', stdout);
    assert.equal(result.events.at(-1).elapsedMilliseconds, result.clickedAt, stdout);
    assert.equal(result.events.at(-1).remainingMilliseconds, scenario.limit ?? 6000, stdout);
    assert.equal(result.events.at(-1).decision, scenario.decision, stdout);
  }
  if (scenario.slowClose || scenario.sameTick) assert.ok(result.elapsed >= scenario.limit, stdout);
});
