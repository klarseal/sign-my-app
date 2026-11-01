import { fileURLToPath } from 'node:url';
import { recipeValue, timestampUrl } from './safety.mjs';

// A recipe enters the same approval, trust, snapshot, SignTool and timestamp
// verification operation. It never embeds a second direct signing implementation.
export function buildRecipe(args, roots, systemDirectory = 'C:\\Windows\\System32') {
  const check = value => {
    if (typeof value === 'string') recipeValue(value);
    else if (Array.isArray(value)) value.forEach(check);
    else if (value && typeof value === 'object') Object.entries(value).forEach(([k, v]) => { recipeValue(k); check(v); });
  };
  check(args); roots.forEach(recipeValue); recipeValue(systemDirectory);
  if (args.timestamp_url) timestampUrl(args.timestamp_url);
  const request = JSON.stringify({ name: 'sign_files', arguments: args });
  // Every interpolated value is decoded as data. Only base64's ASCII alphabet
  // enters PowerShell literals, including executable and installed helper paths.
  const data = value => "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Buffer.from(value, 'utf8').toString('base64') + "')))";
  const quote = value => data(recipeValue(value));
  const entry = fileURLToPath(new URL('./build-sign.mjs', import.meta.url));
  const drive = systemDirectory.slice(0, 2);
  return '#Requires -Version 5.1\r\n$ErrorActionPreference = \'Stop\'\r\n$OutputEncoding = New-Object Text.UTF8Encoding($false)\r\n' +
    '# From the folder containing sign.ps1, run in PowerShell:\r\n' +
    '# & ([IO.Path]::Combine([Environment]::SystemDirectory, \'WindowsPowerShell\\v1.0\\powershell.exe\')) -NoProfile -ExecutionPolicy Bypass -File ".\\sign.ps1"\r\n' +
    '# Bypass applies only to this process; no saved execution policy is changed.\r\n' +
    '# Keep your signing app session open. Sign payload, build installer, then sign installer.\r\n' +
    '# This uses the same policy and calls Microsoft SignTool, then verifies the timestamp.\r\n' +
    `${data(request)} | & ${quote(process.execPath)} ${quote(entry)} ${roots.map(r => '--allow-root ' + quote(r)).join(' ')}${drive === 'C:' ? '' : ' --windows-drive ' + quote(drive)}\r\n` +
    "if ($LASTEXITCODE -ne 0) { throw 'Signing did not complete. Please sign in to your signing app, then tell me. Review the result before retrying.' }\r\n";
}
