# Closed certificate sessions

There is no silent key preflight. Only an approved `sign` process with a nonzero
exit status is classified by its output. A successful process and `verify`
failures never use this classifier. The inference is that key access is currently
unavailable, not proof of SimplySign's login state. Other providers can return the
same codes; broken provider installation can also require setup repair if login
does not resolve it. A real SimplySign session expiry has not been observed yet.

The MCP returns `sessionRequired: true`, with the fixed message:

> The certificate session looks closed. Please log in to SimplySign Desktop, then ask to sign again.

The agent must hand login back to the person, preserve their selection, and wait
for a new signing request. No automatic retry, credential entry or observation of
login. This is separate from declining approval and does not impose the decline
cooldown or remove Always trust. An unchanged Sign once plan can resume for ten
minutes in the same server lifetime. Always survives a server restart; changing
its exact scope, publisher/store or timestamp service requires fresh approval.
Saved trust permits an attempt; it does not open or attest to a certificate
session. Signing still requires the provider to supply the key.

Each SignTool signing process has a **60-second** wait limit, including provider
UI and timestamping. At the deadline the operation terminates its own process tree
using Windows' System32 `taskkill.exe`, with bounded cleanup waits (up to five
seconds for taskkill and five seconds for the process). It never closes or kills
the independently running SimplySign app. A signing timeout returns the same
message because the provider's UI state cannot be inspected without native
interop. Slow timestamping can therefore also produce this result. Verification
has a separate 45-second limit; output draining is bounded too. These are limits
on each process, not promises about total preview/approval/verification duration.

Failed signing only modifies a private snapshot. It is discarded before the
session result returns; the current original remains unchanged. Earlier completed
files in a batch stay signed and are excluded from the remaining-file recovery
request. The audit records `certificate session required: <reason>` with the
approved file hash and approval path. Provider output is not echoed for these
recognized cases. The MCP result remains unsuccessful (`isError: true`); it never
claims signing succeeded, and adds no generic verification/refusal warning.

## Exact HRESULT allowlist

Matching is case insensitive, with word boundaries around the full `0x` plus
eight hexadecimal digits. Code names follow
[Microsoft's Winerror.h reference](https://learn.microsoft.com/en-us/windows/win32/com/com-error-codes-4).

| Code | Name |
| --- | --- |
| `0x8009000D` | `NTE_NO_KEY` |
| `0x80090013` | `NTE_BAD_PROVIDER` |
| `0x80090016` | `NTE_BAD_KEYSET` |
| `0x80090017` | `NTE_PROV_TYPE_NOT_DEF` |
| `0x80090019` | `NTE_KEYSET_NOT_DEF` |
| `0x8009001D` | `NTE_PROVIDER_DLL_FAIL` |
| `0x8009001E` | `NTE_PROV_DLL_NOT_FOUND` |
| `0x80090022` | `NTE_SILENT_CONTEXT` |
| `0x8009002E` | `NTE_UI_REQUIRED` |
| `0x80090030` | `NTE_DEVICE_NOT_READY` |
| `0x8010000C` | `SCARD_E_NO_SMARTCARD` |
| `0x80100017` | `SCARD_E_READER_UNAVAILABLE` |
| `0x8010001D` | `SCARD_E_NO_SERVICE` |
| `0x8010001E` | `SCARD_E_SERVICE_STOPPED` |
| `0x8010002E` | `SCARD_E_NO_READERS_AVAILABLE` |
| `0x80100030` | `SCARD_E_NO_KEY_CONTAINER` |
| `0x80100069` | `SCARD_W_REMOVED_CARD` |
| `0x8010006E` | `SCARD_W_CANCELLED_BY_USER` |
| `0x8010006F` | `SCARD_W_CARD_NOT_AUTHENTICATED` |

Provider cancellation (`0x8010006E`) means the approved signing operation could
not obtain key access; it is not interpreted as declining the MCP approval.

## Exact English text alternatives

These are case-insensitive literal substrings; no localization is inferred.
The literals below are the implementation's diagnostic matching contract:

```text
Keyset does not exist
The keyset is not defined
Key does not exist
Invalid provider specified
Provider type not defined
Provider DLL failed to initialize correctly
Provider DLL could not be found
No smart card inserted
The smart card has been removed
The requested key container does not exist on the smart card
No smart card readers are available
The device that is required by this cryptographic provider is not ready for use
This operation requires input from the user
Provider could not perform the action since the context was acquired as silent
The user has not authenticated to the smart card
```

Two additional case-insensitive regular expressions cover token/session text:

```regex
\btoken (?:is )?(?:not present|not logged in|expired)\b
\bsession (?:has )?expired\b
```

The returned/audited reason is the matched code, literal substring, or fixed
`token/session unavailable`. Timeouts use `provider-wait-timeout` or
`provider-output-timeout`. Unrecognized failures, timestamp failures without a
matching diagnostic, missing certificate selection, bad signatures and untrusted
roots remain ordinary signing/verification failures. Nothing retries itself.
