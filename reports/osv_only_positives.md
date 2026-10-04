# OSV-only positives: annotation material for D4

The 21 packages whose OSV text is regex-positive and whose GHSA text is regex-negative in the frozen snapshot (research_log.md 5.9; decision recorded in 5.9 "D1 decision"). All 21 are grammar-unflagged. One row per regex match (33 matches).

**How produced.** `label_batch` → `attach_grammar_labels` over `data/frozen/incidents_snapshot.jsonl`; GHSA record from `select_canonical_record(..., "ghsa")`; every regex-positive OSV record for the package is listed. "Section" is the `## Source:` header preceding the match in the OSV description ("preamble" = before the first header). Reporter lists use `extract_reporters()` naming. Snippets are the labeler's `matched_text` (±80 chars context), whitespace-collapsed, cut at 220 chars.

**D1 call** is one reader's judgement, not a validated annotation: *clear* = the OSV text describes a concrete malicious mechanism; *borderline* = the matched text is a scanner-template reason line rather than a description. **Category note** marks the 5 packages where the binary DV looks right but the category assignment does not (5.9).

## Summary

| # | Package | Eco | GHSA id | OSV id | GHSA reporters | OSV reporters | Match section(s) | D1 call | Category note |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `ddok-modal` | npm | GHSA-5xvp-j6m9-rwr6 | MAL-2026-10497 | <ghsa-boilerplate> | amazon-inspector, ghsa-malware, <ghsa-boilerplate> | amazon-inspector | clear |  |
| 2 | `homestack-cheer` | npm | GHSA-x567-p88w-3697 | MAL-2026-16333 | <ghsa-boilerplate> | amazon-inspector, ghsa-malware, <ghsa-boilerplate> | amazon-inspector | clear | inline base64 second stage labelled remote_payload_retrieval (no remote fetch) |
| 3 | `pf25133` | npm | GHSA-8f7g-cf69-g5p8 | MAL-2026-16339 | <ghsa-boilerplate> | amazon-inspector, ghsa-malware, <ghsa-boilerplate> | amazon-inspector | clear |  |
| 4 | `pf25262` | npm | GHSA-3pg3-52vp-54fg | MAL-2026-16340 | <ghsa-boilerplate> | amazon-inspector, ghsa-malware, <ghsa-boilerplate> | amazon-inspector | clear |  |
| 5 | `pflag14570` | npm | GHSA-qxgf-vc83-fc34 | MAL-2026-16341 | <ghsa-boilerplate> | amazon-inspector, ghsa-malware, <ghsa-boilerplate> | amazon-inspector | clear |  |
| 6 | `aiosendletter` | pypi | GHSA-hc2r-77jq-mjrx | MAL-2026-16264 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 7 | `auclean` | pypi | GHSA-v257-9gjr-rv2j | MAL-2026-16410 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 8 | `gcphelpit` | pypi | GHSA-9jm3-2h34-h9g3 | MAL-2026-15810 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 9 | `licloud` | pypi | GHSA-gwqx-5242-h5mw | MAL-2026-16219 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear | host-recon beacon labelled credential_or_wallet_exfiltration |
| 10 | `memoryos` | pypi | GHSA-hxf9-rvj5-h45h | MAL-2026-16475 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 11 | `metricboxlite` | pypi | GHSA-92qj-f225-g878 | MAL-2026-15931 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear | host-recon beacon labelled credential_or_wallet_exfiltration |
| 12 | `prosocks` | pypi | GHSA-6v7p-c53r-646f | MAL-2026-17167 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 13 | `proxycer` | pypi | GHSA-qff6-cqrr-65wv | MAL-2026-15935 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 14 | `rak-lab-yoav-orca-zrktd2cp5hjmo4x7` | pypi | GHSA-2mp7-443g-cw4c | MAL-2026-16241 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 15 | `starlette-healthchecks` | pypi | GHSA-6g46-rqp7-42mp | MAL-2026-16356 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear | host-recon beacon labelled credential_or_wallet_exfiltration |
| 16 | `timeweave` | pypi | GHSA-pjqm-mp65-gqw6 | MAL-2026-15910 | amazon-inspector | amazon-inspector, kam193 | kam193 | borderline |  |
| 17 | `trongappy` | pypi | GHSA-xr9j-54f9-pcpm | MAL-2026-16242 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 18 | `trongridew` | pypi | GHSA-vjjx-756v-6p3x | MAL-2026-15936 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 19 | `trongridi` | pypi | GHSA-7h6v-482q-hg5f | MAL-2026-15858 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear |  |
| 20 | `tsshare` | pypi | GHSA-r5pm-g6fr-mh26 | MAL-2026-16044 | (none) | amazon-inspector | amazon-inspector, preamble | clear |  |
| 21 | `vercel-runtime-python` | pypi | GHSA-fvc2-927p-99h8 | MAL-2026-17168 | kam193 | amazon-inspector, kam193 | amazon-inspector | clear | host-recon beacon labelled credential_or_wallet_exfiltration |

## Matches

| Package | Category | Section | Matched text |
|---|---|---|---|
| `ddok-modal` | credential_or_wallet_exfiltration | amazon-inspector | bby, TronLink, Bitget, Coinbase, and Solflare, but the modal UIs are credential-harvesting impersonations of those wallets. Each wallet 'unlock' modal binds an onChange handler that calls sendKeyToBackend(userId, 'c |
| `ddok-modal` | brand_impersonation_narrative | amazon-inspector | nk, Bitget, Coinbase, and Solflare, but the modal UIs are credential-harvesting impersonations of those wallets. Each wallet 'unlock' modal binds an onChange handler that cal |
| `homestack-cheer` | remote_payload_retrieval | amazon-inspector | with `new Function(atob('<~180KB base64>')).call(this)`, decoding an obfuscated second-stage payload via a runtime string-shuffle routine. When a downstream project bundles this pa |
| `pf25133` | credential_or_wallet_exfiltration | amazon-inspector | ist of application paths, extracts flag-shaped patterns from the responses, and POSTs the aggregated data as JSON to a hardcoded webhook.site collector URL (https://webhook.site/c4e39647-bfb8-47ef-b6d4-a112aacc6cd1). The… |
| `pf25262` | credential_or_wallet_exfiltration | amazon-inspector | 2ecd1fc97b2c01dc194e863809626cdaee5c7e6b0a411f8aeb) index.js contains a browser exfiltration snippet that issues a credentialed fetch to /profile, extracts a DGA{...} token or falls back to capturing docum |
| `pf25262` | credential_or_wallet_exfiltration | amazon-inspector | e path. The package's entire shipped payload is this authenticated-session-data exfiltration snippet, sending same-origin credentials and cookies to an attacker-controlled webhook.site bin. ## Source: ghsa-malwa |
| `pflag14570` | credential_or_wallet_exfiltration | amazon-inspector | ettings, and similar), extracts a flag-shaped substring from the responses, and POSTs the aggregated JSON to the hardcoded collector https://webhook.site/42c6d937-77c7-42a5-8678-ef06b4501e38. The package metadata is a st… |
| `aiosendletter` | credential_or_wallet_exfiltration | amazon-inspector | ction archives the contents of %LOCALAPPDATA%\logs with shutil.make_archive and POSTs the resulting archive to a hardcoded, non-configurable Cloudflare Workers endpoint at https://sparkling-pine-f202.stilluer-sweden.work… |
| `auclean` | credential_or_wallet_exfiltration | amazon-inspector | h are consistent with audio normalization, and all of which are consistent with harvesting Kubernetes/CI service-account tokens and other credentials from build/CI environments. The same install-time path a |
| `gcphelpit` | credential_or_wallet_exfiltration | amazon-inspector | WS_*, GOOGLE_APPLICATION_CREDENTIALS, GitHub/npm tokens), so the effect is bulk exfiltration of installer-owned shell secrets to a third-party public webhook collector that is unrelated to the package's a |
| `gcphelpit` | credential_or_wallet_exfiltration | amazon-inspector | gcphelpit/_verify.py runs at import time: it reads the installer's ~/.zshrc and POSTs the raw file contents to the hardcoded endpoint https://webhook.site/bc67d797-61ff-4f3b-a9b8-5df6a5e7643d. cli.py imports _verify at t… |
| `licloud` | credential_or_wallet_exfiltration | amazon-inspector | e068e84b5bd87242ad31e4b833cdcc056021925aa2dcc91633b46) setup.py unconditionally collects the installer's OS name, username, and hostname and POSTs them to a hardcoded plain-HTTP bare-IP endpoint (http://182.92.143.23/col… |
| `licloud` | credential_or_wallet_exfiltration | amazon-inspector | py unconditionally collects the installer's OS name, username, and hostname and POSTs them to a hardcoded plain-HTTP bare-IP endpoint (http://182.92.143.23/collect.php) before invoking setup(). The beacon fires on |
| `memoryos` | credential_or_wallet_exfiltration | amazon-inspector | main C2 fronts, declared $HOME inventory harvest, and a CI-only sideloader that steals publish tokens is a supply-chain implant. ## Source: kam193 (d17530b4f32046961be6354a73139da |
| `metricboxlite` | credential_or_wallet_exfiltration | amazon-inspector | 11a75c8c42dcd677dd3814265d3befefa7f339bdc6b0336788635813e837) MetricBoxLite 1.0 collects the installer's username (getpass.getuser) and hostname (socket.gethostname), JSON-encodes them, and POSTs the payload to a hardcod… |
| `metricboxlite` | credential_or_wallet_exfiltration | amazon-inspector | ame (getpass.getuser) and hostname (socket.gethostname), JSON-encodes them, and POSTs the payload to a hardcoded remote endpoint at https://kznkrxfzy4xgib6ejfh8etegndp3kwguf.oast.invalid/collect. The beacon f |
| `prosocks` | hidden_install_hook | amazon-inspector | exit node under a hardcoded control plane at https://kalnetz.store. setup.py's custom install command writes prosocks.bat into the Windows Startup folder (establishing boot persiste |
| `prosocks` | remote_backdoor_access | amazon-inspector | s whose credentials are handed to that control plane matches a proxyware/botnet backdoor. ## Source: kam193 (a1ca37b881f19975a8ab8b23bd5e69b51355333374385aabfc5784b69b |
| `proxycer` | obfuscated_payload_execution | amazon-inspector | starts.py, which is a single-line loader that reverses a ~100KB string literal, base64-decodes it, marshal.loads the result into a code object, and exec()s it. All actual functionality is concealed behind reversal + base… |
| `rak-lab-yoav-orca-zrktd2cp5hjmo4x7` | credential_or_wallet_exfiltration | amazon-inspector | -orca-zrktd2cp5hjmo4x7 version 9.9.9 ships a setup.py that, during pip install, reads the DEPLOYMENT_TOKEN environment variable and POSTs it as JSON to https://webhook.site/27c83a25-7d20-44e9-98ab-19954383f4b1 via ur |
| `rak-lab-yoav-orca-zrktd2cp5hjmo4x7` | credential_or_wallet_exfiltration | amazon-inspector | y that, during pip install, reads the DEPLOYMENT_TOKEN environment variable and POSTs it as JSON to https://webhook.site/27c83a25-7d20-44e9-98ab-19954383f4b1 via urllib.request. The package has n |
| `rak-lab-yoav-orca-zrktd2cp5hjmo4x7` | credential_or_wallet_exfiltration | amazon-inspector | igned to win resolution against an internal package name. The install-time HTTP POST to a non-publisher webhook.site collector is a working credential-exfiltration primitive; a conditional branch limits exe |
| `starlette-healthchecks` | credential_or_wallet_exfiltration | amazon-inspector | as a log line, resolves the machine's public IP via checkip.amazonaws.com, and sends the hostname. Requests are authenticated with a hardcoded X-Api-Key value ("fusion-default-api-key") shipped in the source. The env-var… |
| `starlette-healthchecks` | credential_or_wallet_exfiltration | amazon-inspector | starlette_healthcheck/setup.py via __init__.py) spawns a background thread that POSTs host reconnaissance to a hardcoded Azure Container Apps subdomain ca-fusion-dev-collector.victorioussmoke-2f009910.uksouth.azurecontai… |
| `timeweave` | remote_payload_retrieval | kam193 | stealers. Campaign: 2026-09-timeweave Reasons (based on the campaign): - Downloads and executes a remote executable. - action-hidden-in-lib-usage - infostealer |
| `timeweave` | remote_payload_retrieval | kam193 | stealers. Campaign: 2026-09-timeweave Reasons (based on the campaign): - Downloads and executes a remote executable. - action-hidden-in-lib-usage - infostealer |
| `trongappy` | credential_or_wallet_exfiltration | amazon-inspector | cc6df1b7) The package exposes a single public function `perm(private_key)` that POSTs its `private_key` argument as JSON to the hardcoded URL https://reda-sequestered-justine.ngrok-free.dev/tron and then queries a `/s |
| `trongridew` | credential_or_wallet_exfiltration | amazon-inspector | a single public function `perm(private_key)` in `main.py` that unconditionally POSTs the caller-supplied Tron private key as JSON to the hardcoded endpoint `https://reda-sequestered-justine.ngrok-free.dev/tron`. The dest… |
| `trongridi` | credential_or_wallet_exfiltration | amazon-inspector | 2b4b403103) The package exposes a single public function perm(private_key) that POSTs the caller-supplied TRON wallet private key as JSON to the hardcoded endpoint https://reda-sequestered-justine.ngrok-free.dev/tron. Th… |
| `tsshare` | credential_or_wallet_exfiltration | amazon-inspector | r Tushare's pro_api, but every method call is dispatched through a query() that POSTs to a hardcoded default backend at https://47.112.191.75/api/v1/proxy rather than to tushare.pr |
| `tsshare` | credential_or_wallet_exfiltration | amazon-inspector | every subsequent proxied call includes {'auth_code': self.auth_code,...} in the POST body to that endpoint, so the paid third-party credential leaves the trust boundary it was issued for |
| `tsshare` | brand_impersonation_narrative | preamble | Malicious code in tsshare (PyPI) The PyPI package `tsshare` is malicious. It impersonates the popular Chinese market-data library `tushare` — its docstrings advertise co |
| `vercel-runtime-python` | credential_or_wallet_exfiltration | amazon-inspector | solved IP, operating system, and machine architecture via get_device_info() and POSTs the result as JSON to the hardcoded URL https://webhook.site/f9bff304-3053-4d54-be05-86537267514a. The destination is not caller-confi… |

## Counts

- Packages: 21 (npm 5, PyPI 16). Grammar-flagged: 0/21.
- Matches: 33. Section of match: amazon-inspector 30, kam193 2 (timeweave), preamble 1 (tsshare).
- GHSA reporters: kam193 only 14, `<ghsa-boilerplate>` only 5 (all npm), amazon-inspector only 1 (timeweave), none 1 (tsshare).
- D1 call: clear 20, borderline 1 (timeweave: "Downloads and executes a remote executable" is a line from kam193's campaign-reason template).
