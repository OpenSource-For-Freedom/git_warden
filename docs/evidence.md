# Evidence store

`evidence/` is committed to the repository and refreshed by every hunt
(The Warden, the VS Code extension hunt and the extension OSM submit job).

| Path | Contents |
|---|---|
| `evidence/findings.csv` | One row per confirmed repository and VS Code extension, all columns |
| `evidence/repositories/<owner>_<repo>.json` | Every finding (file, line, rule, snippet), the scanned commit and the exact OSM report body |
| `evidence/extensions/<registry>_<publisher>.<name>.json` | Every finding, the extension manifest details and, while awaiting approval, the exact OSM report body |
| `evidence/osm_extension_ledger.json` | Extensions submitted to OSM, with threat id, version and time |
| `evidence/osm_repository_ledger.json` | Repositories submitted to OSM by any run, including the KNORR joint hunt, with threat id |

## Columns

`key`, `kind`, `id`, `url`, `registry`, `owner`, `status`, `confidence`,
`score`, `detection_method`, `attribution`, `campaign_id`, `rules`,
`evidence_locations`, `c2_hosts`, `iocs`, `matched_signatures`, `reasons`,
`osm_status` (`not_submitted`, `awaiting_approval`, `submitted`),
`osm_threat_id`, `first_seen`, `last_seen`, `evidence_file`,
`reviewer_decision`, `notes`.

## Editing

Edit `reviewer_decision` and `notes` by hand, in GitHub or a spreadsheet, and
commit. Runs refresh every other column and keep these two. `reject` in
`reviewer_decision` keeps an extension out of every future OSM preview.

Rows are never dropped: a finding whose data was lost from the Actions cache
keeps its last known row. If a run's update conflicts with a hand edit, the
publish script keeps the edited file and regenerates on top of it.

The two ledgers are authoritative for `osm_status`: a submission recorded by
any run is never shown as `not_submitted`, even when a later run's own database
does not know about it. The KNORR joint hunt keeps its own database, so its
submit job exports that database into this store after every submission.

Refresh locally with `python gw.py evidence`.
