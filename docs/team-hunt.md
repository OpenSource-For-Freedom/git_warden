# Joint team hunt

## Purpose

The joint hunt runs Git Warden and KNÖRR as two independent detectors with a shared correlation channel.

Warden searches the repository surface. KNÖRR searches the container surface. Neither tool inherits the other tool's verdict.

## Execution order

The canonical workflow lives in KNÖRR at:

```
.github/workflows/joint-threat-hunt.yml
```

The hunt job performs these stages:

1. harden the GitHub-hosted runner with Legion;
2. check out the reviewed KNÖRR and Warden revisions;
3. restore the shared hunt state;
4. validate the joint-control configuration;
5. build both Tier-2 sandbox images;
6. run workflow security checks, targeted OSM tests, lint, and full test suites;
7. validate required credentials;
8. reconcile Warden's prior repository findings;
9. ingest Warden intelligence;
10. run Warden's deep repository hunt;
11. run KNÖRR Docker Hub hunt;
12. run KNÖRR GHCR hunt;
13. run the Dockerfile threat surface;
14. run Warden again with intelligence learned by KNÖRR;
15. summarize shared breadcrumbs;
16. build Warden and KNÖRR OSM submission previews;
17. upload review evidence.

## Data paths

During the job:

```
ci-state/
  git_warden.sqlite
  knorr.sqlite
  breadcrumbs.jsonl
```

Warden reads and writes `GW_SHARED_INTEL`. KNÖRR reads and writes `KN_SHARED_INTEL`. In joint CI both variables resolve to the same JSONL file.

## Correlation contract

A shared record can cause another target to be discovered or prioritized. It cannot confirm that target.

Examples:

- Warden finds a C2 host. KNÖRR searches image content for that host.
- KNÖRR finds a malicious package inside an image. Warden pivots to repositories using or publishing it.
- Warden identifies an image reference in a malicious repository. KNÖRR inspects the image.
- KNÖRR identifies source-repository metadata. Warden inspects the repository.
- Either tool records an OSM submission. The other treats it as a duplicate-prevention hint and still checks OSM directly.

## Submission boundary

A normal team hunt is read-only with respect to OSM reporting.

When the workflow is dispatched with `submit=true`, the hunt still completes first and produces the exact preview. The submit job is then blocked by the protected `osm-submission` environment. Approval authorizes revalidation; it does not authorize bypassing validation.

See [submit.md](submit.md) for the full gate sequence.
