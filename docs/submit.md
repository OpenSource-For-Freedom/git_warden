# Report a malicious asset via API

This is OpenSourceMalware's own API reference, kept here for operators who build
their own tooling. Git Warden's built-in submitter (`python -m git_warden.osm_submit`)
already wraps all of this with full-history dedup, a liveness recheck, and verified
IOCs. See the "Submit to OSM" section of the README.

Submit threat reports programmatically instead of using the web UI. Submitted reports
enter the community verification process and are only published after passing review.
Use this endpoint to:

- Automate reporting from your tooling: flag suspicious packages the moment your
  internal detection systems identify them.
- Integrate with security pipelines: trigger submissions from CI/CD workflows,
  dependency scanners, or SIEM alerts.
- Contribute at scale: research teams can submit structured reports in bulk.

You can track the status of your submissions from your profile on opensourcemalware.com.
For guidance on writing high-quality threat reports, including what evidence to
include and how to describe threat behavior, see the reporting guidelines.

## Endpoint

The working create endpoint is `submit-threat-report`. The public docs list
`submit-threat`, which returns 404, so use the one below.

```
POST https://api.opensourcemalware.com/functions/v1/submit-threat-report
```
## Required headers
```
Authorization: Bearer osm_your_token
Content-Type: application/json
​```
```
## Request body
```
{
  "report_type": "package",           // Required: "package" | "repository" | "url" | "domain" | "ip" | "wallet" | "container"
  "resource_identifier": "npm/malicious-pkg",  // Required: Package/repo identifier
  "threat_description": "Cryptocurrency miner in postinstall script",  // Required
  
  // Optional fields
  "package_name": "malicious-pkg",
  "registry": "npm",
  "publisher": "evil-user",
  "payload_description": "Downloads and executes mining binary",
  "severity_level": "critical",       // "critical" | "high" | "medium" | "low"
  "evidence_references": "https://github.com/evidence/repo",
  "contact_email": "reporter@example.com",
  "tags": ["cryptocurrency", "miner", "postinstall"],
  "version_info": "All versions affected",
  "first_seen": "2024-01-01T00:00:00Z",
  "last_seen": "2024-01-02T00:00:00Z",
  "osv_advisory_url": "https://osv.dev/vulnerability/OSV-2024-001",
  "contributors": ["security-researcher"],
  "download_count": 50000
}
```
## Response examples

- Success (201)

```
{
  "message": "Threat report submitted successfully",
  "threat_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "pending"
}

​```
## Error (400)
```
{
  "error": "Missing required fields: report_type, resource_identifier, and threat_description are required"
}
​```
## cURL examples
```
Package report
curl -X POST "https://api.opensourcemalware.com/functions/v1/submit-threat" \
  -H "Authorization: Bearer osm_your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "package",
    "resource_identifier": "npm/malicious-package",
    "threat_description": "Package contains cryptocurrency mining code",
    "package_name": "malicious-package",
    "registry": "npm",
    "severity_level": "critical",
    "tags": ["cryptocurrency", "miner"]
  }'
```
## Repository report
```
curl -X POST "https://api.opensourcemalware.com/functions/v1/submit-threat" \
  -H "Authorization: Bearer osm_your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "repository",
    "resource_identifier": "github.com/malicious-user/evil-repo",
    "threat_description": "Repository contains info-stealer malware",
    "publisher": "malicious-user",
    "severity_level": "high",
    "tags": ["infostealer", "lazarus"]
  }'
  ```
## Domain report
```
curl -X POST "https://api.opensourcemalware.com/functions/v1/submit-threat" \
  -H "Authorization: Bearer osm_your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "domain",
    "resource_identifier": "evil-c2-server.com",
    "threat_description": "C2 server used by cryptocurrency miner malware",
    "severity_level": "critical",
    "tags": ["c2", "cryptominer"]
  }'
```