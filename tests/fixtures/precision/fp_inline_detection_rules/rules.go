// From antoroute/openclawsecure, a DEFENSIVE security gateway that confirmed AUTO on
// the 2026-07-21 hunt. This is its detection rule table: the credential paths and
// the known-exfil host are patterns it looks FOR, exactly like a YARA ruleset. The
// file-level security-data check never fired because the rules live inline in
// ordinary source rather than in a file named like a ruleset.
package gateway

import "regexp"

type Rule struct {
	ID         string
	Pattern    *regexp.Regexp
	Title      string
	Severity   string
	Confidence float64
	Tags       []string
}

var Rules = []Rule{
	{ID: "PATH-AWS-CREDS", Pattern: regexp.MustCompile(`(?:~|\$\{?HOME\}?|/home/\w+|/root|/Users/\w+)/\.aws/credentials`), Title: "AWS credentials file", Severity: "CRITICAL", Confidence: 0.98, Tags: []string{"credentials"}},
	{ID: "PATH-SSH-KEY", Pattern: regexp.MustCompile(`/\.ssh/id_(?:rsa|ed25519)`), Title: "SSH private key", Severity: "CRITICAL", Confidence: 0.97, Tags: []string{"credentials"}},
	{ID: "C2-WEBHOOK-SITE", Pattern: regexp.MustCompile(`(?i)webhook\.site`), Title: "webhook.site (known exfil)", Severity: "HIGH", Confidence: 0.90, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-PASTEBIN", Pattern: regexp.MustCompile(`(?i)pastebin\.com/raw`), Title: "pastebin raw fetch", Severity: "HIGH", Confidence: 0.85, Tags: []string{"exfiltration"}},
}
