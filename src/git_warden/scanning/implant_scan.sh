#!/usr/bin/env bash
# implant_scan.sh - git_warden Layer-1 bash scanner for cloned repos (doc 03).
#
# Hunts maliciously *implanted* code in an already-cloned repo: reverse shells,
# download-and-exec, exfiltration, persistence, credential theft, obfuscated
# payloads, and the supply-chain hooks that run the instant a victim installs
# (npm pre/post-install, setup.py exec-on-install). Mirrors the categories and
# weights in scanning/bash_scanner.py so findings line up across the two layers.
#
# SAFETY: read-only. It greps text and reads 4 magic bytes; it NEVER sources,
# executes, installs, or builds anything in the target. Run it inside the
# disposable analysis container/VM, pointed at the clone.
#
# Usage:
#   bash implant_scan.sh <repo_dir> [--json] [--fast]
#     --json   machine-readable single JSON object on stdout (for the pipeline)
#     --fast   skip node_modules/vendor and the binary-magic sweep (large repos)
# Exit: 0 = clean, 1 = suspicious/malicious findings, 2 = usage/IO error.

set -uo pipefail

REPO=""; JSON=0; FAST=0
for a in "$@"; do
  case "$a" in
    --json) JSON=1 ;;
    --fast) FAST=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) REPO="$a" ;;
  esac
done
[ -n "$REPO" ] && [ -d "$REPO" ] || { echo "usage: bash implant_scan.sh <repo_dir> [--json] [--fast]" >&2; exit 2; }

CONFIRM_THRESHOLD=5          # weighted score at/above which (+ a strong cat) => malicious
STRONG="reverse_shell download_exec exfiltration supply_chain credential_harvest"
FINDINGS="$(mktemp)" || exit 2
trap 'rm -f "$FINDINGS"' EXIT

EXCLUDES=(--exclude-dir=.git --exclude-dir=.svn --exclude-dir=.hg)
[ "$FAST" -eq 1 ] && EXCLUDES+=(--exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.venv)

cd "$REPO" || exit 2

# rule CATEGORY RULE WEIGHT 'ERE' -- grep the whole tree, record file/line/snippet.
# (single-quote the pattern; backslashes are passed through to grep -E verbatim)
rule() {
  local cat="$1" name="$2" weight="$3" pat="$4" m file rest line snip
  while IFS= read -r m; do
    file="${m%%:*}"; rest="${m#*:}"; line="${rest%%:*}"; snip="${rest#*:}"
    snip="${snip:0:200}"; snip="${snip//$'\t'/ }"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$cat" "$name" "$weight" "$file" "$line" "$snip" >>"$FINDINGS"
  done < <(grep -rEnIHi "${EXCLUDES[@]}" -e "$pat" . 2>/dev/null)
}

# --- reverse shells (5) -----------------------------------------------------
rule reverse_shell dev-tcp-redirect 5 '/dev/(tcp|udp)/'
rule reverse_shell nc-exec          5 '\bn(c|cat)\b[^\n]*[[:space:]]-e\b'
rule reverse_shell bash-i-socket    5 'bash[[:space:]]+-i\b[^\n]*(>&|2>&1)'
rule reverse_shell mkfifo-shell     5 'mkfifo[^\n]*\b(nc|ncat|sh|bash)\b'
rule reverse_shell python-reverse   5 'socket\.socket[^\n]*(connect|SOCK_STREAM)'
rule reverse_shell powershell-tcp   5 'New-Object[[:space:]]+System\.Net\.Sockets\.TCPClient'

# --- download + execute (4) -------------------------------------------------
rule download_exec curl-pipe-shell  4 '(curl|wget)[[:space:]][^|]*\|[[:space:]]*(sh|bash|python[0-9]?|perl|node|ruby)'
rule download_exec fetch-then-exec  4 '(curl|wget)[[:space:]][^\n]*-o[[:space:]]*[^[:space:]]+[^\n]*;[[:space:]]*(sh|bash|chmod)'
rule download_exec iex-webclient    4 '(IEX|Invoke-Expression)[^\n]*(Net\.WebClient|Invoke-WebRequest|\biwr\b|DownloadString)'
rule download_exec node-http-exec   4 '(child_process|execSync|exec)\([^\n]*(http://|https://)'
rule download_exec py-exec-fetch    4 'exec\([^\n]*requests\.(get|post)|__import__\([\"]os[\"]\)[^\n]*system'

# --- exfiltration (4) -------------------------------------------------------
rule exfiltration discord-webhook   4 'discord(app)?\.com/api/webhooks/'
rule exfiltration telegram-bot      4 'api\.telegram\.org/bot'
rule exfiltration curl-post-data    4 '\bcurl\b[^\n]*([[:space:]]-[dFT]\b|--data\b|--upload-file\b)'
rule exfiltration archive-then-send 4 '(tar|zip|gzip)\b[^\n]*\|[[:space:]]*(curl|nc|wget)'
rule exfiltration env-pipe-out      4 '(env|printenv)\b[^\n]*\|[[:space:]]*(curl|nc|wget)'

# --- supply-chain / install-time implants (4) -- runs on victim install -----
rule supply_chain npm-install-hook  4 '\"(pre|post)install\"[[:space:]]*:[^\n]*(curl|wget|node[[:space:]]+-e|child_process|eval|http|base64|powershell)'
rule supply_chain npm-prepare-hook  4 '\"prepare\"[[:space:]]*:[^\n]*(curl|wget|node[[:space:]]+-e|child_process|http)'
rule supply_chain gh-secrets-exfil  4 '\$\{\{[[:space:]]*secrets\.[^\n]*\}\}[^\n]*(curl|wget|http)'

# --- persistence (3) --------------------------------------------------------
rule persistence cron            3 '\bcrontab\b|/etc/cron|@reboot'
rule persistence rc-files        3 '>>[[:space:]]*~?/?\.?(bashrc|bash_profile|profile|zshrc)\b'
rule persistence systemd         3 'systemctl[[:space:]]+enable|/etc/systemd/system/'
rule persistence authorized-keys 3 '\.ssh/authorized_keys'
rule persistence rc-local        3 '/etc/rc\.local|launchctl[[:space:]]+load'
rule persistence win-run-key     3 '(reg[[:space:]]+add|New-ItemProperty)[^\n]*(CurrentVersion.?Run|HKCU|HKLM)'
rule persistence scheduled-task  3 'schtasks[[:space:]]+/create|Register-ScheduledTask'

# --- credential harvest (3) -------------------------------------------------
rule credential_harvest ssh-keys      3 'id_rsa|id_ed25519|\.ssh/id_'
rule credential_harvest cloud-creds   3 '\.aws/credentials|\.config/gcloud|\.azure/'
rule credential_harvest shadow-passwd 3 '/etc/(shadow|passwd)'
rule credential_harvest env-token     3 '\b(AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|API_KEY|PRIVATE_KEY)\b'
rule credential_harvest browser-creds 3 '(Login Data|Cookies|Local State|key4\.db|logins\.json|wallet\.dat)'
rule credential_harvest lazagne       3 '\blazagne\b'

# --- process injection (3) --------------------------------------------------
rule process_injection ld-preload  3 '\bLD_PRELOAD\b'
rule process_injection ptrace-mem  3 '/proc/[0-9]+/mem|\bptrace\b'
rule process_injection gdb-attach  3 'gdb[[:space:]]+-p\b'
rule process_injection win-inject  3 '(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread)'

# --- lateral movement (2) ---------------------------------------------------
rule lateral_movement sshpass     2 '\bsshpass\b'
rule lateral_movement remote-exec 2 '\b(psexec|wmiexec|smbexec|crackmapexec|evil-winrm)\b'

# --- network scan (2) -------------------------------------------------------
rule network_scan scanner    2 '\b(nmap|masscan|zmap)\b'
rule network_scan port-sweep 2 'nc[[:space:]]+-z\b'

# --- enumeration (1) --------------------------------------------------------
rule enumeration host-recon 1 '\b(uname[[:space:]]+-a|whoami|hostname)\b'
rule enumeration net-recon  1 '\b(ifconfig|ip[[:space:]]+addr|netstat|ss[[:space:]]+-)\b'

# --- obfuscation / evasion (3) ----------------------------------------------
rule obfuscation base64-decode-exec 3 'base64[[:space:]]+(-d|--decode)[^\n]*\|[[:space:]]*(sh|bash)'
rule obfuscation eval-base64        3 'eval[[:space:]][^\n]*base64'
rule obfuscation atob-eval          3 'eval\([^\n]*(atob|Buffer\.from)\('
rule obfuscation fromcharcode       3 'String\.fromCharCode\([^\n]*,'
rule obfuscation powershell-enc     3 'powershell[^\n]*(-enc|-encodedcommand)\b'
rule obfuscation hex-escapes        3 '(\\x[0-9a-fA-F]{2}){8,}'
rule obfuscation ifs-obfuscation    3 '\$\{IFS\}'
rule obfuscation eval-subshell      3 'eval[[:space:]]+[\"]?\$\('
rule obfuscation long-base64-blob   3 '[A-Za-z0-9+/]{220,}={0,2}'

# --- targeted: setup.py executing code at install time ----------------------
# A normal setup.py never needs os.system / exec / network calls; these are the
# classic PyPI-implant signature, so scope the check to install scripts only.
while IFS= read -r f; do
  while IFS= read -r m; do
    file="${m%%:*}"; rest="${m#*:}"; line="${rest%%:*}"; snip="${rest#*:}"
    snip="${snip:0:200}"; snip="${snip//$'\t'/ }"
    printf 'supply_chain\tsetup-exec\t4\t%s\t%s\t%s\n' "$file" "$line" "$snip" >>"$FINDINGS"
  done < <(grep -EnHi '(os\.system|subprocess\.(call|run|Popen|check_output)|[^a-z]exec\(|compile\(|__import__\(|urllib\.request|requests\.(get|post))' "$f" 2>/dev/null)
done < <(find . \( -name setup.py -o -name conftest.py \) -not -path '*/.git/*' 2>/dev/null)

# --- committed native binaries hiding in a "source" repo --------------------
if [ "$FAST" -eq 0 ]; then
  nfiles="$(find . -type f -not -path '*/.git/*' 2>/dev/null | head -20001 | wc -l)"
  if [ "$nfiles" -le 20000 ]; then
    while IFS= read -r f; do
      magic="$(head -c4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')"
      case "$magic" in
        7f454c46)  printf 'binary_payload\telf-binary\t3\t%s\t0\t<ELF executable committed to repo>\n'  "$f" >>"$FINDINGS" ;;
        4d5a*)     printf 'binary_payload\tpe-binary\t3\t%s\t0\t<PE/EXE committed to repo>\n'           "$f" >>"$FINDINGS" ;;
      esac
    done < <(find . -type f -not -path '*/.git/*' 2>/dev/null)
  fi
fi

# ---------------------------------------------------------------------------
# Score: distinct (category,rule) counted once (anti-spam), weighted sum.
score=0; strong_hit=0
if [ -s "$FINDINGS" ]; then
  score="$(cut -f1,2,3 "$FINDINGS" | sort -u | awk -F'\t' '{s+=$3} END{print s+0}')"
  for cat in $STRONG; do
    if cut -f1 "$FINDINGS" | grep -qx "$cat"; then strong_hit=1; break; fi
  done
fi
total="$(wc -l <"$FINDINGS" | tr -d ' ')"

verdict="clean"
if [ "$score" -ge "$CONFIRM_THRESHOLD" ] && [ "$strong_hit" -eq 1 ]; then
  verdict="malicious"
elif [ "$total" -gt 0 ]; then
  verdict="suspicious"
fi

if [ "$JSON" -eq 1 ]; then
  [ "$strong_hit" -eq 1 ] && sbool=true || sbool=false
  printf '{"scanner":"implant","verdict":"%s","score":%s,"strong":%s,"total":%s,"findings":[' \
    "$verdict" "$score" "$sbool" "$total"
  awk -F'\t' 'BEGIN{first=1}
    { cat=$1; r=$2; file=$4; ln=$5; snip=$6;
      gsub(/\\/,"\\\\",snip); gsub(/"/,"\\\"",snip); gsub(/[\001-\037]/," ",snip);
      gsub(/\\/,"\\\\",file); gsub(/"/,"\\\"",file);
      if(ln !~ /^[0-9]+$/) ln="0";
      if(!first) printf(","); first=0;
      printf("{\"category\":\"%s\",\"rule\":\"%s\",\"file\":\"%s\",\"line\":%s,\"snippet\":\"%s\"}",cat,r,file,ln,snip);
    }' "$FINDINGS"
  printf ']}\n'
else
  echo "== git_warden implant scan: $REPO =="
  if [ "$total" -eq 0 ]; then
    echo "No implant indicators found."
  else
    echo "Findings by category (weighted, distinct rules):"
    cut -f1 "$FINDINGS" | sort | uniq -c | sort -rn | sed 's/^/  /'
    echo
    echo "Top hits:"
    awk -F'\t' '{printf "  [%s/%s] %s:%s  %s\n",$1,$2,$4,$5,$6}' "$FINDINGS" | head -40
    echo
  fi
  echo "score=$score  strong_category=$([ $strong_hit -eq 1 ] && echo yes || echo no)  verdict=$verdict"
fi

[ "$verdict" = "clean" ] && exit 0 || exit 1
