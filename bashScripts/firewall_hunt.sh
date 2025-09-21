#!/usr/bin/env bash
# firewall_hunt.sh
#
# Recreated hunting script: searches logs (including .gz), systemd journal (optional),
# and all user history files for firewall-related tampering commands and lists current
# firewall rules/config. Safe read-only tool for offline/forensic use.
#
# Usage:
#   sudo ./firewall_hunt.sh [--logs DIR] [--homes DIR] [--journal] [--out FILE]
#
# Defaults:
#   LOGDIR=/var/log
#   HOMEDIR=/home
#   OUTFILE="" (stdout)
#
# Example:
#   sudo ./firewall_hunt.sh --journal --out /tmp/fw_hunt.tsv
#
# Output (TSV): source<TAB>file_or_journal<TAB>lineno_or_ts<TAB>label<TAB>match_text
# - source: log | history | journal | livecfg
# - label: pattern label from PATTERNS map
#
set -euo pipefail

LOGDIR="/var/log"
HOMEDIR="/home"
OUTFILE=""
DO_JOURNAL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --logs) LOGDIR="$2"; shift 2;;
    --homes) HOMEDIR="$2"; shift 2;;
    --journal) DO_JOURNAL=1; shift;;
    --out) OUTFILE="$2"; shift 2;;
    -h|--help)
      cat <<'USAGE'
firewall_hunt.sh - hunt firewall tampering commands in logs & user histories and list live firewall config

Usage:
  sudo ./firewall_hunt.sh [--logs DIR] [--homes DIR] [--journal] [--out FILE]

Options:
  --logs DIR     Directory to search logs (default /var/log)
  --homes DIR    Parent dir for user homes (default /home)
  --journal      Also scan systemd journal (uses journalctl; last 7 days)
  --out FILE     Save TSV output to FILE (default stdout)
USAGE
      exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

# Timestamp helper
timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Header for TSV
print_header() {
  printf "%s\t%s\t%s\t%s\t%s\n" "source" "file_or_journal" "lineno_or_ts" "label" "match"
}

# Emit function (sanitizes newlines/tabs in match)
emit() {
  local src="$1"; shift
  local file="$1"; shift
  local ln="$1"; shift
  local label="$1"; shift
  local match="$*"
  match="${match//$'\n'/ }"
  match="${match//$'\t'/ }"
  printf "%s\t%s\t%s\t%s\t%s\n" "$src" "$file" "$ln" "$label" "$match"
}

# Patterns: label|extended-regex
read -r -d '' PATTERNS <<'PAT' || true
iptables_cmd|\biptables\b
iptables_flush|\biptables\b.*(-F|\-X|\-Z|--flush|--zero)
iptables_policy_accept|\biptables\b.*-P\b.*ACCEPT\b
nft_cmd|\bnft\b
nft_flush|\bnft\b.*\bflush ruleset\b
firewalld_cmd|\bfirewall-cmd\b
firewalld_systemctl|\bsystemctl\b.*\bfirewalld\b
ufw_cmd|\bufw\b
ufw_disable|\bufw\b.*\bdisable\b
ipset_cmd|\bipset\b
ipset_flush|\bipset\b.*\b(flush|destroy)\b
shorewall_cmd|\bshorewall\b
ebtables_cmd|\bebtables\b
arptables_cmd|\barptables\b
update_alternatives|\bupdate-alternatives\b
rmmod_conntrack|\brmmod\b.*(conntrack|nf_conntrack)
mask_firewalld|\bsystemctl\b.*\bmask\b.*firewalld
systemctl_disable_firewalld|\bsystemctl\b.*\b(disable|stop|mask)\b.*firewalld
iptables_save_write|\biptables-save\b.*(/etc|rules.v4|rules.v6)
nft_load_file|\bnft\b.*-f\b
suspicious_keywords|\b(/bin/sh|/bin/bash|/dev/tcp|/dev/udp|nc\b|socat\b|ssh\b|curl\b|wget\b)
PAT

# Which log file globs to consider (explicit + fallback)
COMMON_FILES=( "audit/audit.log" "syslog*" "messages*" "auth.log*" "secure*" "kern.log*" "ufw.log" "firewalld*" "iptables*" )
# Helper: collect files (including .gz) under LOGDIR (non-destructive)
collect_log_files() {
  local base="$1"
  local -a files=()
  for p in "${COMMON_FILES[@]}"; do
    for f in "$base"/$p; do
      [[ -e "$f" ]] && files+=("$f")
      [[ -e "${f}.gz" ]] && files+=("${f}.gz")
    done
  done
  # add recent .log files (depth 2) as fallback
  while IFS= read -r -d '' ff; do files+=("$ff"); done < <(find "$base" -maxdepth 2 -type f -name '*.log' -print0 2>/dev/null)
  # unique, sorted
  printf "%s\n" "${files[@]}" | sort -u
}

# Search single file (handles .gz)
search_file() {
  local file="$1"
  local is_gz=0
  [[ "$file" == *.gz ]] && is_gz=1

  while IFS='|' read -r label regex; do
    if [[ $is_gz -eq 1 ]]; then
      if zgrep -EnH -- "$regex" "$file" >/dev/null 2>&1; then
        zgrep -EnH -- "$regex" "$file" 2>/dev/null | while IFS=: read -r f ln rest; do
          emit "log" "$f" "$ln" "$label" "$rest"
        done
      fi
    else
      if grep -EnH -- "$regex" "$file" >/dev/null 2>&1; then
        grep -EnH -- "$regex" "$file" 2>/dev/null | while IFS=: read -r f ln rest; do
          emit "log" "$f" "$ln" "$label" "$rest"
        done
      fi
    fi
  done <<< "$PATTERNS"
}

# Search all collected logs
search_logs() {
  echo "$SEPARATOR"
  echo "LOG HUNT: $(timestamp)"
  echo "$SEPARATOR"
  local files
  IFS=$'\n' read -r -d '' -a files < <(collect_log_files "$LOGDIR" && printf '\0')
  for f in "${files[@]}"; do
    [[ -r "$f" ]] || continue
    search_file "$f"
  done
}

# Search histories under HOMEDIR and /root
search_histories() {
  echo "$SEPARATOR"
  echo "HISTORY HUNT: $(timestamp)"
  echo "$SEPARATOR"
  local globs=( "/root/.bash_history" "/root/.zsh_history" "$HOMEDIR/*/.bash_history" "$HOMEDIR/*/.zsh_history" "$HOMEDIR/*/.*history" )
  for g in "${globs[@]}"; do
    for hist in $g; do
      [[ -f "$hist" && -r "$hist" ]] || continue
      # read file line by line with line numbers
      nl -ba -w1 -s: "$hist" 2>/dev/null | while IFS=: read -r lineno line; do
        while IFS='|' read -r label regex; do
          if echo "$line" | grep -E --quiet "$regex"; then
            emit "history" "$hist" "$lineno" "$label" "$line"
          fi
        done <<< "$PATTERNS"
      done
    done
  done
}

# Search journalctl (last 7 days) if requested
search_journal() {
  if ! command -v journalctl >/dev/null 2>&1; then
    echo "journalctl not found; skipping journal search" >&2
    return
  fi
  echo "$SEPARATOR"
  echo "JOURNAL HUNT: $(timestamp) (last 7 days)"
  echo "$SEPARATOR"
  journalctl --since "7 days ago" -o short-iso 2>/dev/null | nl -ba -w1 -s: | while IFS=: read -r lineno line; do
    while IFS='|' read -r label regex; do
      if echo "$line" | grep -E --quiet "$regex"; then
        emit "journal" "journalctl" "$lineno" "$label" "$line"
      fi
    done <<< "$PATTERNS"
  done
}

# List live firewall config / rules (best-effort)
list_firewall_state() {
  echo "$SEPARATOR"
  echo "LIVE FIREWALL CONFIG SNAPSHOT: $(timestamp)"
  echo "$SEPARATOR"
  # iptables
  if command -v iptables >/dev/null 2>&1; then
    emit "livecfg" "iptables -L -n -v" "-" "info" "$(iptables -L -n -v 2>/dev/null | sed -n '1,200p' | tr '\n' ' ' )"
  else
    emit "livecfg" "iptables" "-" "absent" "iptables not present"
  fi

  # nft
  if command -v nft >/dev/null 2>&1; then
    emit "livecfg" "nft list ruleset" "-" "info" "$(nft list ruleset 2>/dev/null | sed -n '1,400p' | tr '\n' ' ' )"
  else
    emit "livecfg" "nft" "-" "absent" "nft not present"
  fi

  # firewalld
  if command -v firewall-cmd >/dev/null 2>&1; then
    emit "livecfg" "firewall-cmd --state" "-" "info" "$(firewall-cmd --state 2>/dev/null || true)"
    emit "livecfg" "firewall-cmd --list-all" "-" "info" "$(firewall-cmd --list-all 2>/dev/null | tr '\n' ' ')"
  fi

  # ufw
  if command -v ufw >/dev/null 2>&1; then
    emit "livecfg" "ufw status verbose" "-" "info" "$(ufw status verbose 2>/dev/null | tr '\n' ' ')"
  fi

  # ipset
  if command -v ipset >/dev/null 2>&1; then
    emit "livecfg" "ipset list" "-" "info" "$(ipset list 2>/dev/null | sed -n '1,400p' | tr '\n' ' ')"
  fi

  # shorewall, ebtables, arptables
  for cmd in shorewall ebtables arptables; do
    if command -v "$cmd" >/dev/null 2>&1; then
      emit "livecfg" "$cmd -L" "-" "info" "$($cmd -L 2>/dev/null | sed -n '1,200p' | tr '\n' ' ')"
    fi
  done

  # lsmod check for conntrack
  emit "livecfg" "lsmod conntrack" "-" "info" "$(lsmod | egrep -i 'conntrack|nf_' 2>/dev/null || true | tr '\n' ' ')"

  # systemctl status checks (firewalld, ufw, shorewall)
  for svc in firewalld ufw shorewall; do
    if systemctl list-units --type=service --all | grep -q "$svc"; then
      emit "livecfg" "systemctl status $svc" "-" "info" "$(systemctl status "$svc" --no-pager 2>/dev/null | sed -n '1,120p' | tr '\n' ' ')"
    fi
  done
}

# Main
SEPARATOR="--------------------------------------------------------------------"

# prepare output (header)
if [[ -n "$OUTFILE" ]]; then
  # create or truncate
  : > "$OUTFILE"
  print_header >> "$OUTFILE"
  # redirect emit to append to file by overriding emit function
  exec 3>>"$OUTFILE"
  emit_to_out() {
    local src="$1"; shift
    local file="$1"; shift
    local ln="$1"; shift
    local label="$1"; shift
    local match="$*"
    match="${match//$'\n'/ }"
    match="${match//$'\t'/ }"
    printf "%s\t%s\t%s\t%s\t%s\n" "$src" "$file" "$ln" "$label" "$match" >&3
  }
  # shell: use emit_to_out instead of emit for subsequent calls
  _EMIT_IMPL="file"
else
  print_header
  _EMIT_IMPL="stdout"
fi

# Wrapper to handle chosen emit impl
_emit_wrapper() {
  if [[ "${_EMIT_IMPL:-stdout}" == "file" ]]; then
    emit_to_out "$@"
  else
    emit "$@"
  fi
}

# Replace emit calls in functions by using alias via shell function name
# (simple approach: rename original emit to emit_stdout and call wrapper)
emit_stdout() { emit "$@"; }    # original behavior (prints to stdout)
emit_out() { emit_to_out "$@"; } # writes to OUTFILE (fd 3)

# Now run hunts, using chosen emitter
if [[ "${_EMIT_IMPL:-stdout}" == "file" ]]; then
  # swap functions
  emit() { emit_to_out "$@"; }
fi

# Execute hunts
echo "$SEPARATOR"
echo "FIREWALL HUNT REPORT - $(timestamp)"
echo "$SEPARATOR"

search_logs
search_histories
if [[ "$DO_JOURNAL" -eq 1 ]]; then
  search_journal
fi
list_firewall_state

# Close file descriptor if used
if [[ -n "$OUTFILE" ]]; then
  exec 3>&-
  echo "Findings saved to: $OUTFILE" >&2
fi

echo
echo "HUNT COMPLETE - $(timestamp)"
