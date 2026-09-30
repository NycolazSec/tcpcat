#!/usr/bin/env bash
# find-tcpcat.sh - look for tcpcat inside files you are entitled to inspect
# (a product you bought, a firmware or container image a vendor published,
# a package you downloaded). It is a software-composition check on the
# *distributed artifact*, not a network tool.
#
# Usage: scripts/find-tcpcat.sh <file-or-directory> [...]
# Exit status: 0 = no indicator found, 1 = tcpcat indicators found, 2 = usage.
#
# A match is evidence to start a conversation (license compliance), not proof
# by itself: check it by hand (see docs/LICENSE-COMPLIANCE.md).
set -u

[ $# -ge 1 ] || { echo "usage: $0 <file-or-directory> [...]" >&2; exit 2; }

# Strong indicators: specific to this project. One hit is significant.
STRONG=(
  'github.com/NycolazSec/tcpcat'          # Go module path, kept in build info even when stripped
  'tcpcat.io/oem'                          # license notice printed by --version/--license
  'Print licensing terms (AGPL-3.0'        # --license flag help text
  'Check GitHub and update the tcpcat binary'  # --update flag help text
  'Start the local web interface'          # --web flag help text
)
# Weak indicators: only meaningful together with a strong one.
WEAK=(
  'tcpcat'
  'rapport-entreprise'
)

found=0
scan_file() {
  local f="$1" s w hits=() weak=()
  [ -f "$f" ] && [ -r "$f" ] || return
  for s in "${STRONG[@]}"; do
    grep -aqF -- "$s" "$f" 2>/dev/null && hits+=("$s")
  done
  [ ${#hits[@]} -gt 0 ] || return
  for w in "${WEAK[@]}"; do
    grep -aqF -- "$w" "$f" 2>/dev/null && weak+=("$w")
  done
  found=1
  echo "== $f"
  echo "   strong indicators (${#hits[@]}/${#STRONG[@]}):"
  printf '     - %s\n' "${hits[@]}"
  [ ${#weak[@]} -gt 0 ] && echo "   also present: ${weak[*]}"
  if command -v go >/dev/null 2>&1; then
    go version -m "$f" 2>/dev/null | grep -E 'path|mod|dep' | head -4 | sed 's/^/   buildinfo: /'
  fi
}

for target in "$@"; do
  if [ -d "$target" ]; then
    while IFS= read -r -d '' f; do scan_file "$f"; done < <(find "$target" -type f -size +100k -print0 2>/dev/null)
  else
    scan_file "$target"
  fi
done

[ "$found" -eq 1 ] && exit 1
echo "no tcpcat indicator found"
exit 0
