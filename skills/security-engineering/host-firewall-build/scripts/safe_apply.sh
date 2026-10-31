#!/usr/bin/env bash
# Apply an nftables ruleset with an automatic rollback unless the operator confirms in time.
#
#   sudo ./safe_apply.sh firewall.nft [timeout_seconds] [table]
#
# 1. Syntax-checks the file (nft -c).
# 2. Backs up the current state of the managed table only (default: inet cb_filter).
# 3. Applies the new ruleset.
# 4. Starts a detached rollback timer that survives an SSH disconnect.
# 5. Keeps the change only if you type "yes" within the timeout. Confirm from a NEW SSH
#    session if you can; that proves new connections still work.
set -euo pipefail
export LC_ALL=C  # [a-z] ranges are locale-dependent (e.g. tr_TR); keep validation predictable

RULES=${1:?usage: safe_apply.sh firewall.nft [timeout_seconds] [table]}
TIMEOUT=${2:-60}
TABLE=${3:-cb_filter}
STATE_DIR=${CB_FW_STATE_DIR:-/var/lib/claude-blue-firewall}

[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "timeout must be an integer" >&2; exit 2; }
[[ "$TABLE" =~ ^[a-z][a-z0-9_]{0,30}$ ]] || { echo "invalid table name" >&2; exit 2; }
command -v nft >/dev/null || { echo "nft not found" >&2; exit 2; }

nft -c -f "$RULES"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
BACKUP="$STATE_DIR/${TABLE}.backup.nft"
if nft list table inet "$TABLE" >"$BACKUP" 2>/dev/null; then
  echo "backed up existing table inet $TABLE -> $BACKUP"
else
  : >"$BACKUP"
  echo "table inet $TABLE did not exist; rollback will remove it"
fi

ROLLBACK="$STATE_DIR/${TABLE}.rollback.sh"
cat >"$ROLLBACK" <<ROLL
#!/bin/sh
nft delete table inet $TABLE 2>/dev/null || true
if [ -s "$BACKUP" ]; then nft -f "$BACKUP"; fi
logger -t claude-blue-firewall "rolled back table inet $TABLE" 2>/dev/null || true
ROLL
chmod 700 "$ROLLBACK"

nft -f "$RULES"
echo "applied $RULES"

setsid sh -c "sleep $TIMEOUT; sh '$ROLLBACK'" </dev/null >/dev/null 2>&1 &
TIMER=$!
echo "rollback scheduled in ${TIMEOUT}s (pid $TIMER). Open a new session and test access now."

if read -r -t "$TIMEOUT" -p "Type 'yes' to keep the new firewall: " ANSWER && [[ "$ANSWER" == "yes" ]]; then
  kill "$TIMER" 2>/dev/null || true
  echo "kept. Persist it: copy $RULES into your nftables include (e.g. /etc/nftables.d/) and enable nftables.service."
else
  echo
  kill "$TIMER" 2>/dev/null || true
  sh "$ROLLBACK"
  echo "not confirmed: rolled back"
  exit 1
fi
